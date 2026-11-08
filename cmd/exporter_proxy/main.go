// Command exporter_proxy puts TLS, mTLS and basic authentication in front of
// Prometheus exporters, HTTP exporters on Unix sockets and static metric files.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/check"
	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/metrics"
	"github.com/123-soleil/exporter_proxy/internal/server"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
)

const (
	appName = "exporter_proxy"

	defaultConfigPath = "/etc/exporter_proxy/config.yml"

	// shutdownTimeout bounds the wait for in-flight requests on SIGTERM;
	// it stays well below systemd's default TimeoutStopSec (90 s).
	shutdownTimeout = 15 * time.Second
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// options holds the parsed command line.
type options struct {
	configPath  string
	showVersion bool
	check       bool
	probe       bool
	accessLog   bool
	logConfig   *promslog.Config
}

func init() {
	// Builds without -ldflags -X (go run, go test) report "dev" everywhere:
	// --version, the startup log line and, later, the build_info metric.
	if version.Version == "" {
		version.Version = "dev"
	}
}

func main() {
	// Log timestamps in UTC whatever the server time zone, so that lines from
	// different servers compare directly once centralized.
	time.Local = time.UTC
	// SIGTERM (systemctl stop) and SIGINT trigger a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	// Once the first signal is received, restore the default handling: a
	// second SIGTERM or Ctrl-C stops the process without waiting for the
	// graceful shutdown.
	go func() {
		<-ctx.Done()
		stop()
	}()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it parses args, writes to the given
// streams, serves until ctx is done and returns the process exit code.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		// The flag package already printed the error and the usage.
		return exitUsage
	}

	// SIGHUP (systemctl reload) reloads the configuration. Registered
	// first, so that a SIGHUP received while starting does not kill the
	// process: it is buffered and applied once serving.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	if opts.showVersion {
		if _, err := fmt.Fprintln(stdout, versionLine()); err != nil {
			return exitError
		}
		return exitOK
	}

	opts.logConfig.Writer = stderr
	logger := promslog.New(opts.logConfig)

	logger.Info("starting "+appName, version.Slog()...)
	if opts.check {
		return runCheck(ctx, opts.configPath, opts.probe, logger)
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		logger.Error("cannot load configuration", "path", opts.configPath, "err", err)
		return exitError
	}
	routes := 0
	for _, l := range cfg.Listeners {
		routes += len(l.Routes)
	}
	logger.Info("configuration loaded", "path", opts.configPath,
		"listeners", len(cfg.Listeners), "routes", routes, "hash", cfg.HashString())

	m := metrics.New()
	m.ConfigLoaded(cfg, time.Now())

	srv, err := server.Start(cfg, server.Options{
		Logger:         logger,
		Recorder:       m,
		AccessLog:      opts.accessLog,
		MetricsHandler: m.Handler(logger.With("listener", server.MetricsListener)),
	})
	if err != nil {
		logger.Error("cannot start listeners", "err", err)
		return exitError
	}
	// After the metrics were initialized: listeners whose TLS settings
	// fail from the start show it at once.
	srv.ReportTLSHealth()

	code := exitOK
loop:
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down", "timeout", shutdownTimeout)
			break loop
		case err := <-srv.Err():
			logger.Error("listener failed, shutting down", "err", err)
			code = exitError
			break loop
		case <-hup:
			if next := reload(opts.configPath, cfg, srv, m, logger); next != nil {
				cfg = next
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown incomplete, connections closed", "err", err)
		code = exitError
	}
	logger.Info("stopped")
	return code
}

// reload loads the configuration again and applies it, returning the new
// configuration. On any error it returns nil: the running configuration is
// kept and the reload metric is set to 0.
func reload(path string, running *config.Config, srv *server.Server, m *metrics.Metrics, logger *slog.Logger) *config.Config {
	logger.Info("reloading configuration", "path", path)
	cfg, err := config.Load(path)
	if err == nil {
		m.PrepareReload(cfg)
		err = srv.Reload(cfg)
	}
	if err != nil {
		m.ReloadFailed(running)
		logger.Error("configuration reload failed, keeping the running configuration", "path", path, "err", err)
		return nil
	}
	m.ConfigLoaded(cfg, time.Now())
	srv.ReportTLSHealth() // after the metrics reset
	logger.Info("configuration reloaded", "path", path, "hash", cfg.HashString(),
		"changed", cfg.Hash != running.Hash, "listeners", len(cfg.Listeners))
	return cfg
}

// runCheck implements --check: it reports every problem, one log line each,
// and returns exitOK only if there is none. Warnings do not fail the check.
func runCheck(ctx context.Context, path string, probe bool, logger *slog.Logger) int {
	cfg, err := config.Load(path)
	if err != nil {
		var verr *config.ValidationError
		if errors.As(err, &verr) {
			for _, p := range verr.Problems {
				logger.Error("check: configuration problem", "path", path, "problem", p)
			}
			logger.Error("check failed", "path", path, "problems", len(verr.Problems))
		} else {
			logger.Error("check failed: cannot load configuration", "path", path, "err", err)
		}
		return exitError
	}

	problems, warnings := 0, 0
	findings := check.Run(cfg, time.Now())
	if probe {
		// Sources are read one by one, each bounded by its route timeout.
		// SIGINT or SIGTERM stops the probes in progress.
		findings = append(findings, check.Probe(ctx, cfg)...)
	}
	for _, f := range findings {
		switch f.Severity {
		case check.Problem:
			problems++
			logger.Error("check: problem", "where", f.Where, "problem", f.Message)
		default:
			warnings++
			logger.Warn("check: warning", "where", f.Where, "warning", f.Message)
		}
	}
	if problems > 0 {
		logger.Error("check failed", "path", path, "problems", problems, "warnings", warnings)
		return exitError
	}
	logger.Info("check passed", "path", path, "hash", cfg.HashString(), "warnings", warnings)
	return exitOK
}

// parseFlags parses the command line. Flag names follow the conventions of
// Prometheus exporters (--log.level, --log.format).
func parseFlags(args []string, stderr io.Writer) (*options, error) {
	opts := &options{
		logConfig: &promslog.Config{
			Level:  promslog.NewLevel(),
			Format: promslog.NewFormat(),
			Style:  promslog.SlogStyle,
		},
	}

	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.configPath, "config", defaultConfigPath, "path to the configuration file")
	fs.BoolVar(&opts.showVersion, "version", false, "print version information and exit")
	fs.BoolVar(&opts.check, "check", false, "check the configuration and the files it references, then exit")
	fs.BoolVar(&opts.probe, "probe", false, "with --check: also read every source once and validate its content")
	fs.BoolVar(&opts.accessLog, "log.access", false, "log one line per served request")
	fs.Var(opts.logConfig.Level, "log.level", "minimum log level: debug, info, warn, error")
	fs.Var(opts.logConfig.Format, "log.format", "log format: logfmt, json")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected argument %q", fs.Arg(0))
		// Nowhere else to report a failed write on stderr.
		_, _ = fmt.Fprintln(stderr, err)
		fs.Usage()
		return nil, err
	}
	if opts.probe && !opts.check {
		err := errors.New("--probe only applies with --check")
		_, _ = fmt.Fprintln(stderr, err)
		fs.Usage()
		return nil, err
	}
	return opts, nil
}

// versionLine returns the version information on a single line.
func versionLine() string {
	return fmt.Sprintf("%s version=%s revision=%s branch=%s go=%s",
		appName, version.Version, version.GetRevision(), version.Branch, version.GoVersion)
}

// Compile-time check that promslog flag types satisfy flag.Value.
var (
	_ flag.Value = (*promslog.Level)(nil)
	_ flag.Value = (*promslog.Format)(nil)
)
