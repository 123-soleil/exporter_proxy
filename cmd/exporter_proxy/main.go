// Command exporter_proxy puts TLS, mTLS and basic authentication in front of
// Prometheus exporters, HTTP exporters on Unix sockets and static metric files.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
)

const (
	appName = "exporter_proxy"

	defaultConfigPath = "/etc/exporter_proxy/config.yml"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it parses args, writes to the given
// streams and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		// The flag package already printed the error and the usage.
		return exitUsage
	}

	if opts.showVersion {
		if _, err := fmt.Fprintln(stdout, versionLine()); err != nil {
			return exitError
		}
		return exitOK
	}

	opts.logConfig.Writer = stderr
	logger := promslog.New(opts.logConfig)

	logger.Info("starting "+appName, version.Slog()...)
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

	// The proxy itself is not implemented yet: fail loudly rather than
	// pretending to run.
	logger.Error("proxy not implemented yet")
	return exitError
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
