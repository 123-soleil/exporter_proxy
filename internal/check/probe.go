package check

import (
	"context"
	"fmt"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/content"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

// samplesWarning is the share of max_samples above which a probe warns:
// the source would soon be rejected as too_many_samples.
const samplesWarning = 0.8

// Probe reads every route's source once, like the proxy does (same code,
// timeout and limits), and validates its content. Routes that need query
// parameters (a required forward_params entry) are not read.
func Probe(ctx context.Context, cfg *config.Config) []Finding {
	c := &checker{}
	for _, l := range cfg.Listeners {
		for _, r := range l.Routes {
			if ctx.Err() != nil {
				break
			}
			c.probe(ctx, fmt.Sprintf("listener %q route %q", l.Name, r.Path), r)
		}
	}
	if ctx.Err() != nil {
		// Interrupted: no false failures, one finding.
		c.add(Problem, "probe", "interrupted: some sources were not read")
	}
	return c.findings
}

func (c *checker) probe(ctx context.Context, where string, r config.Route) {
	for name, p := range r.ForwardParams {
		if p.Required {
			c.add(Warning, where, "not probed: it needs the query parameter %q (forward_params)", name)
			return
		}
	}
	src, err := source.New(r)
	if err != nil {
		c.add(Problem, where, "probe: %v", err)
		return
	}
	if closer, ok := src.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	res, err := src.Fetch(ctx, source.Request{})
	if err != nil && ctx.Err() != nil {
		return // interrupted: reported once by Probe
	}
	if err != nil {
		c.add(Problem, where, "probe: %s: %v", source.ReasonOf(err), err)
		return
	}
	parsed, err := content.ValidateFormat(res.Body, r.Limits.MaxSamples, res.Protobuf)
	if err != nil {
		c.add(Problem, where, "probe: %s: %v", source.ReasonOf(err), err)
		return
	}
	if float64(parsed.Samples) > samplesWarning*float64(r.Limits.MaxSamples) {
		c.add(Warning, where, "probe: %d samples, close to max_samples (%d)", parsed.Samples, r.Limits.MaxSamples)
	}
}
