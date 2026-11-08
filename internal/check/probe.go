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
	interrupted := false
	for _, l := range cfg.Listeners {
		for _, r := range l.Routes {
			if interrupted || ctx.Err() != nil {
				interrupted = true
				break
			}
			if !c.probe(ctx, fmt.Sprintf("listener %q route %q", l.Name, r.Path), r) {
				interrupted = true
			}
		}
	}
	if interrupted {
		// Interrupted: no false failures, one finding.
		c.add(Problem, "probe", "interrupted: some sources were not read")
	}
	return c.findings
}

// probe reads one route; it returns false when the read was interrupted.
func (c *checker) probe(ctx context.Context, where string, r config.Route) bool {
	for name, p := range r.ForwardParams {
		if p.Required {
			c.add(Warning, where, "not probed: it needs the query parameter %q (forward_params)", name)
			return true
		}
	}
	src, err := source.New(r)
	if err != nil {
		c.add(Problem, where, "probe: %v", err)
		return true
	}
	if closer, ok := src.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	res, err := src.Fetch(ctx, source.Request{})
	if err != nil && ctx.Err() != nil {
		return false // interrupted: reported once by Probe
	}
	if err != nil {
		c.add(Problem, where, "probe: %s: %v", source.ReasonOf(err), err)
		return true
	}
	parsed, err := content.ValidateFormat(res.Body, r.Limits.MaxSamples, res.Protobuf)
	if err != nil {
		c.add(Problem, where, "probe: %s: %v", source.ReasonOf(err), err)
		return true
	}
	if float64(parsed.Samples) > samplesWarning*float64(r.Limits.MaxSamples) {
		c.add(Warning, where, "probe: %d samples, close to max_samples (%d)", parsed.Samples, r.Limits.MaxSamples)
	}
	return true
}
