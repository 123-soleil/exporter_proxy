// Package content validates that data read from a source is in the
// Prometheus text exposition format before it is served.
//
// Validation uses the official parser (prometheus/common/expfmt), never
// regular expressions, and is mandatory: anything that does not parse is
// rejected.
package content

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

// Result describes validated content.
type Result struct {
	// Samples counts lines carrying a value, like Prometheus' sample_limit:
	// one per counter, gauge or untyped series, and for histograms and
	// summaries one per bucket or quantile plus _sum and _count.
	Samples int
	// Duration is the time spent parsing.
	Duration time.Duration
}

// Validate parses body and checks the number of samples against maxSamples.
// Failures are *source.Error with ReasonInvalid or ReasonTooManySamples. The
// Result is filled even on error, as far as parsing went.
func Validate(body []byte, maxSamples int) (Result, error) {
	start := time.Now()
	// UTF-8 validation accepts classic names and quoted UTF-8 names, like
	// Prometheus 3. A parser is not safe for concurrent use: one per call.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	res := Result{Duration: time.Since(start)}
	if err != nil {
		return res, source.NewError(source.ReasonInvalid, "not in Prometheus text format: %s", safeMessage(err))
	}

	res.Samples = countSamples(families)
	if res.Samples > maxSamples {
		return res, source.NewError(source.ReasonTooManySamples,
			"%d samples exceed max_samples (%d)", res.Samples, maxSamples)
	}
	return res, nil
}

func countSamples(families map[string]*dto.MetricFamily) int {
	n := 0
	for _, f := range families {
		for _, m := range f.GetMetric() {
			switch {
			case m.GetHistogram() != nil:
				n += len(m.GetHistogram().GetBucket()) + 2 // + _sum and _count
			case m.GetSummary() != nil:
				n += len(m.GetSummary().GetQuantile()) + 2 // + _sum and _count
			default:
				n++
			}
		}
	}
	return n
}

// quoted matches quoted values in parser messages.
var quoted = regexp.MustCompile(`"[^"]*"`)

// safeMessage keeps the line number and the kind of error but drops the
// offending content: a misconfigured source could point to sensitive data,
// which must not end up in logs.
func safeMessage(err error) string {
	var pe expfmt.ParseError
	var ppe *expfmt.ParseError
	switch {
	case errors.As(err, &pe):
	case errors.As(err, &ppe) && ppe != nil:
		pe = *ppe
	default:
		return "parse error"
	}

	msg := pe.Msg
	if i := strings.Index(msg, " got "); i >= 0 {
		msg = msg[:i]
	}
	msg = quoted.ReplaceAllString(msg, `"..."`)
	msg = strings.TrimRight(msg, ", ")
	if len(msg) > 100 {
		msg = msg[:100] + "..."
	}
	if pe.Line > 0 {
		return "line " + strconv.Itoa(pe.Line) + ": " + msg
	}
	return msg
}
