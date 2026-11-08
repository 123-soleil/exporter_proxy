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
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

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
	return ValidateFormat(body, maxSamples, false)
}

// ValidateFormat is Validate for body in the delimited protobuf format
// when protobuf is set, in the text format otherwise.
func ValidateFormat(body []byte, maxSamples int, protobuf bool) (Result, error) {
	if protobuf {
		return validateProtobuf(body, maxSamples)
	}
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

// validateProtobuf decodes every metric family of a delimited protobuf
// body (each message prefixed with its length as a varint), and checks
// metric names, label names and label values like the text parser.
//
// The body is cut by hand rather than with expfmt's decoder, which
// allocates whatever length a prefix announces: a few bytes from a
// malicious upstream would make it allocate gigabytes, or panic. Here a
// length larger than what is left of the body is invalid before anything
// is allocated.
func validateProtobuf(body []byte, maxSamples int) (Result, error) {
	start := time.Now()
	n, families := 0, 0
	invalid := func() (Result, error) {
		// Only the position: names or values could be sensitive.
		return Result{Samples: n, Duration: time.Since(start)},
			source.NewError(source.ReasonInvalid, "not in delimited protobuf format: metric family %d", families+1)
	}
	for rest := body; len(rest) > 0; {
		size, prefix := protowire.ConsumeVarint(rest)
		if prefix < 0 || size > uint64(len(rest)-prefix) {
			return invalid()
		}
		msg := rest[prefix : prefix+int(size)]
		rest = rest[prefix+int(size):]
		var mf dto.MetricFamily
		if err := proto.Unmarshal(msg, &mf); err != nil || !validFamily(&mf) {
			return invalid()
		}
		families++
		n += familySamples(&mf)
	}
	res := Result{Samples: n, Duration: time.Since(start)}
	if n > maxSamples {
		return res, source.NewError(source.ReasonTooManySamples, "%d samples exceed max_samples (%d)", n, maxSamples)
	}
	return res, nil
}

// validFamily checks the names and label values of a decoded family, like
// the text parser in UTF-8 mode.
func validFamily(mf *dto.MetricFamily) bool {
	if !model.UTF8Validation.IsValidMetricName(mf.GetName()) {
		return false
	}
	for _, m := range mf.GetMetric() {
		for _, l := range m.GetLabel() {
			if !model.UTF8Validation.IsValidLabelName(l.GetName()) || !model.LabelValue(l.GetValue()).IsValid() {
				return false
			}
		}
	}
	return true
}

func countSamples(families map[string]*dto.MetricFamily) int {
	n := 0
	for _, f := range families {
		n += familySamples(f)
	}
	return n
}

// familySamples counts samples like Prometheus' sample_limit: a native
// histogram counts as one sample, classic buckets and quantiles one each,
// plus _sum and _count.
func familySamples(f *dto.MetricFamily) int {
	n := 0
	for _, m := range f.GetMetric() {
		switch h := m.GetHistogram(); {
		case h != nil:
			if len(h.GetBucket()) > 0 || !isNative(h) {
				n += len(h.GetBucket()) + 2 // + _sum and _count
			}
			if isNative(h) {
				n++
			}
		case m.GetSummary() != nil:
			n += len(m.GetSummary().GetQuantile()) + 2 // + _sum and _count
		default:
			n++
		}
	}
	return n
}

// isNative reports whether a histogram carries a native histogram.
func isNative(h *dto.Histogram) bool {
	return h.Schema != nil || h.ZeroThreshold != nil || len(h.GetPositiveSpan()) > 0 ||
		len(h.GetNegativeSpan()) > 0 || h.ZeroCount != nil || h.ZeroCountFloat != nil
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
