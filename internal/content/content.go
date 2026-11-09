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
	res, _, err := parseText(body, maxSamples)
	return res, err
}

// ValidateAndFilter is ValidateFormat followed by Filter, parsing a text
// body once.
func ValidateAndFilter(body []byte, maxSamples int, protobuf bool, keep func(name string) bool) (Result, []byte, error) {
	if protobuf {
		res, err := validateProtobuf(body, maxSamples)
		if err != nil {
			return res, nil, err
		}
		out, err := filterProtobuf(body, keep)
		return res, out, err
	}
	res, families, err := parseText(body, maxSamples)
	if err != nil {
		return res, nil, err
	}
	out, err := filterChecked(body, families, keep)
	return res, out, err
}

// parseText checks the cost of a text body, parses and counts it.
func parseText(body []byte, maxSamples int) (Result, map[string]*dto.MetricFamily, error) {
	start := time.Now()
	// The parser is quadratic in the labels of a line and allocates far
	// more than the body for cheap samples: such bodies are refused
	// before parsing.
	scan := scanText(body, maxSamples)
	switch {
	case scan.tooManyLabels > 0:
		return Result{Duration: time.Since(start)}, nil, source.NewError(source.ReasonInvalid,
			"line %d: more than %d labels", scan.tooManyLabels, MaxLabelsPerLine)
	case scan.samples > maxSamples:
		return Result{Samples: scan.samples, Duration: time.Since(start)}, nil, source.NewError(source.ReasonTooManySamples,
			"more than %d samples (max_samples)", maxSamples)
	case scan.cost > labelBudget(len(body)):
		return Result{Duration: time.Since(start)}, nil, source.NewError(source.ReasonInvalid,
			"too many labels for the body size (%d label pairs squared per line, at most %d)", scan.cost, labelBudget(len(body)))
	}
	// UTF-8 validation accepts classic names and quoted UTF-8 names, like
	// Prometheus 3. A parser is not safe for concurrent use: one per call.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	res := Result{Duration: time.Since(start)}
	if err != nil {
		return res, nil, source.NewError(source.ReasonInvalid, "not in Prometheus text format: %s", safeMessage(err))
	}
	res.Samples = countSamples(families)
	if res.Samples > maxSamples {
		return res, nil, source.NewError(source.ReasonTooManySamples,
			"%d samples exceed max_samples (%d)", res.Samples, maxSamples)
	}
	return res, families, nil
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
	// Decoding allocates far more than the wire size of empty series,
	// labels, buckets or spans: such bodies are refused before decoding.
	scan := scanProtobuf(body, maxSamples)
	switch {
	case scan.bad > 0:
		families = scan.bad - 1
		return invalid()
	case scan.tooManyLabels > 0:
		return Result{Duration: time.Since(start)}, source.NewError(source.ReasonInvalid,
			"metric family %d: a series has more than %d labels", scan.tooManyLabels, MaxLabelsPerLine)
	case scan.samples > maxSamples:
		return Result{Samples: scan.samples, Duration: time.Since(start)}, source.NewError(source.ReasonTooManySamples,
			"more than %d samples (max_samples)", maxSamples)
	case scan.entries > entryBudget(len(body)):
		return Result{Duration: time.Since(start)}, source.NewError(source.ReasonInvalid,
			"too many labels, buckets or spans for the body size (%d, at most %d)", scan.entries, entryBudget(len(body)))
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

// MaxLabelsPerLine bounds the labels of one sample line in the text
// format, checked before parsing: the parser's cost grows with the square
// of a line's labels. Real exporters stay below (kube_node_labels of nodes
// labelled by Node Feature Discovery can approach 150).
const MaxLabelsPerLine = 256

// labelBudget bounds the sum over lines of (labels per line)², the parse
// cost, for a body of size bytes: real lines spend tens of bytes per
// label, so they stay far below; lines of tiny labels made to burn CPU do
// not.
func labelBudget(size int) int { return 8*size + 1<<16 }

// textScan is what scanText found.
type textScan struct {
	samples       int // sample lines, counted up to the limit
	tooManyLabels int // 1-based line with more than MaxLabelsPerLine labels, 0 if none
	cost          int // sum of (labels per line)²
}

// scanText counts the lines of a text body that are neither blank nor
// comments (one per sample: buckets, quantiles, _sum and _count included,
// stopping past limit) and the parse cost of their labels.
func scanText(body []byte, limit int) textScan {
	var sc textScan
	for lineNo := 1; len(body) > 0 && sc.samples <= limit; lineNo++ {
		line := body
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			body = nil
		}
		line = bytes.TrimLeft(line, " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		sc.samples++
		labels := labelCount(line)
		if labels > MaxLabelsPerLine {
			sc.tooManyLabels = lineNo
			return sc
		}
		sc.cost += labels * labels
	}
	return sc
}

// labelCount counts the '=' of a sample line outside quoted strings: one
// per label pair (an upper bound for a malformed line, which the parser
// refuses anyway).
func labelCount(line []byte) int {
	n, quoted, escaped := 0, false, false
	for _, c := range line {
		switch {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case !quoted && c == '=':
			n++
		}
	}
	return n
}

// metricField is the field number of MetricFamily.metric.
const metricField = 4

// entryBudget bounds the sub-messages (labels, buckets, quantiles, spans,
// exemplars) of a protobuf body of size bytes. Each one decodes into a Go
// struct of about a hundred bytes; real ones take more than 6 bytes on the
// wire (a label carries a name, a bucket a bound and a count), empty ones
// made to inflate decoding take 2.
func entryBudget(size int) int { return size/6 + 1<<16 }

// protobufScan is what scanProtobuf found in a delimited protobuf body.
type protobufScan struct {
	samples       int // lower bound of the samples, counted up to the limit
	entries       int // labels, buckets, quantiles, spans and exemplars
	bad           int // 1-based position of a malformed family, 0 if none
	tooManyLabels int // 1-based family with a series of more than MaxLabelsPerLine labels
}

// Field numbers of client_model's messages.
const (
	labelField      = 1  // Metric.label, Exemplar.label
	counterField    = 3  // Metric.counter
	summaryField    = 4  // Metric.summary
	histogramField  = 7  // Metric.histogram
	entriesField    = 3  // Summary.quantile, Histogram.bucket
	counterExemplar = 2  // Counter.exemplar
	bucketExemplar  = 3  // Bucket.exemplar
	negSpanField    = 9  // Histogram.negative_span
	posSpanField    = 12 // Histogram.positive_span
	exemplarsField  = 16 // Histogram.exemplars
)

// scanProtobuf walks the wire format of a delimited protobuf body without
// decoding it: a lower bound of its samples (the same rule as familySamples,
// stopping past limit), its sub-messages and its labels per series.
func scanProtobuf(body []byte, limit int) protobufScan {
	var sc protobufScan
	family := 0
	for rest := body; len(rest) > 0 && sc.samples <= limit; {
		family++
		size, prefix := protowire.ConsumeVarint(rest)
		if prefix < 0 || size > uint64(len(rest)-prefix) {
			sc.bad = family
			return sc
		}
		msg := rest[prefix : prefix+int(size)]
		rest = rest[prefix+int(size):]
		ok := eachField(msg, func(num protowire.Number, v []byte) bool {
			if num != metricField {
				return true
			}
			m, ok := scanMetric(v)
			if !ok {
				return false
			}
			if m.labels > MaxLabelsPerLine && sc.tooManyLabels == 0 {
				sc.tooManyLabels = family
			}
			sc.samples += m.samples
			sc.entries += m.entries
			return true
		})
		if !ok {
			sc.bad = family
			return sc
		}
	}
	return sc
}

// metricScan is what scanMetric found in one encoded Metric.
type metricScan struct{ samples, entries, labels int }

// scanMetric counts the samples of one encoded Metric like familySamples
// (a lower bound: a histogram's classic buckets or a summary's quantiles,
// at least one) and its sub-messages: the series itself, its labels,
// buckets, quantiles, spans, and exemplars with their labels.
func scanMetric(metric []byte) (metricScan, bool) {
	m := metricScan{entries: 1}
	hasHistogram, buckets, quantiles := false, 0, 0
	ok := eachField(metric, func(num protowire.Number, v []byte) bool {
		switch num {
		case labelField:
			m.labels++
			m.entries++
		case counterField:
			return eachField(v, func(f protowire.Number, e []byte) bool {
				if f == counterExemplar {
					return m.exemplar(e)
				}
				return true
			})
		case summaryField:
			return eachField(v, func(f protowire.Number, _ []byte) bool {
				if f == entriesField {
					quantiles++
					m.entries++
				}
				return true
			})
		case histogramField:
			hasHistogram = true
			return eachField(v, func(f protowire.Number, sub []byte) bool {
				switch f {
				case entriesField:
					buckets++
					m.entries++
					return eachField(sub, func(bf protowire.Number, e []byte) bool {
						if bf == bucketExemplar {
							return m.exemplar(e)
						}
						return true
					})
				case negSpanField, posSpanField:
					m.entries++
				case exemplarsField:
					return m.exemplar(sub)
				}
				return true
			})
		}
		return true
	})
	if hasHistogram {
		m.samples = max(1, buckets)
	} else {
		m.samples = max(1, quantiles)
	}
	return m, ok
}

// exemplar counts an encoded Exemplar and its labels as entries.
func (m *metricScan) exemplar(e []byte) bool {
	m.entries++
	return eachField(e, func(f protowire.Number, _ []byte) bool {
		if f == labelField {
			m.entries++
		}
		return true
	})
}

// eachField calls fn with the number and content of every length-delimited
// field of msg, until fn returns false. It reports false for a malformed
// message or when fn stopped.
func eachField(msg []byte, fn func(num protowire.Number, v []byte) bool) bool {
	for len(msg) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(msg)
		if tagLen < 0 {
			return false
		}
		valLen := protowire.ConsumeFieldValue(num, typ, msg[tagLen:])
		if valLen < 0 {
			return false
		}
		if typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(msg[tagLen:])
			if !fn(num, v) {
				return false
			}
		}
		msg = msg[tagLen+valLen:]
	}
	return true
}

// validFamily checks the names and label values of a decoded family, like
// the text parser in UTF-8 mode.
func validFamily(mf *dto.MetricFamily) bool {
	if !model.UTF8Validation.IsValidMetricName(mf.GetName()) {
		return false
	}
	for _, m := range mf.GetMetric() {
		seen := make(map[string]bool, len(m.GetLabel()))
		for _, l := range m.GetLabel() {
			name := l.GetName()
			// Like the text parser: no __name__ label, no duplicate.
			if name == model.MetricNameLabel || seen[name] ||
				!model.UTF8Validation.IsValidLabelName(name) || !model.LabelValue(l.GetValue()).IsValid() {
				return false
			}
			seen[name] = true
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
// Escapes are part of the quoted text: a value holding \" is hidden
// whole, not up to its first escaped quote.
var quoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"?`)

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
