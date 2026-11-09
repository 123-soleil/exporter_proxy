package content

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

// encodeProto returns families in the delimited protobuf format.
func encodeProto(t *testing.T, families ...*dto.MetricFamily) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeProtoDelim))
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func gauge(name string, values ...float64) *dto.MetricFamily {
	f := &dto.MetricFamily{Name: proto.String(name), Type: dto.MetricType_GAUGE.Enum()}
	for i, v := range values {
		f.Metric = append(f.Metric, &dto.Metric{
			Label: []*dto.LabelPair{{Name: proto.String("i"), Value: proto.String(strings.Repeat("x", i+1))}},
			Gauge: &dto.Gauge{Value: proto.Float64(v)},
		})
	}
	return f
}

// nativeHistogram returns a family with one native histogram, and classic
// buckets when classic is set.
func nativeHistogram(classic bool) *dto.MetricFamily {
	h := &dto.Histogram{
		SampleCount:   proto.Uint64(3),
		SampleSum:     proto.Float64(1.5),
		Schema:        proto.Int32(3),
		ZeroThreshold: proto.Float64(1e-128),
		ZeroCount:     proto.Uint64(0),
		PositiveSpan:  []*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(2)}},
		PositiveDelta: []int64{1, 1},
	}
	if classic {
		h.Bucket = []*dto.Bucket{
			{UpperBound: proto.Float64(1), CumulativeCount: proto.Uint64(1)},
			{UpperBound: proto.Float64(2), CumulativeCount: proto.Uint64(3)},
		}
	}
	return &dto.MetricFamily{
		Name: proto.String("latency_seconds"), Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{Histogram: h}},
	}
}

func TestValidateProtobuf(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		wantSamples int
	}{
		{"gauges", encodeProto(t, gauge("a", 1, 2), gauge("b", 3)), 3},
		{"native histogram: one sample", encodeProto(t, nativeHistogram(false)), 1},
		{"native and classic buckets", encodeProto(t, nativeHistogram(true)), 2 + 2 + 1},
		{"utf-8 name", encodeProto(t, gauge("my.metric", 1)), 1},
		{"empty body", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ValidateFormat(tt.body, 100, true)
			if err != nil {
				t.Fatal(err)
			}
			if res.Samples != tt.wantSamples {
				t.Errorf("samples = %d, want %d", res.Samples, tt.wantSamples)
			}
		})
	}
}

func TestValidateProtobufRejects(t *testing.T) {
	valid := encodeProto(t, gauge("a", 1), gauge("b", 2))
	tests := []struct {
		name   string
		body   []byte
		max    int
		reason source.Reason
		msg    string
	}{
		{"text body", []byte("# TYPE up gauge\nup 1\n"), 100, source.ReasonInvalid, "metric family 1"},
		{"truncated", valid[:len(valid)-3], 100, source.ReasonInvalid, "metric family 2"},
		{"invalid label value", encodeProto(t, &dto.MetricFamily{
			Name: proto.String("a"), Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{{
				Label: []*dto.LabelPair{{Name: proto.String("l"), Value: proto.String("\xff secret")}},
				Gauge: &dto.Gauge{Value: proto.Float64(1)},
			}},
		}), 100, source.ReasonInvalid, "metric family 1"},
		{"too many samples", valid, 1, source.ReasonTooManySamples, "more than 1 samples (max_samples)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateFormat(tt.body, tt.max, true)
			if source.ReasonOf(err) != tt.reason || !strings.Contains(err.Error(), tt.msg) {
				t.Fatalf("err = %v, want %s containing %q", err, tt.reason, tt.msg)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("error quotes the content: %v", err)
			}
		})
	}
}

// A length prefix announcing more than the body holds is invalid at once,
// without allocating what it announces (it used to panic with 1<<62, and
// to reserve 16 GiB with 1<<34).
func TestValidateProtobufHugeLengthPrefix(t *testing.T) {
	for _, size := range []uint64{1 << 62, 1 << 34, 4097, 10} {
		body := protowire.AppendVarint(nil, size)
		body = append(body, "abc"...)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := ValidateFormat(body, 100, true)
		runtime.ReadMemStats(&after)
		if source.ReasonOf(err) != source.ReasonInvalid {
			t.Errorf("length %d: err = %v, want invalid", size, err)
		}
		if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<20 {
			t.Errorf("length %d: allocated %d bytes", size, grown)
		}
	}
	// A truncated varint is invalid too.
	if _, err := ValidateFormat([]byte{0xff, 0xff}, 100, true); source.ReasonOf(err) != source.ReasonInvalid {
		t.Errorf("truncated varint: err = %v", err)
	}
	// An empty message has no metric name.
	if _, err := ValidateFormat([]byte{0}, 100, true); source.ReasonOf(err) != source.ReasonInvalid {
		t.Errorf("empty family: err = %v", err)
	}
}

// Bodies made of the cheapest samples are refused on their count before
// parsing: they made the parsers allocate 50 to 70 times their size.
func TestCheapSampleFloodsRefusedBeforeParsing(t *testing.T) {
	text := bytes.Repeat([]byte("a 1\n"), 512<<10) // 2 MiB, 512k samples
	// One protobuf family named "a" holding a million empty series.
	family := protowire.AppendTag(nil, 1, protowire.BytesType)
	family = protowire.AppendString(family, "a")
	for range 1 << 20 {
		family = protowire.AppendTag(family, metricField, protowire.BytesType)
		family = protowire.AppendVarint(family, 0)
	}
	pb := protowire.AppendVarint(nil, uint64(len(family)))
	pb = append(pb, family...)
	for name, tc := range map[string]struct {
		body     []byte
		protobuf bool
	}{"text": {text, false}, "protobuf": {pb, true}} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := ValidateFormat(tc.body, 24000, tc.protobuf)
		runtime.ReadMemStats(&after)
		if source.ReasonOf(err) != source.ReasonTooManySamples {
			t.Errorf("%s: err = %v, want too_many_samples", name, err)
		}
		if grown := after.TotalAlloc - before.TotalAlloc; grown > 4<<20 {
			t.Errorf("%s: allocated %d MiB for a %d MiB body", name, grown>>20, len(tc.body)>>20)
		}
	}
}

// Like the text parser, protobuf content may not carry __name__ or
// duplicate label names.
func TestValidateProtobufLabelRules(t *testing.T) {
	for name, labels := range map[string][]*dto.LabelPair{
		"__name__":  {{Name: proto.String("__name__"), Value: proto.String("other")}},
		"duplicate": {{Name: proto.String("a"), Value: proto.String("1")}, {Name: proto.String("a"), Value: proto.String("2")}},
	} {
		body := encodeProto(t, &dto.MetricFamily{Name: proto.String("m"), Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{{Label: labels, Gauge: &dto.Gauge{Value: proto.Float64(1)}}}})
		if _, err := ValidateFormat(body, 100, true); source.ReasonOf(err) != source.ReasonInvalid {
			t.Errorf("%s: err = %v, want invalid", name, err)
		}
	}
}

// One series of many empty buckets is refused before decoding: decoding
// would allocate tens of times the body size.
func TestProtobufBucketFloodRefusedBeforeDecoding(t *testing.T) {
	const buckets = 30000
	h := &dto.Histogram{SampleCount: proto.Uint64(0), SampleSum: proto.Float64(0), Bucket: make([]*dto.Bucket, buckets)}
	for i := range h.Bucket {
		h.Bucket[i] = &dto.Bucket{}
	}
	mf := &dto.MetricFamily{Name: proto.String("flood"), Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{Histogram: h}}}
	msg, err := proto.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	body := protowire.AppendVarint(nil, uint64(len(msg)))
	body = append(body, msg...)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res, err := ValidateFormat(body, 24000, true)
	runtime.ReadMemStats(&after)

	if source.ReasonOf(err) != source.ReasonTooManySamples {
		t.Fatalf("reason = %q (%v), want too_many_samples", source.ReasonOf(err), err)
	}
	if res.Samples <= 24000 {
		t.Errorf("Samples = %d, want above the limit", res.Samples)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(4*len(body)) {
		t.Errorf("allocated %d bytes for a %d byte body: decoded before refusing", alloc, len(body))
	}

	// Below the limit, the same shape is still accepted.
	h.Bucket = h.Bucket[:100]
	msg, _ = proto.Marshal(mf)
	ok := append(protowire.AppendVarint(nil, uint64(len(msg))), msg...)
	if _, err := ValidateFormat(ok, 24000, true); err != nil {
		t.Errorf("100 buckets refused: %v", err)
	}
}

// familyName reads the name like proto.Unmarshal would, last occurrence
// included, so filtering keeps the same families as before.
func TestFamilyNameMatchesUnmarshal(t *testing.T) {
	one, _ := proto.Marshal(&dto.MetricFamily{Name: proto.String("first"), Type: dto.MetricType_GAUGE.Enum(),
		Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(1)}}}})
	two, _ := proto.Marshal(&dto.MetricFamily{Name: proto.String("second")})
	repeated := append(append([]byte{}, one...), two...) // name field twice: the last wins
	for _, msg := range [][]byte{one, two, repeated, nil} {
		var mf dto.MetricFamily
		if err := proto.Unmarshal(msg, &mf); err != nil {
			t.Fatal(err)
		}
		got, ok := familyName(msg)
		if !ok || got != mf.GetName() {
			t.Errorf("familyName = %q, %v; proto.Unmarshal reads %q", got, ok, mf.GetName())
		}
	}
	if _, ok := familyName([]byte{0x0a, 0x05, 'a'}); ok {
		t.Error("truncated message accepted")
	}
}

func BenchmarkFilterProtobuf(b *testing.B) {
	var body []byte
	for i := 0; i < 500; i++ {
		msg, _ := proto.Marshal(&dto.MetricFamily{Name: proto.String(fmt.Sprintf("family_%d", i)), Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{{Label: []*dto.LabelPair{{Name: proto.String("l"), Value: proto.String("v")}},
				Gauge: &dto.Gauge{Value: proto.Float64(1)}}}})
		body = append(protowire.AppendVarint(body, uint64(len(msg))), msg...)
	}
	keep := func(name string) bool { return len(name)%2 == 0 }
	b.ReportAllocs()
	for b.Loop() {
		if _, err := filterProtobuf(body, keep); err != nil {
			b.Fatal(err)
		}
	}
}

// delimited encodes families in the delimited protobuf format.
func delimited(t *testing.T, families ...*dto.MetricFamily) []byte {
	t.Helper()
	var body []byte
	for _, mf := range families {
		msg, err := proto.Marshal(mf)
		if err != nil {
			t.Fatal(err)
		}
		body = append(protowire.AppendVarint(body, uint64(len(msg))), msg...)
	}
	return body
}

// Sub-messages that decode to far more than their wire size are refused
// before decoding: empty spans, empty labels, too many labels per series.
func TestProtobufInflationRefusedBeforeDecoding(t *testing.T) {
	spans := make([]*dto.BucketSpan, 200000)
	for i := range spans {
		spans[i] = &dto.BucketSpan{}
	}
	native := &dto.MetricFamily{Name: proto.String("spans"), Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{Histogram: &dto.Histogram{Schema: proto.Int32(0), PositiveSpan: spans}}}}

	manyLabels := make([]*dto.LabelPair, MaxLabelsPerLine+1)
	for i := range manyLabels {
		manyLabels[i] = &dto.LabelPair{Name: proto.String(fmt.Sprintf("l%d", i)), Value: proto.String("v")}
	}
	wide := &dto.MetricFamily{Name: proto.String("wide"), Type: dto.MetricType_GAUGE.Enum(),
		Metric: []*dto.Metric{{Label: manyLabels, Gauge: &dto.Gauge{Value: proto.Float64(1)}}}}

	// Many series of empty labels: under max_samples and under the labels
	// per series, but far over the sub-messages the body size allows.
	var series []*dto.Metric
	for i := 0; i < 2000; i++ {
		labels := make([]*dto.LabelPair, 200)
		for j := range labels {
			labels[j] = &dto.LabelPair{}
		}
		series = append(series, &dto.Metric{Label: labels, Gauge: &dto.Gauge{}})
	}
	emptyLabels := &dto.MetricFamily{Name: proto.String("empty"), Type: dto.MetricType_GAUGE.Enum(), Metric: series}

	for name, tt := range map[string]struct {
		mf   *dto.MetricFamily
		want string
	}{
		"200k empty spans":                 {native, "too many labels, buckets or spans for the body size"},
		"more than 256 labels in a series": {wide, "has more than 256 labels"},
		"400k empty labels":                {emptyLabels, "too many labels, buckets or spans for the body size"},
	} {
		t.Run(name, func(t *testing.T) {
			body := delimited(t, tt.mf)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := ValidateFormat(body, 24000, true)
			runtime.ReadMemStats(&after)
			if source.ReasonOf(err) != source.ReasonInvalid || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want invalid %q", err, tt.want)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(4*len(body)) {
				t.Errorf("allocated %d bytes for a %d byte body: decoded before refusing", alloc, len(body))
			}
		})
	}
}

// The pre-scan never counts more than the decoded count: a series with a
// summary and a native histogram counts as its histogram, like
// familySamples, and real native histograms pass.
func TestProtobufPrescanIsALowerBound(t *testing.T) {
	quantiles := make([]*dto.Quantile, 50)
	for i := range quantiles {
		quantiles[i] = &dto.Quantile{Quantile: proto.Float64(float64(i) / 50), Value: proto.Float64(1)}
	}
	both := &dto.MetricFamily{Name: proto.String("both"), Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Summary:   &dto.Summary{SampleCount: proto.Uint64(1), SampleSum: proto.Float64(1), Quantile: quantiles},
			Histogram: &dto.Histogram{Schema: proto.Int32(3), SampleCount: proto.Uint64(1), SampleSum: proto.Float64(1)},
		}}}
	real := &dto.MetricFamily{Name: proto.String("latency_seconds"), Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Label: []*dto.LabelPair{{Name: proto.String("job"), Value: proto.String("api")}},
			Histogram: &dto.Histogram{Schema: proto.Int32(3), ZeroThreshold: proto.Float64(1e-128),
				SampleCount: proto.Uint64(10), SampleSum: proto.Float64(2.5),
				PositiveSpan:  []*dto.BucketSpan{{Offset: proto.Int32(-4), Length: proto.Uint32(3)}, {Offset: proto.Int32(2), Length: proto.Uint32(2)}},
				PositiveDelta: []int64{1, 2, -1, 3, 0}},
		}}}
	for name, mf := range map[string]*dto.MetricFamily{"summary and native histogram": both, "native histogram": real} {
		t.Run(name, func(t *testing.T) {
			body := delimited(t, mf)
			sc := scanProtobuf(body, 1000)
			res, err := ValidateFormat(body, 10, true)
			if err != nil {
				t.Fatalf("refused: %v (pre-scan %+v)", err, sc)
			}
			if sc.samples > res.Samples {
				t.Errorf("pre-scan counted %d samples, decoding %d: not a lower bound", sc.samples, res.Samples)
			}
		})
	}
}
