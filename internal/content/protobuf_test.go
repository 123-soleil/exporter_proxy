package content

import (
	"bytes"
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
		{"too many samples", valid, 1, source.ReasonTooManySamples, "2 samples exceed max_samples (1)"},
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
