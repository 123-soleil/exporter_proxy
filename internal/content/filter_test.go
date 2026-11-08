package content

import (
	"strings"
	"testing"
)

const filterInput = `# HELP node_cpu_seconds_total CPU time.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 10
# TYPE node_memory_bytes gauge
node_memory_bytes 2048
# TYPE http_latency_seconds histogram
http_latency_seconds_bucket{le="1"} 1
http_latency_seconds_bucket{le="+Inf"} 2
http_latency_seconds_sum 1.5
http_latency_seconds_count 2
`

func TestFilterText(t *testing.T) {
	out, err := Filter([]byte(filterInput), false, func(name string) bool { return name != "node_memory_bytes" })
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		`node_cpu_seconds_total{cpu="0",mode="idle"} 10`,
		`# HELP node_cpu_seconds_total CPU time.`,
		`http_latency_seconds_bucket{le="+Inf"} 2`, // a whole histogram family kept
		`http_latency_seconds_count 2`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "node_memory_bytes") {
		t.Errorf("filtered family served:\n%s", got)
	}
	if _, err := Validate(out, 100); err != nil {
		t.Errorf("filtered output invalid: %v", err)
	}
}

func TestFilterProtobuf(t *testing.T) {
	body := encodeProto(t, gauge("keep_me", 1, 2), gauge("drop_me", 3), gauge("keep_too", 4))
	out, err := Filter(body, true, func(name string) bool { return strings.HasPrefix(name, "keep") })
	if err != nil {
		t.Fatal(err)
	}
	res, err := ValidateFormat(out, 100, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Samples != 3 {
		t.Errorf("samples after filter = %d, want 3", res.Samples)
	}
	// Kept messages are copied byte for byte.
	want := encodeProto(t, gauge("keep_me", 1, 2), gauge("keep_too", 4))
	if string(out) != string(want) {
		t.Error("kept protobuf messages differ from the source")
	}
}
