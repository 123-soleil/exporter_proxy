package content

import (
	"fmt"
	"strings"
	"testing"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

const sample = `# HELP up Whether the target is up.
# TYPE up gauge
up 1
# TYPE requests_total counter
requests_total{code="200"} 10
requests_total{code="500"} 1
# TYPE latency_seconds histogram
latency_seconds_bucket{le="0.1"} 1
latency_seconds_bucket{le="1"} 2
latency_seconds_bucket{le="+Inf"} 3
latency_seconds_sum 2.5
latency_seconds_count 3
# TYPE rpc_seconds summary
rpc_seconds{quantile="0.5"} 0.2
rpc_seconds{quantile="0.9"} 0.8
rpc_seconds_sum 10
rpc_seconds_count 30
untyped_metric 42
{"utf8.metric.name", zone="a"} 1
`

func TestValidateAccepts(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantSamples int
	}{
		// up(1) + requests_total(2) + histogram(3 buckets + 2) + summary(2 quantiles + 2) + untyped(1) + utf8(1)
		{"mixed types", sample, 1 + 2 + 5 + 4 + 1 + 1},
		{"empty", "", 0},
		{"comments only", "# just a comment\n", 0},
		{"timestamp", "m 1 1700000000000\n", 1},
		{"special values", "a NaN\nb +Inf\nc -Inf\n", 3},
		{"escaped label value", `m{path="C:\\dir\"q\"\nx"} 1` + "\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Validate([]byte(tt.body), 1000)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if res.Samples != tt.wantSamples {
				t.Errorf("Samples = %d, want %d", res.Samples, tt.wantSamples)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	secret := "root:$y$j9T$SECRETHASH:19000:0:99999:7:::\n"

	tests := []struct {
		name       string
		body       string
		maxSamples int
		want       source.Reason
		wantMsg    string
	}{
		{"html page", "<html><body>Admin</body></html>\n", 1000, source.ReasonInvalid, "line 1"},
		{"binary", "\x00\x01\xff\xfe binary", 1000, source.ReasonInvalid, "line 1"},
		{"json", `{"status":"ok"}` + "\n", 1000, source.ReasonInvalid, "line 1"},
		{"shadow file", secret, 1000, source.ReasonInvalid, "line 1"},
		{"value not a number", "m one\n", 1000, source.ReasonInvalid, "line 1"},
		{"no trailing newline (required by the format)", "m 1", 1000, source.ReasonInvalid, "line 1"},
		{"invalid utf-8 label", "m{l=\"\xff\"} 1\n", 1000, source.ReasonInvalid, "line 1"},
		{"bad line after valid ones", "a 1\nb 2\nnot valid line\n", 1000, source.ReasonInvalid, "line 3"},
		{"duplicate TYPE", "# TYPE m gauge\nm 1\n# TYPE m gauge\n", 1000, source.ReasonInvalid, "line 3"},
		{"too many samples", sample, 5, source.ReasonTooManySamples, "more than 5 samples (max_samples)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Validate([]byte(tt.body), tt.maxSamples)
			if got := source.ReasonOf(err); got != tt.want {
				t.Fatalf("reason = %q, want %q (err: %v)", got, tt.want, err)
			}
			msg := err.Error()
			if !strings.Contains(msg, tt.wantMsg) {
				t.Errorf("error = %q, want substring %q", msg, tt.wantMsg)
			}
			if strings.ContainsAny(msg, "\r\n") {
				t.Errorf("error spans several lines: %q", msg)
			}
		})
	}
}

// The parser quotes offending content in its messages; none of it must reach
// the error, which is logged.
func TestValidateErrorDoesNotLeakContent(t *testing.T) {
	bodies := []string{
		"root:$y$j9T$SECRETHASH:19000:0:99999:7:::\n",
		"m SECRETHASH\n",
		"m{l=\"SECRETHASH\" 1\n",
		"SECRETHASH{a=\"b\"} x\n",
		"# TYPE m SECRETHASH\n",
	}
	for _, body := range bodies {
		_, err := Validate([]byte(body), 1000)
		if err == nil {
			t.Errorf("Validate(%q) succeeded, want error", body)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error leaks content: %q", err)
		}
	}
}

func TestValidateReportsDuration(t *testing.T) {
	res, err := Validate([]byte(sample), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %s, want > 0", res.Duration)
	}
}

// synthetic builds an exposition resembling node_exporter output with about
// the given number of samples: labelled counters and gauges plus histograms.
// It is generated rather than captured, so that no host data is versioned.
func synthetic(samples int) []byte {
	var b strings.Builder
	n := 0
	for fam := 0; n < samples; fam++ {
		switch fam % 4 {
		case 0, 1:
			fmt.Fprintf(&b, "# HELP node_synthetic_%d_total Synthetic counter %d.\n# TYPE node_synthetic_%d_total counter\n", fam, fam, fam)
			for i := 0; i < 32 && n < samples; i++ {
				fmt.Fprintf(&b, "node_synthetic_%d_total{cpu=\"%d\",mode=\"user\"} %d.25\n", fam, i, 1000000+i*37)
				n++
			}
		case 2:
			fmt.Fprintf(&b, "# HELP node_synthetic_%d_bytes Synthetic gauge %d.\n# TYPE node_synthetic_%d_bytes gauge\n", fam, fam, fam)
			for i := 0; i < 16 && n < samples; i++ {
				fmt.Fprintf(&b, "node_synthetic_%d_bytes{device=\"sd%c\",fstype=\"ext4\",mountpoint=\"/srv/data%d\"} %d\n", fam, 'a'+i%26, i, 1<<34+i)
				n++
			}
		case 3:
			fmt.Fprintf(&b, "# HELP node_synthetic_%d_seconds Synthetic histogram %d.\n# TYPE node_synthetic_%d_seconds histogram\n", fam, fam, fam)
			for _, le := range []string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "+Inf"} {
				fmt.Fprintf(&b, "node_synthetic_%d_seconds_bucket{le=\"%s\"} %d\n", fam, le, n)
				n++
			}
			fmt.Fprintf(&b, "node_synthetic_%d_seconds_sum 123.45\nnode_synthetic_%d_seconds_count %d\n", fam, fam, n)
			n += 2
		}
	}
	return []byte(b.String())
}

func TestSynthetic(t *testing.T) {
	body := synthetic(2000)
	res, err := Validate(body, 1<<20)
	if err != nil {
		t.Fatalf("synthetic data invalid: %v", err)
	}
	if res.Samples < 2000 || res.Samples > 2020 {
		t.Errorf("Samples = %d, want about 2000", res.Samples)
	}
}

// BenchmarkValidate measures parsing cost for typical and large exporters.
// Run with: go test -bench=Validate -benchmem ./internal/content/
func BenchmarkValidate(b *testing.B) {
	for _, samples := range []int{2000, 10000, 50000} {
		body := synthetic(samples)
		b.Run(fmt.Sprintf("samples=%d", samples), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Validate(body, 1<<20); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Quoted content holding escaped quotes is hidden whole.
func TestSafeMessageHidesEscapedQuotes(t *testing.T) {
	for _, body := range []string{
		"m{l=\"abc\\\"SECRET-PASSWORD-123\\xff\"} 1\n",
		"m 1 2 \"SECRET-PASSWORD-123\n",
	} {
		_, err := Validate([]byte(body), 100)
		if err == nil {
			t.Fatalf("%q: accepted", body)
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%q: message leaks content: %v", body, err)
		}
	}
}
