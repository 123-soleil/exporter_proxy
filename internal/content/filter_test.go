package content

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
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

// Filtering copies lines: nothing is added. Re-encoding gave a histogram
// without _sum and _count lines "h_sum 0" and "h_count 0".
func TestFilterTextAddsNothing(t *testing.T) {
	in := "# TYPE h histogram\n" +
		"h_bucket{le=\"1\"} 3\n" +
		"h_bucket{le=\"+Inf\"} 5\n" +
		"# TYPE s summary\n" +
		"s{quantile=\"0.5\"} 1\n" +
		"other 1\n"
	out, err := Filter([]byte(in), false, func(name string) bool { return name != "other" })
	if err != nil {
		t.Fatal(err)
	}
	want := "# TYPE h histogram\nh_bucket{le=\"1\"} 3\nh_bucket{le=\"+Inf\"} 5\n# TYPE s summary\ns{quantile=\"0.5\"} 1\n"
	if string(out) != want {
		t.Errorf("filtered:\n%s\nwant (the original lines, nothing added):\n%s", out, want)
	}
}

// filterCases are bodies whose families the line resolution must assign
// exactly like the parser.
var filterCases = []string{
	filterInput,
	// UTF-8 names, quoted, with escapes, in comments and samples.
	"# HELP \"my.metric\" A dotted name.\n# TYPE \"my.metric\" gauge\n{\"my.metric\", zone=\"a\"} 1\n{\"my.metric\"} 2\n" +
		"# TYPE \"esc\\\"aped\" counter\n{\"esc\\\"aped\"} 3\nplain 4\n",
	// _count seen before the histogram is declared: its own family.
	"x_count 1\n# TYPE x histogram\nx_bucket{le=\"+Inf\"} 1\nx_sum 0\n",
	// A HELP for x_count after the histogram x resolves to x.
	"# TYPE x histogram\nx_bucket{le=\"+Inf\"} 1\n# HELP x_count help\nx_count 1\nx_sum 2\n",
	// Summary and histogram suffixes, gauge named like a suffix.
	"# TYPE s summary\ns{quantile=\"0.9\"} 1\ns_sum 2\ns_count 3\n# TYPE g_count gauge\ng_count 7\n",
	// Found by review: the name after labels inside braces, quotes inside
	// a name, a HELP without text, types spelled or cased differently.
	"{zone=\"a\",\"secret\"} 1\nzone 2\n",
	"{zone=\"a\",secret} 1\nzone 2\n",
	"foo\"bar\" 1\nfoo 2\n",
	"# HELP foo\"bar\" secret help\nfoo\"bar\" 1\nfoo 2\n",
	"# HELP h_sum\n# TYPE h histogram\nh_bucket{le=\"+Inf\"} 1\nh_sum 3\nh_count 1\n",
	"# TYPE g gauge_histogram\ng_bucket{le=\"+Inf\"} 1\ng_sum 3\ng_count 1\n",
	"# TYPE g gaugehistogram\ng_bucket{le=\"+Inf\"} 1\ng_sum 3\ng_count 1\nother 1\n",
	"# TYPE s \u017fummary\ns{quantile=\"0.5\"} 1\ns_sum 2\ns_count 3\n",
	"# TYPE h h\u0131stogram\nh_bucket{le=\"+Inf\"} 1\nh_sum 3\nh_count 1\n",
	"A\"0\"0\n",
	// Blank lines, other comments, leading blanks, timestamps.
	"\n# just a comment\n  a 1 1700000000000\n\n# TYPE b counter\nb_total 2\nb 3\n",
}

// Parsing the filtered body gives the original families minus the dropped
// ones, unchanged.
func TestFilterTextKeepsFamiliesIntact(t *testing.T) {
	for i, in := range filterCases {
		if _, _, err := parseText([]byte(in), 1000); err != nil {
			t.Fatalf("case %d invalid: %v", i, err)
		}
		checkFilterEquivalence(t, []byte(in))
	}
}

// checkFilterEquivalence checks Filter on a body for several keep
// functions, among them dropping each family in turn: the output parses,
// serves no dropped family and every kept one; when it is the copy of the
// source's lines, every kept family is unchanged.
func checkFilterEquivalence(t *testing.T, body []byte) {
	t.Helper()
	_, orig, err := parseText(body, 1<<30)
	if err != nil {
		return // only validated bodies are filtered
	}
	keeps := []func(string) bool{
		func(string) bool { return true },
		func(string) bool { return false },
		func(n string) bool { return len(n)%2 == 0 },
		func(n string) bool { return strings.Contains(n, "_") },
	}
	for name := range orig {
		keeps = append(keeps, func(n string) bool { return n != name })
	}
	for _, keep := range keeps {
		out, err := Filter(body, false, keep)
		if err != nil {
			t.Fatalf("Filter: %v", err)
		}
		_, got, err := parseText(out, 1<<30)
		if err != nil {
			t.Fatalf("filtered body invalid: %v\ninput:\n%q\noutput:\n%q", err, body, out)
		}
		for name := range got {
			if _, known := orig[name]; !known || !keep(name) {
				t.Fatalf("family %q served although dropped or unknown\ninput:\n%q\noutput:\n%q", name, body, out)
			}
		}
		for name := range orig {
			if _, served := got[name]; keep(name) && !served {
				t.Errorf("kept family %q missing\ninput:\n%q\noutput:\n%q", name, body, out)
			}
		}
		if string(out) == string(filterText(body, keep)) {
			for name, mf := range got {
				if !proto.Equal(mf, orig[name]) {
					t.Errorf("copied family %q changed\ninput:\n%q\noutput:\n%q", name, body, out)
				}
			}
		}
	}
}

func FuzzFilterText(f *testing.F) {
	for _, c := range filterCases {
		f.Add([]byte(c))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		checkFilterEquivalence(t, body)
	})
}

// A gauge histogram spelled the OpenMetrics way keeps its lines: the copy
// path, not the re-encoding fallback (which would change its type).
func TestFilterGaugeHistogramCopied(t *testing.T) {
	in := "# TYPE g gaugehistogram\ng_bucket{le=\"+Inf\"} 1\ng_sum 3\ng_count 1\nother 1\n"
	out, err := Filter([]byte(in), false, func(n string) bool { return n == "g" })
	if err != nil {
		t.Fatal(err)
	}
	want := "# TYPE g gaugehistogram\ng_bucket{le=\"+Inf\"} 1\ng_sum 3\ng_count 1\n"
	if string(out) != want {
		t.Errorf("filtered:\n%s\nwant the source's lines:\n%s", out, want)
	}
}
