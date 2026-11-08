package content

import (
	"bytes"
	"maps"
	"slices"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

// Filter keeps the metric families of an already validated body whose name
// keep accepts. Protobuf messages kept are copied byte for byte; text is
// re-encoded family by family, sorted by name (the only reliable way to
// keep every line of a family, histogram buckets included).
func Filter(body []byte, protobuf bool, keep func(name string) bool) ([]byte, error) {
	if protobuf {
		return filterProtobuf(body, keep)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		return nil, source.NewError(source.ReasonInvalid, "not in Prometheus text format: %s", safeMessage(err))
	}
	return encodeText(families, keep)
}

// encodeText encodes the families keep accepts, sorted by name.
func encodeText(families map[string]*dto.MetricFamily, keep func(name string) bool) ([]byte, error) {
	var out bytes.Buffer
	for _, name := range slices.Sorted(maps.Keys(families)) {
		if !keep(name) {
			continue
		}
		if _, err := expfmt.MetricFamilyToText(&out, families[name]); err != nil {
			return nil, source.NewError(source.ReasonInvalid, "cannot re-encode metric family: %v", err)
		}
	}
	return out.Bytes(), nil
}

// filterProtobuf copies the delimited messages whose family name keep
// accepts. The body was validated: lengths are within it.
func filterProtobuf(body []byte, keep func(name string) bool) ([]byte, error) {
	out := make([]byte, 0, len(body))
	for rest := body; len(rest) > 0; {
		size, prefix := protowire.ConsumeVarint(rest)
		if prefix < 0 || size > uint64(len(rest)-prefix) {
			return nil, source.NewError(source.ReasonInvalid, "not in delimited protobuf format")
		}
		msg := rest[:prefix+int(size)]
		var mf dto.MetricFamily
		if err := proto.Unmarshal(rest[prefix:prefix+int(size)], &mf); err != nil {
			return nil, source.NewError(source.ReasonInvalid, "not in delimited protobuf format")
		}
		rest = rest[prefix+int(size):]
		if keep(mf.GetName()) {
			out = append(out, msg...)
		}
	}
	return out, nil
}
