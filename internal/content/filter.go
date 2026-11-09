package content

import (
	"bytes"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

// Filter keeps the metric families of an already validated body whose name
// keep accepts. Kept protobuf messages and text lines are copied byte for
// byte, in their order: nothing is re-encoded, so nothing is added (a
// histogram without _sum or _count lines gets none).
func Filter(body []byte, protobuf bool, keep func(name string) bool) ([]byte, error) {
	if protobuf {
		return filterProtobuf(body, keep)
	}
	return filterText(body, keep), nil
}

// filterText copies the lines of the families keep accepts: their HELP and
// TYPE comments and their sample lines. Other comments and blank lines are
// dropped. Lines are assigned to families exactly like the text parser does
// (see resolve), so the result holds the same families as the original,
// minus the dropped ones.
func filterText(body []byte, keep func(name string) bool) []byte {
	out := make([]byte, 0, len(body))
	r := familyResolver{exists: map[string]bool{}, types: map[string]string{}}
	for len(body) > 0 {
		line := body
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i+1], body[i+1:]
		} else {
			body = nil
		}
		family, ok := r.lineFamily(bytes.TrimLeft(line, " \t"))
		if ok && keep(family) {
			out = append(out, line...)
		}
	}
	return out
}

// familyResolver assigns names to metric families as the text parser of
// expfmt does, line by line: the name itself if it is a family already,
// else the summary of which it is the _sum or _count, else the histogram of
// which it is the _sum, _count or _bucket, else a new family.
type familyResolver struct {
	exists map[string]bool
	types  map[string]string // TYPE keyword of a family, when declared
}

func (r *familyResolver) resolve(name string) string {
	if r.exists[name] {
		return name
	}
	if base, ok := cutSuffixes(name, "_count", "_sum"); ok && r.exists[base] && r.types[base] == "summary" {
		return base
	}
	if base, ok := cutSuffixes(name, "_count", "_sum", "_bucket"); ok && r.exists[base] &&
		(r.types[base] == "histogram" || r.types[base] == "gaugehistogram") {
		return base
	}
	r.exists[name] = true
	return name
}

func cutSuffixes(name string, suffixes ...string) (string, bool) {
	for _, s := range suffixes {
		if base, ok := strings.CutSuffix(name, s); ok {
			return base, true
		}
	}
	return "", false
}

// lineFamily returns the family of a line, with leading blanks removed.
// ok is false for blank lines and comments other than HELP and TYPE.
func (r *familyResolver) lineFamily(line []byte) (string, bool) {
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", false
	}
	if line[0] == '#' {
		keyword, rest := firstWord(bytes.TrimLeft(line[1:], " \t"))
		if keyword != "HELP" && keyword != "TYPE" {
			return "", false
		}
		name, after, ok := metricName(bytes.TrimLeft(rest, " \t"))
		if !ok {
			return "", false
		}
		family := r.resolve(name)
		if keyword == "TYPE" {
			if _, set := r.types[family]; !set {
				// The parser reads the type case-insensitively.
				typ, _ := firstWord(bytes.TrimLeft(after, " \t"))
				r.types[family] = strings.ToLower(typ)
			}
		}
		return family, true
	}
	if line[0] == '{' {
		line = bytes.TrimLeft(line[1:], " \t")
	}
	name, _, ok := metricName(line)
	if !ok {
		return "", false
	}
	return r.resolve(name), true
}

// firstWord splits b at its first blank (space or tab).
func firstWord(b []byte) (string, []byte) {
	if i := bytes.IndexAny(b, " \t"); i >= 0 {
		return string(b[:i]), b[i:]
	}
	return string(b), nil
}

// metricName reads the metric name at the start of b: quoted (UTF-8 names)
// or the longest run of [a-zA-Z0-9_:]. It returns the rest of b.
func metricName(b []byte) (name string, rest []byte, ok bool) {
	if len(b) > 0 && b[0] == '"' {
		escaped := false
		for i := 1; i < len(b); i++ {
			switch {
			case escaped:
				escaped = false
			case b[i] == '\\':
				escaped = true
			case b[i] == '"':
				n, err := strconv.Unquote(string(b[:i+1]))
				return n, b[i+1:], err == nil
			}
		}
		return "", nil, false
	}
	// Like the parser: an unquoted name is made of [a-zA-Z0-9_:].
	end := 0
	for end < len(b) && isNameChar(b[end]) {
		end++
	}
	return string(b[:end]), b[end:], end > 0
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == ':'
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
		name, ok := familyName(rest[prefix : prefix+int(size)])
		if !ok {
			return nil, source.NewError(source.ReasonInvalid, "not in delimited protobuf format")
		}
		rest = rest[prefix+int(size):]
		if keep(name) {
			out = append(out, msg...)
		}
	}
	return out, nil
}

// nameField is MetricFamily.name.
const nameField = 1

// familyName reads the name of an encoded MetricFamily without decoding the
// rest of it (the body was validated, decoding it again only cost time). As
// in protobuf, the last occurrence of the field wins.
func familyName(msg []byte) (string, bool) {
	name := ""
	for len(msg) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(msg)
		if tagLen < 0 {
			return "", false
		}
		valLen := protowire.ConsumeFieldValue(num, typ, msg[tagLen:])
		if valLen < 0 {
			return "", false
		}
		if num == nameField && typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(msg[tagLen:])
			name = string(v)
		}
		msg = msg[tagLen+valLen:]
	}
	return name, true
}
