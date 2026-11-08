package proxy

import (
	"fmt"
	"net/url"
	"slices"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// checkParams checks the query string of a request against the route's
// forward_params and returns the parameters to forward, or why the request
// is refused (a 400 message naming only configured parameters, never
// client text). Without forward_params, the query string is ignored.
func checkParams(params map[string]config.ForwardParam, rawQuery string) (url.Values, string) {
	if params == nil {
		return nil, ""
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, "malformed query string"
	}
	for name, values := range q {
		p, ok := params[name]
		switch {
		case !ok:
			return nil, "query parameter not allowed"
		case len(values) != 1:
			return nil, fmt.Sprintf("query parameter %q given more than once", name)
		case len(values[0]) > config.MaxParamValueLength:
			return nil, fmt.Sprintf("query parameter %q too long", name)
		case !allowedValue(p, values[0]):
			return nil, fmt.Sprintf("value not allowed for query parameter %q", name)
		}
	}
	for name, p := range params {
		if p.Required && !q.Has(name) {
			return nil, fmt.Sprintf("query parameter %q is required", name)
		}
	}
	return q, ""
}

func allowedValue(p config.ForwardParam, v string) bool {
	if slices.Contains(p.Values, v) {
		return true
	}
	for _, re := range p.Patterns {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}
