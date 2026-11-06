// Package errfmt formats errors for structured logs.
package errfmt

import "strings"

// OneLine returns the message of err on a single line, so that each log
// event stays on one line whatever the error wraps (YAML, TLS, ...).
func OneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
