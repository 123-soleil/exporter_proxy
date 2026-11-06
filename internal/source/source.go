// Package source reads metrics from the source of a route: an HTTP exporter
// over TCP, an HTTP exporter over a Unix socket, or a static file.
//
// Every read is bounded in time (timeout) and size (max_body_bytes). Failures
// are returned as *Error values carrying a Reason, a fixed set of values used
// as a metric label.
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// Reason classifies a failed read. Values are used as metric label values:
// keep the set small and fixed.
type Reason string

// Reasons returned by sources.
const (
	ReasonUnavailable Reason = "unavailable" // connection, file or HTTP status error
	ReasonTimeout     Reason = "timeout"     // timeout reached
	ReasonTooLarge    Reason = "too_large"   // content larger than max_body_bytes
	ReasonStale       Reason = "stale"       // file older than max_age

	// Returned by content validation, kept here so that all reasons form
	// one set.
	ReasonInvalid        Reason = "invalid"          // not in the Prometheus text format
	ReasonTooManySamples Reason = "too_many_samples" // more samples than max_samples
)

// NewError returns an *Error with the given reason.
func NewError(reason Reason, format string, args ...any) *Error {
	return newError(reason, format, args...)
}

// Error is a failed read with its reason.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %v", e.Reason, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

// ReasonOf returns the reason of err, ReasonUnavailable for an error that is
// not an *Error, and "" for nil.
func ReasonOf(err error) Reason {
	if err == nil {
		return ""
	}
	var se *Error
	if errors.As(err, &se) {
		return se.Reason
	}
	return ReasonUnavailable
}

func newError(reason Reason, format string, args ...any) *Error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// Result is the content read from a source.
type Result struct {
	Body []byte

	// ModTime is the modification time of a file source; zero for HTTP
	// sources. It is also set alongside a ReasonStale error.
	ModTime time.Time
}

// Source reads the metrics of one route.
type Source interface {
	// Fetch reads the whole content. On error, the returned Result may still
	// carry metadata (ModTime) but no Body.
	Fetch(ctx context.Context) (*Result, error)
}

// New returns the source described by a validated route.
func New(r config.Route) (Source, error) {
	switch {
	case r.File != "":
		return newFileSource(r), nil
	case r.Upstream != "":
		return newHTTPSource(r)
	default:
		return nil, errors.New("route has no source")
	}
}

// readLimited reads at most limit bytes from r and fails with
// ReasonTooLarge if there is more, without reading the rest.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	probe := limit + 1 // one more byte tells that there is more
	if probe < limit {
		probe = limit // overflow: cannot be exceeded anyway
	}
	body, err := io.ReadAll(io.LimitReader(r, probe))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, newError(ReasonTooLarge, "content exceeds max_body_bytes (%d)", limit)
	}
	return body, nil
}

// classify converts a deadline error to ReasonTimeout, other errors to
// ReasonUnavailable, and keeps *Error values unchanged.
func classify(ctx context.Context, err error, timeout time.Duration) error {
	var se *Error
	if errors.As(err, &se) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(ReasonTimeout, "no complete answer within %s: %w", timeout, err)
	}
	return &Error{Reason: ReasonUnavailable, Err: err}
}
