package source

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// fileSource reads a static file in the Prometheus text format.
type fileSource struct {
	path         string
	maxAge       time.Duration
	timeout      time.Duration
	maxBodyBytes int64
	now          func() time.Time // replaced in tests
}

func newFileSource(r config.Route) *fileSource {
	return &fileSource{
		path:         r.File,
		maxAge:       r.MaxAge,
		timeout:      r.Limits.Timeout,
		maxBodyBytes: r.Limits.MaxBodyBytes,
		now:          time.Now,
	}
}

// Fetch opens the file, checks it on the open descriptor (so that it cannot
// be swapped between check and read), then reads it.
//
// Local file reads cannot be interrupted: the timeout is checked once the
// read is done, so a file on a hung network mount can still block.
func (s *fileSource) Fetch(ctx context.Context) (*Result, error) {
	start := s.now()

	// O_NONBLOCK: opening a FIFO must not block waiting for a writer. It
	// has no effect on regular files.
	f, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &Error{Reason: ReasonUnavailable, Err: err}
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, &Error{Reason: ReasonUnavailable, Err: err}
	}
	if !info.Mode().IsRegular() {
		return nil, newError(ReasonUnavailable, "%s is not a regular file (%s)", s.path, info.Mode().Type())
	}

	res := &Result{ModTime: info.ModTime()}
	if age := start.Sub(info.ModTime()); age > s.maxAge {
		return res, newError(ReasonStale, "%s was modified %s ago, more than max_age (%s)",
			s.path, age.Truncate(time.Second), s.maxAge)
	}
	if info.Size() > s.maxBodyBytes {
		return res, newError(ReasonTooLarge, "%s size %d exceeds max_body_bytes (%d)",
			s.path, info.Size(), s.maxBodyBytes)
	}

	// The file may grow between Stat and read: the read is bounded too.
	body, err := readLimited(f, s.maxBodyBytes)
	if err != nil {
		return res, classify(ctx, fmt.Errorf("read %s: %w", s.path, err), s.timeout)
	}
	if elapsed := s.now().Sub(start); elapsed > s.timeout {
		return res, newError(ReasonTimeout, "reading %s took %s, more than timeout (%s)",
			s.path, elapsed.Truncate(time.Millisecond), s.timeout)
	}
	if err := ctx.Err(); err != nil {
		return res, classify(ctx, err, s.timeout)
	}

	res.Body = body
	return res, nil
}
