package server

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"
)

// tlsCache keeps what a listener reads for every new TLS connection and
// every request: the TLS configuration built from its web configuration
// file (certificate, key, client CA, client_crl_file) and its CRLs. An
// entry is reused for tls_cache_ttl, never past the end of the server
// certificate's validity nor past the next update of a CRL, so the cache
// never serves an expired certificate nor a stale CRL. Failures are not
// cached: the next connection reads the files again. A reload empties it.
type tlsCache struct {
	ttl *atomic.Int64 // tls_cache_ttl of the server, in nanoseconds
	now func() time.Time

	mu sync.Mutex
	// epoch is incremented by flush: a read started before a flush (a
	// reload) must not store what it read, or the files of before the
	// reload would be served for a whole tls_cache_ttl.
	epoch    uint64
	cfg      *tls.Config
	cfgCRL   string // client_crl_file the configuration was built with
	cfgUntil time.Time
	crl      *crlSet
	crlPath  string
	crlUntil time.Time
}

func newTLSCache(ttl *atomic.Int64) *tlsCache {
	return &tlsCache{ttl: ttl, now: time.Now}
}

// until returns when an entry built now and valid until notAfter (zero for
// no bound) expires; ok is false when nothing must be cached.
func (c *tlsCache) until(notAfter time.Time) (time.Time, bool) {
	ttl := time.Duration(c.ttl.Load())
	if ttl <= 0 {
		return time.Time{}, false
	}
	u := c.now().Add(ttl)
	if !notAfter.IsZero() && notAfter.Before(u) {
		u = notAfter
	}
	return u, true
}

// begin returns the current epoch, to pass to the store methods after
// reading the files.
func (c *tlsCache) begin() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

// config returns the cached TLS configuration built with the
// client_crl_file crl, or nil.
func (c *tlsCache) config(crl string) *tls.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg != nil && c.cfgCRL == crl && c.now().Before(c.cfgUntil) {
		return c.cfg
	}
	return nil
}

// storeConfig caches cfg, built with the client_crl_file crl whose lists
// are set (nil for none), from files read since epoch.
func (c *tlsCache) storeConfig(epoch uint64, cfg *tls.Config, crl string, set *crlSet) {
	u, ok := c.until(earliest(certNotAfter(cfg), set.nextUpdate()))
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epoch != epoch {
		return // flushed meanwhile: what was read may be outdated
	}
	c.cfg, c.cfgCRL, c.cfgUntil = cfg, crl, u
}

// crlSet returns the CRLs of path, from the cache or from load.
func (c *tlsCache) crlSet(path string, load func() (*crlSet, error)) (*crlSet, error) {
	c.mu.Lock()
	if c.crl != nil && c.crlPath == path && c.now().Before(c.crlUntil) {
		set := c.crl
		c.mu.Unlock()
		return set, nil
	}
	epoch := c.epoch
	c.mu.Unlock()
	set, err := load()
	if err != nil {
		return nil, err
	}
	if u, ok := c.until(set.nextUpdate()); ok {
		c.mu.Lock()
		if c.epoch == epoch {
			c.crl, c.crlPath, c.crlUntil = set, path, u
		}
		c.mu.Unlock()
	}
	return set, nil
}

// flush forgets everything: the next connection and request read the
// files again.
func (c *tlsCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.cfg, c.crl = nil, nil
}

// certNotAfter returns the end of validity of the server certificate
// pinned in cfg, zero when unknown.
func certNotAfter(cfg *tls.Config) time.Time {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return time.Time{}
	}
	leaf := cfg.Certificates[0].Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cfg.Certificates[0].Certificate[0]); err != nil {
			return time.Time{}
		}
	}
	return leaf.NotAfter
}

// nextUpdate returns the earliest next update of the CRLs, zero for none.
func (s *crlSet) nextUpdate() time.Time {
	if s == nil {
		return time.Time{}
	}
	var t time.Time
	for _, l := range s.lists {
		t = earliest(t, l.NextUpdate)
	}
	return t
}

// earliest returns the earliest non-zero time of a and b, zero if both are.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}
