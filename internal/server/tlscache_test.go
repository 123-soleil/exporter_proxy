package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// cacheClock is a settable clock for tlsCache.
type cacheClock struct{ t time.Time }

func (c *cacheClock) now() time.Time { return c.t }

func newTestTLSCache(ttl time.Duration) (*tlsCache, *cacheClock) {
	var v atomic.Int64
	v.Store(int64(ttl))
	clock := &cacheClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	c := newTLSCache(&v)
	c.now = clock.now
	return c, clock
}

// tlsConfigValidUntil returns a TLS configuration pinning a certificate
// valid until notAfter.
func tlsConfigValidUntil(t *testing.T, notAfter time.Time) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "srv"},
		NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func crlSetUntil(next time.Time) *crlSet {
	return &crlSet{lists: []*x509.RevocationList{{NextUpdate: next}}}
}

func TestTLSCacheConfigExpiry(t *testing.T) {
	tests := []struct {
		name     string
		ttl      time.Duration
		certEnd  time.Duration // from now
		crlNext  time.Duration // from now, 0 for no CRL
		validFor time.Duration // how long the entry must be served
	}{
		{"bounded by tls_cache_ttl", 5 * time.Minute, 30 * 24 * time.Hour, 0, 5 * time.Minute},
		{"bounded by the certificate", 6 * time.Hour, time.Minute, 0, time.Minute},
		{"bounded by the next CRL update", 6 * time.Hour, 30 * 24 * time.Hour, 2 * time.Minute, 2 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, clock := newTestTLSCache(tt.ttl)
			cfg := tlsConfigValidUntil(t, clock.t.Add(tt.certEnd))
			var set *crlSet
			crl := ""
			if tt.crlNext > 0 {
				set, crl = crlSetUntil(clock.t.Add(tt.crlNext)), "/crl.pem"
			}
			c.storeConfig(c.begin(), cfg, crl, set)

			clock.t = clock.t.Add(tt.validFor - time.Second)
			if c.config(crl) != cfg {
				t.Fatal("entry not served before it expires")
			}
			clock.t = clock.t.Add(time.Second)
			if c.config(crl) != nil {
				t.Error("entry served past its expiry")
			}
		})
	}
}

func TestTLSCacheDisabledFlushAndPath(t *testing.T) {
	off, clock := newTestTLSCache(0)
	cfg := tlsConfigValidUntil(t, clock.t.Add(time.Hour))
	off.storeConfig(off.begin(), cfg, "", nil)
	if off.config("") != nil {
		t.Error("tls_cache_ttl 0 cached a configuration")
	}

	c, clock := newTestTLSCache(time.Hour)
	c.storeConfig(c.begin(), tlsConfigValidUntil(t, clock.t.Add(24*time.Hour)), "/a.crl", nil)
	if c.config("/b.crl") != nil {
		t.Error("configuration built for another client_crl_file served")
	}
	c.flush()
	if c.config("/a.crl") != nil {
		t.Error("configuration served after a flush")
	}
}

func TestTLSCacheCRL(t *testing.T) {
	c, clock := newTestTLSCache(time.Hour)
	loads := 0
	set := crlSetUntil(clock.t.Add(10 * time.Minute))
	load := func() (*crlSet, error) { loads++; return set, nil }

	for range 3 {
		if got, err := c.crlSet("/a.crl", load); err != nil || got != set {
			t.Fatalf("crlSet = %v, %v", got, err)
		}
	}
	if loads != 1 {
		t.Errorf("CRL loaded %d times within the cache duration, want 1", loads)
	}
	// Past its next update the CRL is read again (and refused by
	// loadCRL), never served from the cache.
	clock.t = clock.t.Add(10 * time.Minute)
	_, _ = c.crlSet("/a.crl", load)
	if loads != 2 {
		t.Errorf("CRL past its next update served from the cache (loads %d)", loads)
	}

	// Failures are not cached.
	failing := 0
	fail := func() (*crlSet, error) { failing++; return nil, errors.New("unreadable") }
	for range 2 {
		if _, err := c.crlSet("/b.crl", fail); err == nil {
			t.Fatal("failure not returned")
		}
	}
	if failing != 2 {
		t.Errorf("failure cached: loaded %d times, want 2", failing)
	}
}

// A read that started before a flush (a reload) does not store what it
// read: the files of before the reload would be served for tls_cache_ttl.
func TestTLSCacheFlushDuringRead(t *testing.T) {
	c, clock := newTestTLSCache(time.Hour)

	// CRL read by a request, a reload flushing meanwhile.
	old := crlSetUntil(clock.t.Add(24 * time.Hour))
	if _, err := c.crlSet("/a.crl", func() (*crlSet, error) {
		c.flush() // the reload commits while the file is being read
		return old, nil
	}); err != nil {
		t.Fatal(err)
	}
	fresh := crlSetUntil(clock.t.Add(24 * time.Hour))
	if got, _ := c.crlSet("/a.crl", func() (*crlSet, error) { return fresh, nil }); got != fresh {
		t.Error("CRL read before the reload served after it")
	}

	// TLS configuration built by a handshake, a reload flushing meanwhile.
	epoch := c.begin()
	cfg := tlsConfigValidUntil(t, clock.t.Add(24*time.Hour))
	c.flush()
	c.storeConfig(epoch, cfg, "", nil)
	if c.config("") != nil {
		t.Error("TLS configuration built before the reload served after it")
	}
}
