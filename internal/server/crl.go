package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/webconfig"
)

// crlSet holds the certificate revocation lists of a client_crl_file.
type crlSet struct {
	lists []*x509.RevocationList
	// revoked indexes the revoked serial numbers of each list.
	revoked []map[string]bool

	// verified caches CRL signature checks, by CRL index and issuer
	// certificate.
	mu       sync.Mutex
	verified map[crlIssuer]bool
}

type crlIssuer struct {
	crl    int
	issuer [sha256.Size]byte
}

// crlCache keeps the parsed CRLs by file content: a client_crl_file is
// read on every new connection and request, parsed only when it changes.
var crlCache = struct {
	sync.Mutex
	m map[[sha256.Size]byte]*crlSet
}{m: map[[sha256.Size]byte]*crlSet{}}

const maxCRLCacheEntries = 16

// loadCRL reads and parses a client_crl_file: one or more CRLs, PEM
// ("X509 CRL") or a single DER one. Their validity is checked against now:
// a CRL not yet valid or past its next update is an error, which refuses
// client certificates (fail closed) rather than trusting a stale list.
func loadCRL(path string, now time.Time) (*crlSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client_crl_file: %w", err)
	}
	key := sha256.Sum256(data)
	crlCache.Lock()
	set := crlCache.m[key]
	crlCache.Unlock()
	if set == nil {
		if set, err = parseCRLs(data); err != nil {
			return nil, fmt.Errorf("client_crl_file %s: %w", path, err)
		}
		crlCache.Lock()
		if len(crlCache.m) >= maxCRLCacheEntries {
			clear(crlCache.m)
		}
		crlCache.m[key] = set
		crlCache.Unlock()
	}
	for i, l := range set.lists {
		switch {
		case now.Before(l.ThisUpdate):
			return nil, fmt.Errorf("client_crl_file %s: CRL %d is not valid before %s", path, i+1, l.ThisUpdate.UTC().Format(time.RFC3339))
		case !l.NextUpdate.IsZero() && now.After(l.NextUpdate):
			return nil, fmt.Errorf("client_crl_file %s: CRL %d is past its next update (%s): publish a new one",
				path, i+1, l.NextUpdate.UTC().Format(time.RFC3339))
		}
	}
	return set, nil
}

func parseCRLs(data []byte) (*crlSet, error) {
	lists, err := webconfig.ParseCRLs(data)
	if err != nil {
		return nil, err
	}
	set := &crlSet{lists: lists, verified: map[crlIssuer]bool{}}
	for _, l := range lists {
		serials := make(map[string]bool, len(l.RevokedCertificateEntries))
		for _, e := range l.RevokedCertificateEntries {
			serials[string(e.SerialNumber.Bytes())+e.SerialNumber.String()] = true
		}
		set.revoked = append(set.revoked, serials)
	}
	return set, nil
}

// errRevoked refuses a client certificate listed by a CRL.
var errRevoked = errors.New("client certificate revoked")

// check accepts verified chains when at least one is covered and clean:
// every certificate but the root has a CRL from its issuer, signed by it,
// that does not list it. A certificate whose issuer has no CRL is refused:
// revocation cannot be checked (fail closed).
func (s *crlSet) check(chains [][]*x509.Certificate) error {
	if len(chains) == 0 {
		return nil // no client certificate
	}
	var err error
	for _, chain := range chains {
		if err = s.checkChain(chain); err == nil {
			return nil
		}
	}
	return err
}

func (s *crlSet) checkChain(chain []*x509.Certificate) error {
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		lists := s.listsOf(issuer)
		if len(lists) == 0 {
			return fmt.Errorf("no CRL from %q in client_crl_file: the revocation of %q cannot be checked",
				issuer.Subject.String(), cert.Subject.String())
		}
		// Every CRL of the issuer counts: one listing the certificate
		// revokes it (an older CRL left next to a newer one never hides a
		// revocation).
		key := string(cert.SerialNumber.Bytes()) + cert.SerialNumber.String()
		for _, i := range lists {
			if s.revoked[i][key] {
				return fmt.Errorf("%w: %q (serial %s)", errRevoked, cert.Subject.String(), cert.SerialNumber)
			}
		}
	}
	return nil
}

// listsOf returns the indexes of the CRLs issued and signed by issuer.
func (s *crlSet) listsOf(issuer *x509.Certificate) []int {
	id := sha256.Sum256(issuer.Raw)
	var found []int
	for i, l := range s.lists {
		if !bytes.Equal(l.RawIssuer, issuer.RawSubject) {
			continue
		}
		k := crlIssuer{i, id}
		s.mu.Lock()
		ok, known := s.verified[k]
		s.mu.Unlock()
		if !known {
			ok = l.CheckSignatureFrom(issuer) == nil
			s.mu.Lock()
			s.verified[k] = ok
			s.mu.Unlock()
		}
		if ok {
			found = append(found, i)
		}
	}
	return found
}
