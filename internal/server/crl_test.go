package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// crlPKI is a client CA able to issue client certificates and CRLs.
type crlPKI struct {
	t      *testing.T
	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPath string
	serial int64
}

func newCRLPKI(t *testing.T) *crlPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "crl test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &crlPKI{t: t, dir: t.TempDir(), ca: ca, caKey: key, serial: 10}
	p.caPath = filepath.Join(p.dir, "ca.pem")
	p.write(p.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return p
}

func (p *crlPKI) write(path string, data []byte) {
	p.t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		p.t.Fatal(err)
	}
}

// client issues a client certificate and returns its serial and a client
// using it.
func (p *crlPKI) client(name string) (*big.Int, *http.Client) {
	p.t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return tmpl.SerialNumber, &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}, //nolint:gosec // test server
	}}
}

// crl writes a CRL revoking serials, valid from thisUpdate to nextUpdate.
func (p *crlPKI) crl(path string, thisUpdate, nextUpdate time.Time, serials ...*big.Int) {
	p.t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(time.Now().UnixNano()), ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
		RevokedCertificateEntries: entries,
	}, p.ca, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	p.write(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

// crlServer starts an mTLS listener verifying client certificates against
// pki's CA, with client_crl_file crlPath.
func crlServer(t *testing.T, pki *crlPKI, crlPath string) (*Server, config.Listener, *mtlsTest) {
	t.Helper()
	m := newMTLSTest(t, "")
	m.writeMTLSWeb(t, pki.caPath)
	m.l.ClientCRLFile = crlPath
	m.reload(t)
	return m.s, m.l, m
}

func status(c *http.Client, url string) (int, error) {
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestClientCRL(t *testing.T) {
	pki := newCRLPKI(t)
	goodSerial, good := pki.client("good")
	badSerial, bad := pki.client("bad")
	crlPath := filepath.Join(pki.dir, "clients.crl")
	pki.crl(crlPath, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), badSerial)
	_, _, m := crlServer(t, pki, crlPath)

	deadline := time.Now().Add(3 * time.Second)
	for {
		if code, err := status(good, m.url()); err == nil && code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client not revoked refused")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := status(bad, m.url()); err == nil {
		t.Error("revoked client accepted")
	}

	// Revoking the good client while its connection is open: its next
	// request is refused and the connection closed.
	pki.crl(crlPath, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), badSerial, goodSerial)
	if code, err := status(good, m.url()); err == nil && code != http.StatusForbidden {
		t.Errorf("client revoked while connected: code %d, want 403 (or a refused handshake)", code)
	}
	if code, err := status(good, m.url()); err == nil {
		t.Errorf("client revoked: new connection answered %d", code)
	}
}

// A CRL past its next update refuses client certificates (fail closed).
func TestClientCRLExpired(t *testing.T) {
	pki := newCRLPKI(t)
	_, good := pki.client("good")
	crlPath := filepath.Join(pki.dir, "clients.crl")
	pki.crl(crlPath, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	_, _, m := crlServer(t, pki, crlPath)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if code, err := status(good, m.url()); err == nil && code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client refused with a valid CRL")
		}
		time.Sleep(20 * time.Millisecond)
	}
	pki.crl(crlPath, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	good.CloseIdleConnections()
	if _, err := status(good, m.url()); err == nil {
		t.Error("client accepted with an expired CRL")
	}
}

// A certificate whose issuer has no CRL in the file is refused: its
// revocation cannot be checked.
func TestClientCRLMustCoverTheIssuer(t *testing.T) {
	pki, other := newCRLPKI(t), newCRLPKI(t)
	_, good := pki.client("good")
	crlPath := filepath.Join(pki.dir, "clients.crl")
	other.crl(crlPath, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)) // another CA's CRL
	_, _, m := crlServer(t, pki, crlPath)
	if _, err := status(good, m.url()); err == nil {
		t.Error("client accepted although no CRL covers its CA")
	}
}

// client_crl_file needs verified client certificates, and a reload cannot
// remove it (it would lower protection).
func TestClientCRLConfiguration(t *testing.T) {
	pki := newCRLPKI(t)
	crlPath := filepath.Join(pki.dir, "clients.crl")
	pki.crl(crlPath, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	m := newMTLSTest(t, "") // TLS without client certificates
	m.l.ClientCRLFile = crlPath
	if err := m.s.Reload(&config.Config{Listeners: []config.Listener{m.l}}); err == nil ||
		!strings.Contains(err.Error(), "client_crl_file needs a web configuration verifying client certificates") {
		t.Errorf("CRL without verified client certificates: err = %v", err)
	}

	_, l, m2 := crlServer(t, pki, crlPath)
	l.ClientCRLFile = ""
	if err := m2.s.Reload(&config.Config{Listeners: []config.Listener{l}}); err == nil ||
		!strings.Contains(err.Error(), "client_crl_file") {
		t.Errorf("reload removing the CRL: err = %v, want a refusal", err)
	}

	bad := filepath.Join(pki.dir, "bad.crl")
	pki.write(bad, []byte("not a crl"))
	l.ClientCRLFile = bad
	if err := m2.s.Reload(&config.Config{Listeners: []config.Listener{l}}); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("client_crl_file %s", bad)) {
		t.Errorf("unparsable CRL: err = %v", err)
	}
}

// crlDER returns a CRL of pki revoking serials, with extra extensions.
func (p *crlPKI) crlDER(number int64, extra []pkix.Extension, serials ...*big.Int) []byte {
	p.t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries, ExtraExtensions: extra,
	}, p.ca, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// Every CRL of an issuer counts: an older one left before a newer one
// does not hide a revocation.
func TestClientCRLSeveralFromOneIssuer(t *testing.T) {
	pki := newCRLPKI(t)
	serial := big.NewInt(42)
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "leaf"}}
	chain := [][]*x509.Certificate{{leaf, pki.ca}}
	for name, data := range map[string][]byte{
		"old then new": append(pki.crlDER(1, nil), pki.crlDER(2, nil, serial)...),
		"new then old": append(pki.crlDER(2, nil, serial), pki.crlDER(1, nil)...),
	} {
		set, err := parseCRLs(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.check(chain); !errors.Is(err, errRevoked) {
			t.Errorf("%s: err = %v, want revoked", name, err)
		}
	}
}

// CRLs whose scope Go does not apply are refused rather than taken as
// complete.
func TestClientCRLUnsupportedExtensions(t *testing.T) {
	pki := newCRLPKI(t)
	idp, _ := asn1.Marshal(struct {
		OnlyCA bool `asn1:"optional,tag:2"`
	}{OnlyCA: true})
	delta, _ := asn1.Marshal(big.NewInt(1))
	for name, ext := range map[string]pkix.Extension{
		"delta CRL":                  {Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: delta},
		"issuing distribution point": {Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: idp},
		"unknown critical extension": {Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}},
	} {
		if _, err := parseCRLs(pki.crlDER(1, []pkix.Extension{ext})); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A non-critical unknown extension is fine.
	if _, err := parseCRLs(pki.crlDER(1, []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Value: []byte{5, 0}}})); err != nil {
		t.Errorf("non-critical extension: %v", err)
	}
}
