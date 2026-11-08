package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

type userKey struct{}

// WithUser returns ctx carrying the basic authentication user verified for
// the request. Only the authentication layer calls it, once the password
// is checked: a client cannot set it.
func WithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

// userOf returns the verified basic authentication user of a request.
func userOf(ctx context.Context) (string, bool) {
	u, ok := ctx.Value(userKey{}).(string)
	return u, ok
}

// authorization is the authorize block of a route.
type authorization struct {
	users map[string]bool
	// client_sans by kind: each entry only matches names of its kind in
	// the certificate (a DNS name spelled like an IP address or a URI
	// never matches an IP or URI entry, and the reverse).
	dns   map[string]bool // lower-cased: DNS names compare without case
	ips   map[netip.Addr]bool
	email map[string]bool
	uris  map[string]bool
}

// uriScheme matches an entry starting with a URI scheme (RFC 3986).
var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

func newAuthorization(a *config.Authorize) *authorization {
	if a == nil {
		return nil
	}
	z := &authorization{users: map[string]bool{}, dns: map[string]bool{}, ips: map[netip.Addr]bool{},
		email: map[string]bool{}, uris: map[string]bool{}}
	for _, u := range a.Users {
		z.users[u] = true
	}
	for _, s := range a.ClientSANs {
		if ip, err := netip.ParseAddr(s); err == nil {
			z.ips[ip.Unmap()] = true
			continue
		}
		switch {
		case uriScheme.MatchString(s):
			// Before emails: a URI may hold @ (mailto:, user@host).
			z.uris[s] = true
		case strings.Contains(s, "@"):
			z.email[s] = true
		default:
			z.dns[strings.ToLower(s)] = true
		}
	}
	return z
}

// allows reports whether the request may read the route, and who it was
// identified as (for logs): its verified basic authentication user, or a
// subject alternative name of its verified client certificate.
func (z *authorization) allows(r *http.Request) (allowed bool, who string) {
	user, hasUser := userOf(r.Context())
	if hasUser && z.users[user] {
		return true, user
	}
	if cs := r.TLS; verified(cs) {
		leaf := cs.PeerCertificates[0]
		for _, name := range leaf.DNSNames {
			if z.dns[strings.ToLower(name)] {
				return true, name
			}
		}
		for _, raw := range leaf.IPAddresses {
			if ip, ok := netip.AddrFromSlice(raw); ok && z.ips[ip.Unmap()] {
				return true, ip.Unmap().String()
			}
		}
		for _, e := range leaf.EmailAddresses {
			if z.email[e] {
				return true, e
			}
		}
		for _, u := range leaf.URIs {
			if z.uris[u.String()] {
				return true, u.String()
			}
		}
	}
	return false, user
}

// verified reports whether the connection has a client certificate
// verified against the client CA: with RequireAnyClientCert or
// RequestClientCert, any client can present a self-signed certificate
// carrying any name.
func verified(cs *tls.ConnectionState) bool {
	return cs != nil && len(cs.VerifiedChains) > 0 && len(cs.PeerCertificates) > 0
}

// certName names a verified client certificate for logs: its subject
// common name, else its first subject alternative name; empty without a
// verified certificate.
func certName(cs *tls.ConnectionState) string {
	if !verified(cs) {
		return ""
	}
	leaf := cs.PeerCertificates[0]
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	if others := otherSANs(leaf); len(others) > 0 {
		return others[0]
	}
	return ""
}

// otherSANs returns the IP address, email address and URI names of a
// certificate, compared exactly.
func otherSANs(leaf *x509.Certificate) []string {
	sans := make([]string, 0, len(leaf.EmailAddresses)+len(leaf.IPAddresses)+len(leaf.URIs))
	sans = append(sans, leaf.EmailAddresses...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range leaf.URIs {
		sans = append(sans, u.String())
	}
	return sans
}
