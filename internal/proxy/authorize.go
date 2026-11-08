package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
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
	sans  map[string]bool // exact names: IP addresses, email addresses, URIs
	dns   map[string]bool // lower-cased: DNS names compare without case
}

func newAuthorization(a *config.Authorize) *authorization {
	if a == nil {
		return nil
	}
	z := &authorization{users: map[string]bool{}, sans: map[string]bool{}, dns: map[string]bool{}}
	for _, u := range a.Users {
		z.users[u] = true
	}
	for _, s := range a.ClientSANs {
		z.sans[s] = true
		if dnsLike(s) {
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
		for _, san := range otherSANs(leaf) {
			if z.sans[san] {
				return true, san
			}
		}
	}
	return false, user
}

// dnsLike reports whether a client_sans entry can only be a DNS name: not
// an IP address, an email address or a URI. Only those match DNS names of
// certificates, so that a DNS name spelled like an IP address does not
// match an IP entry.
func dnsLike(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return !strings.ContainsAny(s, "@:")
}

// verified reports whether the connection has a client certificate
// verified against the client CA: with RequireAnyClientCert or
// RequestClientCert, any client can present a self-signed certificate
// carrying any name.
func verified(cs *tls.ConnectionState) bool {
	return cs != nil && len(cs.VerifiedChains) > 0 && len(cs.PeerCertificates) > 0
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
