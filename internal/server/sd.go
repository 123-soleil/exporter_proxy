package server

import (
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// SDPath is where the metrics endpoint serves the Prometheus HTTP service
// discovery targets, when service_discovery is configured.
const SDPath = "/sd"

// sdTargetGroup is one entry of the Prometheus HTTP service discovery
// format.
type sdTargetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// Health endpoints of the metrics endpoint, like Prometheus'.
const (
	HealthyPath = "/-/healthy"
	ReadyPath   = "/-/ready"
)

// metricsEndpoint serves the metrics endpoint: the metrics, the health
// endpoints, and the Prometheus HTTP service discovery targets when
// configured (one per route, at the address and with the scheme its
// listener actually serves).
type metricsEndpoint struct {
	s    *Server
	cfg  *config.Config
	next http.Handler // the metrics
}

func (h *metricsEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case HealthyPath, ReadyPath, SDPath:
	default:
		h.next.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case HealthyPath:
		// Serving at all is healthy.
		_, _ = io.WriteString(w, "exporter_proxy is healthy.\n")
		return
	case ReadyPath:
		if !h.s.ready.Load() {
			http.Error(w, "exporter_proxy is not ready.", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "exporter_proxy is ready.\n")
		return
	}
	if h.cfg.Metrics.ServiceDiscovery == nil {
		http.NotFound(w, r)
		return
	}
	body, err := json.Marshal(h.targets())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// targets lists the routes of the listeners serving now. Listeners on a
// Unix socket are left out: Prometheus scrapes over TCP.
func (h *metricsEndpoint) targets() []sdTargetGroup {
	sd := h.cfg.Metrics.ServiceDiscovery
	groups := []sdTargetGroup{}
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	for _, l := range h.cfg.Listeners {
		cur := h.s.listeners[l.Name]
		if cur == nil {
			continue
		}
		ap, err := netip.ParseAddrPort(cur.ln.Addr().String())
		if err != nil {
			continue // Unix socket
		}
		target := net.JoinHostPort(sd.Host, strconv.Itoa(int(ap.Port())))
		scheme := "http"
		if cur.settings.tls {
			scheme = "https"
		}
		for _, r := range l.Routes {
			labels := maps.Clone(sd.Labels)
			if labels == nil {
				labels = map[string]string{}
			}
			labels["__metrics_path__"] = r.Path
			labels["__scheme__"] = scheme
			labels["exporter_proxy_listener"] = l.Name
			labels["exporter_proxy_route"] = r.Path
			groups = append(groups, sdTargetGroup{Targets: []string{target}, Labels: labels})
		}
	}
	return groups
}
