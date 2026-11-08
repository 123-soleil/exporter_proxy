package server

import (
	"encoding/json"
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

// sdHandler serves the routes of the configuration as Prometheus HTTP
// service discovery targets: one per route, at the address and with the
// scheme its listener actually serves.
type sdHandler struct {
	s    *Server
	cfg  *config.Config
	next http.Handler // the metrics endpoint
}

func (h *sdHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != SDPath {
		h.next.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	body, err := json.Marshal(h.targets())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// targets lists the routes of the listeners serving now. Listeners on a
// Unix socket are left out: Prometheus scrapes over TCP.
func (h *sdHandler) targets() []sdTargetGroup {
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
