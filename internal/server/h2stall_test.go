package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// An HTTP/2 client that stops reading the socket in the middle of a large
// answer does not hold the read's slot for as long as its connection stays
// open: the stalled connection is closed and the slot comes back.
func TestHTTP2StalledClientReleasesItsSlot(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the HTTP/2 write timeout")
	}
	var body bytes.Buffer
	body.WriteString("# TYPE x gauge\n")
	for i := 0; body.Len() < 4<<20; i++ {
		fmt.Fprintf(&body, "x{id=\"%d\",pad=\"%040d\"} %d\n", i, i, i)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body.Bytes()) }))
	defer up.Close()
	dir := t.TempDir()
	cert, key := testTLSFiles(t, dir)
	writeWeb(t, dir, "web.yml", fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\nhttp_server_config:\n  http2: true\n", cert, key))
	l := withAddr(t, listenerConfig("node", filepath.Join(dir, "web.yml"), up.URL))
	l.MaxConcurrentRequests = 1
	l.Routes[0].Limits = config.Limits{Timeout: 30 * time.Second, MaxBodyBytes: 64 << 20, MaxSamples: 10_000_000}
	s, err := Start(&config.Config{Listeners: []config.Listener{l}}, Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(t.Context()) })
	addr := s.Addr("node").String()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // test server
	if err := c.Handshake(); err != nil || c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("no HTTP/2 connection: %v", err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, http2.ClientPreface)
	fr := http2.NewFramer(c, c)
	_ = fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30})
	_ = fr.WriteWindowUpdate(0, 1<<30-65535)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "x"}, {":path", "/metrics"}} {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	start := time.Now()
	_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true})
	// Read until the answer's headers: the source read is over and the
	// answer is being written, holding the slot. From then on, never read
	// the socket.
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("waiting for the answer's headers: %v", err)
		}
		if h, ok := f.(*http2.HeadersFrame); ok && h.StreamID == 1 {
			break
		}
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		DisableKeepAlives: true, DisableCompression: true,
	}}
	refused := false
	for {
		if resp, err := client.Get("https://" + addr + "/metrics"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusServiceUnavailable:
				refused = true // the stalled answer holds the slot
			case http.StatusOK:
				if !refused {
					t.Fatal("the stalled answer did not hold the slot: the test proves nothing")
				}
				t.Logf("slot free after %s", time.Since(start).Round(time.Second))
				return
			}
		}
		if time.Since(start) > 35*time.Second {
			t.Fatal("slot still held by a stalled HTTP/2 client after 35s")
		}
		time.Sleep(250 * time.Millisecond)
	}
}
