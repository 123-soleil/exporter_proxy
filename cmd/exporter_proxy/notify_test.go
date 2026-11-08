package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSdNotify(t *testing.T) {
	// Without NOTIFY_SOCKET: nothing to do.
	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotify(notifyReady); err != nil {
		t.Errorf("without NOTIFY_SOCKET: %v", err)
	}

	dir, err := os.MkdirTemp("", "sdn") // short path: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := sdNotify(notifyReady); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != notifyReady {
		t.Errorf("systemd got %q, want %q", got, notifyReady)
	}

	t.Setenv("NOTIFY_SOCKET", filepath.Join(dir, "missing"))
	if err := sdNotify(notifyReady); err == nil {
		t.Error("no error for a missing socket")
	}
}
