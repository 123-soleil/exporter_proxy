package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// systemd notification states (sd_notify(3)).
const (
	notifyReady    = "READY=1"
	notifyStopping = "STOPPING=1"
)

// sdNotify sends state to systemd (Type=notify services): a datagram to the
// socket named by NOTIFY_SOCKET, a path or, starting with '@', a Linux
// abstract socket. Without NOTIFY_SOCKET (not under systemd, or another
// service type) it does nothing. Written here rather than using go-systemd's
// daemon package, which does not build on every platform the releases
// target (NetBSD).
func sdNotify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if strings.HasPrefix(addr, "vsock:") {
		return fmt.Errorf("NOTIFY_SOCKET %q: vsock is not supported", addr)
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(state))
	return err
}
