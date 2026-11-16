package httpmcp

import (
	"fmt"
	"net"
	"strings"
)

// Listen is the only TCP listen in the process. It accepts a literal
// loopback address with an explicit port: 127.0.0.1 or ::1. It refuses
// 0.0.0.0, an empty host, a LAN address, and the name localhost.
func Listen(addr string) (net.Listener, error) {
	if err := ValidateAddr(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

// ValidateAddr reports whether addr is a literal loopback host and a port.
// It does not listen.
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || host == "" {
		return fmt.Errorf("httpmcp: refusing listen address %q", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("httpmcp: refusing hostname %q", host)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("httpmcp: refusing non-loopback listen %q", addr)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("httpmcp: refusing unspecified listen %q", addr)
	}
	return nil
}

// LoopbackRemote reports whether a connection's RemoteAddr is loopback.
// X-Forwarded-For is not consulted.
func LoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
