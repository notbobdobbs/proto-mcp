package httpmcp

import (
	"fmt"
	"net"
	"strconv"
)

// Listen is the only TCP listen in the process. It accepts exactly
// 127.0.0.1 or ::1 with an explicit non-zero port. Other 127/8
// addresses, IPv4-mapped IPv6, localhost, and port 0 are refused.
func Listen(addr string) (net.Listener, error) {
	if err := ValidateAddr(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

// ValidateAddr reports whether addr is exactly 127.0.0.1 or ::1 and a
// port from 1 to 65535. It does not listen. It does not treat every
// loopback IP as acceptable.
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || host == "" {
		return fmt.Errorf("httpmcp: refusing listen address %q", addr)
	}
	if host != "127.0.0.1" && host != "::1" {
		return fmt.Errorf("httpmcp: refusing listen address %q", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("httpmcp: refusing listen port %q", port)
	}
	return nil
}

// LoopbackRemote reports whether a connection's RemoteAddr is exactly
// 127.0.0.1 or ::1. X-Forwarded-For is not consulted. 127.0.0.2 and
// ::ffff:127.0.0.1 are not accepted.
func LoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return host == "127.0.0.1" || host == "::1"
}
