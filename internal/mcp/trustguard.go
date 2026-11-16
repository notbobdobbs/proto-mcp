package mcp

import (
	"errors"
	"net"
)

// init installs a "no TCP listen except the loopback door" invariant
// per SECURITY Foundational #3. The stdio transport and the daemon's
// Unix socket are the local doors. The only TCP listen in the repo is
// httpmcp.Listen, which binds a literal loopback address and refuses
// anything else. Any other net.Listen("tcp") is still forbidden.
//
// Implementation: monkey-patching net.Listen would require unsafe
// tricks Go won't let us do. Instead, this file exposes a small
// MustNotListenTCP helper that future transport code can call as a
// no-op assertion, AND a build-tag-driven test that greps the
// codebase for forbidden patterns. The point is to make it loud
// rather than silent if anyone ever tries.
//
// For now (no transport code outside stdio), this is documentation
// + a sentinel error that future code paths can reference.

// ErrTCPForbidden is returned if any future transport tries to bind
// a TCP listener. Code that opens a new transport SHOULD call
// MustNotListenTCP at the top to make this explicit.
var ErrTCPForbidden = errors.New("mcp: TCP transport forbidden — SECURITY Foundational #3 (stdio + Unix-domain only)")

// MustNotListenTCP panics if called. Use as a sentinel in any
// future code path that handles a network address — the panic is the
// invariant guard.
//
//nolint:unused // sentinel exported for future transport code
func MustNotListenTCP(network, address string) {
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		panic(ErrTCPForbidden.Error() + ": tried to listen on " + address)
	}
}

// _ guarantees the net package is part of the import graph so a
// future "remove unused imports" pass doesn't drop it before
// MustNotListenTCP grows real callers.
var _ = net.Listen
