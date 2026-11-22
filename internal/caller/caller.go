// Package caller resolves the identity of the process that spawned
// this binary. Phase 4 needs this for the audit log's
// caller_pid / caller_uid / caller_binary columns and for the policy
// engine's per-caller decisioning (Phase 5 may want "only Claude
// Desktop can call mail_send", for example).
//
// On macOS we resolve the binary path via libproc's proc_pidpath.
// The Resolve() call is cached for the life of the process because
// our parent PID can't legitimately change after startup — if it
// does, that's because our parent died and we got reparented to
// launchd, which is a session we should refuse to honor anyway.
// (Phase 6's daemon will reconsider this.)
package caller

import (
	"fmt"
	"os"
	"sync"
)

// Transport values recorded on a Caller. The Unix socket and the
// loopback HTTP door are different callers even when the numeric
// ids match. The HTTP listener itself is a later change; this
// package only names the door.
const (
	TransportUnix = "unix"
	TransportHTTP = "http"
)

// Caller is the resolved identity of whoever invoked a tool.
//
// Transport and Label are part of that identity. A socket peer
// keeps its PID, UID, and binary, with Transport "unix". An HTTP
// caller has no peer process (PID 0) and a configured Label; the
// approval dialog shows that as "http:<label>".
type Caller struct {
	PID       int
	UID       int
	Binary    string // absolute path, empty if resolution failed
	Transport string // TransportUnix, TransportHTTP, or empty for serve-stdio
	Label     string // configured name of an HTTP caller; empty on the socket
}

// String formats for log / audit display and for the Touch ID
// helper's "Requested by" line.
//
// HTTP returns "http:<label>" so the dialog names the remote door
// instead of a binary path the caller could claim. Socket and
// stdio callers stay "Claude (pid 1234)", or "pid 1234" when the
// binary could not be resolved.
func (c Caller) String() string {
	if c.Transport == TransportHTTP {
		return "http:" + c.Label
	}
	if c.Binary == "" {
		return fmt.Sprintf("pid %d", c.PID)
	}
	return fmt.Sprintf("%s (pid %d)", basenameOf(c.Binary), c.PID)
}

// Resolver caches a single Caller for the life of the process.
// Construct via New; call Resolve() on every tool-call to get the
// cached value at O(1) cost.
type Resolver struct {
	once   sync.Once
	cached Caller
}

// New returns a fresh Resolver. The actual resolution happens lazily
// on the first Resolve() call so package init doesn't make syscalls.
func New() *Resolver {
	return &Resolver{}
}

// BinaryFor returns the absolute path of the binary running with the
// given PID, or "" if it can't be determined (PID gone, EPERM, non-
// macOS platform). Exported so internal/policy.FindRunningPIDs can
// filter pgrep matches by actual executable path — see D33/D34 fix.
//
// Empty-string return is intentional and non-fatal; callers treat
// it as "can't verify, skip."
func BinaryFor(pid int) string {
	bin, _ := resolveBinary(pid)
	return bin
}

// Resolve returns the cached Caller, computing it on first call.
// Never returns an error — partial resolution (PID only, no binary)
// is acceptable; consumers handle empty Binary as "unknown."
func (r *Resolver) Resolve() Caller {
	r.once.Do(func() {
		pid := os.Getppid()
		uid := os.Getuid()
		bin, _ := resolveBinary(pid) // platform-specific; nil error tolerated
		r.cached = Caller{PID: pid, UID: uid, Binary: bin}
	})
	return r.cached
}

// basenameOf returns the last path element of p, stripping any
// trailing slash. Used for display only — not for security
// decisions; an attacker who controls argv[0] could forge this.
func basenameOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
