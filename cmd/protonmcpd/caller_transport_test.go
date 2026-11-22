package main

import (
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

func TestStampSocketCallerSetsUnixTransport(t *testing.T) {
	peer := caller.Caller{PID: 42, UID: 501, Binary: "/synthetic/client"}
	got := stampSocketCaller(peer)
	if got.Transport != caller.TransportUnix {
		t.Fatalf("transport = %q, want %q", got.Transport, caller.TransportUnix)
	}
	if got.PID != 42 || got.UID != 501 || got.Binary != "/synthetic/client" {
		t.Fatalf("peer identity changed: %+v", got)
	}
	if peer.Transport != "" {
		t.Fatal("stampSocketCaller mutated its input")
	}
}
