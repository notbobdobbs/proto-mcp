package serve

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

func TestSighupReReadsHTTPWhenPolicyReloadFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("{{ broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	eng, err := policy.New(t.Context(), path, logger)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	handleSighup(eng, nil, logger, func() { calls++ })
	if calls != 1 {
		t.Fatalf("http reload calls = %d, want 1", calls)
	}
	if d, _ := eng.Decide("mail_read", nil, policy.Caller{}); d == "" {
		t.Fatal("policy decision was cleared")
	}
}
