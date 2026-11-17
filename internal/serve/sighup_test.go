package serve

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

func TestSighupRunsHTTPReloadWhenPolicyFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.New(context.Background(), path, slog.New(slog.NewTextHandler(nopWriter{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tools: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &Runtime{}
	var n int
	rt.SetOnReload(func() { n++ })
	handleSighup(eng, nil, rt, slog.New(slog.NewTextHandler(nopWriter{}, nil)))
	if n != 1 {
		t.Fatalf("http reloads = %d, want 1 even though policy.yaml is bad", n)
	}
	if err := eng.Reload(); err == nil {
		t.Fatal("bad policy file was accepted")
	}
}
