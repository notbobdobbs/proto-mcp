package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpmcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/serve"
)

// startHTTPDoor wires the loopback HTTP door onto the running runtime.
// A missing or disabled http.yaml, or a missing token, leaves no TCP
// listener. SIGHUP re-reads the file. This does not open a public port.
func startHTTPDoor(ctx context.Context, rt *serve.Runtime) *httpmcp.Service {
	path := ""
	if dir, err := appSupportDir(); err == nil {
		path = filepath.Join(dir, "http.yaml")
	}
	svc := httpmcp.New(rt.MCPServer, path, keystore.LoadHTTPToken)
	svc.Clock = httpmcp.NewUnlockClock(nil)
	svc.Reads = httpmcp.NewReadCap(rt.Store.DB, nil, svc.MaxReads)
	rt.MCPServer.UseRemoteAllow(svc.Allows)
	if svc.Reads != nil {
		rt.MCPServer.UseReadCap(svc.Reads.Take)
	}
	rt.MCPServer.UseTrashGuard(func(ctx context.Context, args json.RawMessage) error {
		return httpmcp.TrashRefused(ctx, rt.Store, args)
	})
	rt.MCPServer.UseHTTPUnlock(func(ctx context.Context) error {
		return svc.Clock.Gate(ctx, svc.UnlockHours(), func(ctx context.Context) error {
			_, err := rt.Broker.Request(ctx, approval.Request{
				Tool: "http_unlock",
				Caller: caller.Caller{
					Transport: caller.TransportHTTP,
					Label:     svc.Label(),
					PID:       0,
					UID:       os.Getuid(),
				},
				Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt, TTL: "0", Confirm: true},
				Title:  "Approve remote access?",
				Body:   "The remote door asks for Touch ID because the 8-hour unlock expired. This does not approve sending mail.",
			})
			return err
		})
	})
	rt.SetOnUnlockStamp(func() {
		svc.Clock.Stamp(time.Now())
		svc.Publish()
	})
	rt.SetOnReload(func() {
		if err := svc.Reload(); err != nil {
			slog.Warn("remote door reload failed", "err", httpmcp.SafeError(err))
		}
	})
	svc.Clock.Stamp(time.Now())
	if err := svc.Reload(); err != nil {
		slog.Warn("remote door reload failed", "err", httpmcp.SafeError(err))
	}
	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		_ = httpmcp.DailyNotice(rt.Store.DB, time.Now(), httpmcp.OSNotify)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = httpmcp.DailyNotice(rt.Store.DB, time.Now(), httpmcp.OSNotify)
			}
		}
	}()
	return svc
}

func appSupportDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp"), nil
}
