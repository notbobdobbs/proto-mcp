package httpmcp

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
)

// recordAuthFailure counts one failed HTTP authentication for the
// local day. At the configured threshold it writes enabled:false,
// closes the listener, drops sessions, writes an audit row, and
// posts a notification. A notification error does not turn the door
// back on. The door does not re-enable itself.
func (s *Service) recordAuthFailure(ctx context.Context, now time.Time) {
	if s == nil || s.Path == "" {
		return
	}
	s.failMu.Lock()
	defer s.failMu.Unlock()

	limit := s.autoDisableLimit()
	rec, err := httpconfig.AddAuthFailure(httpconfig.AuthStatePath(s.Path), now)
	if err != nil {
		return
	}
	s.mu.Lock()
	enabled := s.cfg.Enabled
	label := s.cfg.CallerLabel
	s.mu.Unlock()
	if !enabled || rec.Failures < limit {
		return
	}
	if err := httpconfig.SetEnabled(s.Path, false); err != nil {
		_ = httpconfig.WriteDisabled(s.Path)
	}
	_ = httpconfig.MarkAutoDisabled(httpconfig.AuthStatePath(s.Path), now)

	s.mu.Lock()
	s.cfg.Enabled = false
	s.sessions = map[string]*hsess{}
	s.haveFP = false
	s.stopLocked()
	st, doorPath := s.snapshotLocked()
	s.mu.Unlock()
	writeDoor(doorPath, st)

	s.writeAutoDisableAudit(ctx, label, rec.Failures)
	s.postAutoDisableNotice(rec.Failures)
}

func (s *Service) autoDisableLimit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.AutoDisableAfterAuthFailures <= 0 {
		return httpconfig.DefaultAutoDisableAfterAuthFailures
	}
	return s.cfg.AutoDisableAfterAuthFailures
}

func (s *Service) writeAutoDisableAudit(ctx context.Context, label string, failures int) {
	if s.Audit == nil {
		return
	}
	if label == "" {
		label = "remote"
	}
	id := s.Audit.Begin(ctx, &audit.Entry{
		Caller: caller.Caller{
			Transport: caller.TransportHTTP,
			Label:     label,
			UID:       os.Getuid(),
		},
		Tool:           "http_auto_disable",
		ArgsJSON:       []byte(fmt.Sprintf(`{"failures":%d}`, failures)),
		PolicyDecision: "deny",
	})
	if id == 0 {
		return
	}
	s.Audit.Complete(ctx, id, audit.OutcomeDenied, "policy", "remote door disabled after repeated auth failures", 0)
}

func (s *Service) postAutoDisableNotice(failures int) {
	text := fmt.Sprintf("Remote access was turned off after %d failed sign-ins today. Turn it back on with protonmcp http enable.", failures)
	fn := s.Notify
	if fn == nil {
		fn = OSNotify
	}
	_ = fn(text)
}
