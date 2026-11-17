package httpmcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
)

// recordAuthFailure counts one failed sign-in in memory and, when it
// can, in the counter file. The memory count still reaches the
// threshold when the file cannot be written. A file write error also
// disables the door immediately. The door stays off until
// `protonmcp http enable` clears that state.
func (s *Service) recordAuthFailure(ctx context.Context, now time.Time) {
	if s == nil || s.Path == "" {
		return
	}
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if s.blocked {
		s.bumpAuthFailures(now)
		return
	}

	n := s.bumpAuthFailures(now)
	_, err := httpconfig.AddAuthFailure(httpconfig.AuthStatePath(s.Path), now)
	if err != nil {
		slog.Warn("remote door auth-failure counter could not be saved", "err", SafeError(err))
	}
	limit := s.autoDisableLimit()
	s.mu.Lock()
	enabled := s.cfg.Enabled
	label := s.cfg.CallerLabel
	s.mu.Unlock()
	if !enabled {
		return
	}
	if err != nil || n >= limit {
		s.disableLocked(ctx, now, label, n, err != nil)
	}
}

// bumpAuthFailures adds one failure for now's local day. The count
// lives in the process, so a counter-file write error does not drop it.
// Caller holds failMu.
func (s *Service) bumpAuthFailures(now time.Time) int {
	day := now.Format("2006-01-02")
	if s.memDay != day {
		s.memDay = day
		s.memFails = 0
	}
	s.memFails++
	return s.memFails
}

// autoDisableBlocks reports whether Reload must leave the listener
// closed. A persisted auto-disable blocks even after a restart. An
// in-memory block stays when both disable writes failed, until http
// enable records a newer clear stamp.
func (s *Service) autoDisableBlocks(now time.Time) bool {
	if s == nil || s.Path == "" {
		return false
	}
	st := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), now)
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if st.AutoDisabled {
		if !s.blocked {
			s.blocked = true
			s.blockedAt = now.UnixNano()
		}
		return true
	}
	if s.blocked && st.ClearedUnixNano > s.blockedAt {
		s.blocked = false
		s.memFails = 0
		s.memDay = ""
		return false
	}
	return s.blocked
}

// disableLocked closes the door. Caller holds failMu.
func (s *Service) disableLocked(ctx context.Context, now time.Time, label string, failures int, writeFailed bool) {
	s.blocked = true
	s.blockedAt = now.UnixNano()
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

	s.writeAutoDisableAudit(ctx, label, failures, writeFailed)
	s.postAutoDisableNotice(failures, writeFailed)
}

func (s *Service) autoDisableLimit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.AutoDisableAfterAuthFailures <= 0 {
		return httpconfig.DefaultAutoDisableAfterAuthFailures
	}
	return s.cfg.AutoDisableAfterAuthFailures
}

func (s *Service) writeAutoDisableAudit(ctx context.Context, label string, failures int, writeFailed bool) {
	if s.Audit == nil {
		return
	}
	if label == "" {
		label = "remote"
	}
	args := fmt.Sprintf(`{"failures":%d}`, failures)
	msg := "remote door disabled after repeated auth failures"
	if writeFailed {
		args = fmt.Sprintf(`{"failures":%d,"counter":"unsaved"}`, failures)
		msg = "remote door disabled because the auth-failure counter could not be saved"
	}
	id := s.Audit.Begin(ctx, &audit.Entry{
		Caller: caller.Caller{
			Transport: caller.TransportHTTP,
			Label:     label,
			UID:       os.Getuid(),
		},
		Tool:           "http_auto_disable",
		ArgsJSON:       []byte(args),
		PolicyDecision: "deny",
	})
	if id == 0 {
		return
	}
	s.Audit.Complete(ctx, id, audit.OutcomeDenied, "policy", msg, 0)
}

func (s *Service) postAutoDisableNotice(failures int, writeFailed bool) {
	text := fmt.Sprintf("Remote access was turned off after %d failed sign-ins today. Turn it back on with protonmcp http enable.", failures)
	if writeFailed && failures < s.autoDisableLimit() {
		text = "Remote access was turned off because the sign-in failure counter could not be saved. Turn it back on with protonmcp http enable."
	}
	fn := s.Notify
	if fn == nil {
		fn = OSNotify
	}
	_ = fn(text)
}
