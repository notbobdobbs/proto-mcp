package httpmcp

import (
	"context"
	"encoding/json"
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
func (s *Service) recordAuthFailure(ctx context.Context, now time.Time, ev httpconfig.AuthEvent) {
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
	ev.At = now
	rec, err := httpconfig.AddAuthFailureEvent(httpconfig.AuthStatePath(s.Path), now, ev)
	if err != nil {
		slog.Warn("remote door auth-failure counter could not be saved", "err", SafeError(err))
	} else if rec.Failures > n {
		// The file was ahead of this process, usually because an
		// earlier process recorded failures and then exited.
		n = rec.Failures
		s.memFails = rec.Failures
	}
	limit := s.autoDisableLimit()
	warnAt := s.warnAfter()
	s.mu.Lock()
	enabled := s.cfg.Enabled
	label := s.cfg.CallerLabel
	s.mu.Unlock()
	if !enabled {
		return
	}
	if err != nil || n >= limit {
		s.disableLocked(ctx, now, label, n, err != nil)
		return
	}
	if limit > warnAt && n >= warnAt && !rec.Warned {
		if merr := httpconfig.MarkWarned(httpconfig.AuthStatePath(s.Path), now); merr != nil {
			slog.Warn("remote door auth warning could not be saved", "err", SafeError(merr))
			return
		}
		rec.Warned = true
		s.postAuthNotice(rec, false)
		s.writeAuthAudit(ctx, label, "http_auth_warn", rec, "warned after repeated remote sign-in failures", audit.OutcomeOK, "allow")
	}
}

// noteAuthEvent records a rejection that does not count as a sign-in
// failure. A write error does not change the door.
func (s *Service) noteAuthEvent(now time.Time, ev httpconfig.AuthEvent) {
	if s == nil || s.Path == "" || ev.Reason == "" {
		return
	}
	ev.At = now
	if err := httpconfig.AddAuthEvent(httpconfig.AuthStatePath(s.Path), now, ev); err != nil {
		slog.Warn("remote door auth-failure detail could not be saved", "err", SafeError(err))
	}
}

// bumpAuthFailures adds one failure for now's local day. A new day
// starts from the count already stored for that day, so a restarted
// process does not begin again at zero. Caller holds failMu.
func (s *Service) bumpAuthFailures(now time.Time) int {
	s.adoptStoredCount(now)
	s.memFails++
	return s.memFails
}

// adoptStoredCount loads today's stored count when this process has
// not counted that day yet, and otherwise keeps the larger of the
// two. Caller holds failMu.
func (s *Service) adoptStoredCount(now time.Time) {
	day := now.Format("2006-01-02")
	stored := 0
	if s.Path != "" {
		stored = httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), now).Failures
	}
	if s.memDay != day {
		s.memDay = day
		s.memFails = stored
		return
	}
	if stored > s.memFails {
		s.memFails = stored
	}
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
	}
	if !s.blocked {
		s.adoptStoredCount(now)
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

	fresh := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), now)
	if fresh.Failures == 0 {
		fresh.Failures = failures
	}
	msg := "remote door disabled after repeated auth failures"
	if writeFailed && failures < s.autoDisableLimit() {
		msg = "remote door disabled because the auth-failure counter could not be saved"
	}
	s.writeAuthAudit(ctx, label, "http_auto_disable", fresh, msg, audit.OutcomeDenied, "deny")
	if writeFailed && failures < s.autoDisableLimit() {
		s.postPlainNotice("Remote access was turned off because the sign-in failure counter could not be saved. Turn it back on with protonmcp http enable.")
		return
	}
	s.postAuthNotice(fresh, true)
}

func (s *Service) warnAfter() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.WarnAfterAuthFailures <= 0 {
		return httpconfig.DefaultWarnAfterAuthFailures
	}
	return s.cfg.WarnAfterAuthFailures
}

func (s *Service) autoDisableLimit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.AutoDisableAfterAuthFailures <= 0 {
		return httpconfig.DefaultAutoDisableAfterAuthFailures
	}
	return s.cfg.AutoDisableAfterAuthFailures
}

func (s *Service) writeAuthAudit(ctx context.Context, label, tool string, rec httpconfig.AuthDay, msg, outcome, decision string) {
	if s.Audit == nil {
		return
	}
	if label == "" {
		label = "remote"
	}
	raw, err := json.Marshal(struct {
		Failures int                  `json:"failures"`
		Trace    httpconfig.AuthTrace `json:"trace"`
	}{rec.Failures, rec.Trace})
	if err != nil {
		return
	}
	raw = httpconfig.ScrubAuthJSON(raw)
	id := s.Audit.Begin(ctx, &audit.Entry{
		Caller: caller.Caller{
			Transport: caller.TransportHTTP,
			Label:     label,
			UID:       os.Getuid(),
		},
		Tool:           tool,
		ArgsJSON:       raw,
		PolicyDecision: decision,
	})
	if id == 0 {
		return
	}
	s.Audit.Complete(ctx, id, outcome, "policy", msg, 0)
}

func (s *Service) postAuthNotice(rec httpconfig.AuthDay, disabled bool) {
	s.postPlainNotice(httpconfig.ShortAuthNotice(rec, disabled))
}

func (s *Service) postPlainNotice(text string) {
	fn := s.Notify
	if fn == nil {
		fn = OSNotify
	}
	_ = fn(text)
}
