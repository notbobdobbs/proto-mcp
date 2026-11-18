package httpconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuthDay is one local calendar day's HTTP auth-failure count.
// A different day, a missing file, or a file that does not parse is
// a zero count: the day has rolled over, or there is nothing to read.
type AuthDay struct {
	Day            string `json:"day"`
	Failures       int    `json:"failures"`
	AutoDisabled   bool   `json:"auto_disabled"`
	AutoDisabledAt string `json:"auto_disabled_at,omitempty"`
	// Warned is set the first time today's count reaches the warn
	// threshold. A restart sees it and does not post the warning again.
	Warned   bool      `json:"warned,omitempty"`
	WarnedAt string    `json:"warned_at,omitempty"`
	Trace    AuthTrace `json:"trace,omitempty"`
	// ClearedUnixNano is set by `protonmcp http enable`. A hand-edit
	// of http.yaml does not set it. The daemon uses it to tell an
	// enable apart from a reload after a failed disable write.
	ClearedUnixNano int64 `json:"cleared_unix_nano,omitempty"`
}

// AuthStatePath is the counter file next to http.yaml.
func AuthStatePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "http-auth.json")
}

var authMu sync.Mutex

// ReadAuthDay returns today's count. Yesterday's file is not today's
// count, and it is not today's auto-disable event.
func ReadAuthDay(path string, now time.Time) AuthDay {
	authMu.Lock()
	defer authMu.Unlock()
	return readAuthDay(path, now)
}

// AddAuthFailure adds one failure for now's local day and returns the
// updated day. A day change starts the count at 1.
func AddAuthFailure(path string, now time.Time) (AuthDay, error) {
	return AddAuthFailureEvent(path, now, AuthEvent{})
}

// AddAuthFailureEvent counts one sign-in failure and stores ev.
// An empty Reason still counts, without a trace row.
func AddAuthFailureEvent(path string, now time.Time, ev AuthEvent) (AuthDay, error) {
	authMu.Lock()
	defer authMu.Unlock()
	rec := readAuthDay(path, now)
	rec.Day = dayKey(now)
	rec.Failures++
	if ev.Reason != "" {
		if ev.At.IsZero() {
			ev.At = now
		}
		rec.Trace.Add(ev)
	}
	if err := writeAuthDay(path, rec); err != nil {
		return AuthDay{}, err
	}
	return rec, nil
}

// AddAuthEvent stores a rejection that is not a counted sign-in
// failure, such as a bad Origin or a per-minute lockout.
func AddAuthEvent(path string, now time.Time, ev AuthEvent) error {
	authMu.Lock()
	defer authMu.Unlock()
	rec := readAuthDay(path, now)
	rec.Day = dayKey(now)
	if ev.At.IsZero() {
		ev.At = now
	}
	rec.Trace.Add(ev)
	return writeAuthDay(path, rec)
}

// MarkWarned records that today's warning was posted. The failure
// count is left as it is.
func MarkWarned(path string, now time.Time) error {
	authMu.Lock()
	defer authMu.Unlock()
	rec := readAuthDay(path, now)
	rec.Day = dayKey(now)
	rec.Warned = true
	rec.WarnedAt = now.Format(time.RFC3339)
	return writeAuthDay(path, rec)
}

// MarkAutoDisabled records that today tripped the threshold. The
// failure count is left as it is.
func MarkAutoDisabled(path string, now time.Time) error {
	authMu.Lock()
	defer authMu.Unlock()
	rec := readAuthDay(path, now)
	rec.Day = dayKey(now)
	rec.AutoDisabled = true
	rec.AutoDisabledAt = now.Format(time.RFC3339)
	return writeAuthDay(path, rec)
}

// ResetAuthFailures is what `protonmcp http enable` calls. It zeros
// today's count and clears the auto-disable block. A new local day
// zeros the count by itself, but it does not clear the block.
func ResetAuthFailures(path string, now time.Time) error {
	authMu.Lock()
	defer authMu.Unlock()
	rec := readAuthDay(path, now)
	rec.Day = dayKey(now)
	rec.Failures = 0
	rec.AutoDisabled = false
	rec.AutoDisabledAt = ""
	rec.Warned = false
	rec.WarnedAt = ""
	rec.Trace = AuthTrace{}
	rec.ClearedUnixNano = now.UnixNano()
	return writeAuthDay(path, rec)
}

func readAuthDay(path string, now time.Time) AuthDay {
	today := dayKey(now)
	data, err := os.ReadFile(path)
	if err != nil {
		return AuthDay{Day: today}
	}
	var rec AuthDay
	if err := json.Unmarshal(data, &rec); err != nil {
		return AuthDay{Day: today}
	}
	if rec.Day != today {
		// The failure count and the once-a-day warning are per local
		// day. The auto-disable block stays until http enable clears it.
		rec.Day = today
		rec.Failures = 0
		rec.Warned = false
		rec.WarnedAt = ""
		rec.Trace = AuthTrace{}
	}
	return rec
}

func writeAuthDay(path string, rec AuthDay) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(path, data)
}

func dayKey(t time.Time) string {
	return t.Format("2006-01-02")
}
