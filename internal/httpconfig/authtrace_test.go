package httpconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestAuthTraceBoundsAndScrub(t *testing.T) {
	token := strings.Repeat("ab", 32)
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	var tr AuthTrace
	start := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	longPath := "POST /" + strings.Repeat("p", 200) + "/" + token
	for i := 0; i < traceSampleMax+5; i++ {
		tr.Add(AuthEvent{
			Reason:  ReasonWrongToken,
			Source:  "remote 10.0.0." + strings.Repeat("1", i%3),
			Agent:   "agent-" + string(rune('a'+i%12)) + " " + token + "\x00\x01",
			Request: longPath,
			At:      start.Add(time.Duration(i) * time.Second),
		})
	}
	if len(tr.Sample) != traceSampleMax {
		t.Fatalf("sample = %d, want %d", len(tr.Sample), traceSampleMax)
	}
	if len(tr.Agents) > traceMapMax+1 {
		t.Fatalf("agents = %d", len(tr.Agents))
	}
	if tr.Agents["other"] == 0 {
		t.Fatal("distinct agents were not capped")
	}
	if tr.PeakPerMinute < traceSampleMax {
		t.Fatalf("peak = %d", tr.PeakPerMinute)
	}
	blob := FormatAuthDebug(AuthDay{Failures: len(tr.Sample), Trace: tr})
	notice := ShortAuthNotice(AuthDay{Failures: 500, Trace: tr}, false)
	if strings.Contains(blob, token) || strings.Contains(blob, token[:8]) || strings.Contains(blob, hash) || strings.Contains(strings.ToLower(blob), "bearer") {
		t.Fatal("debug output kept token material")
	}
	if strings.Contains(notice, token) || !strings.Contains(notice, "still on") || !strings.Contains(notice, "http status --debug") || !strings.Contains(notice, "wrong token") {
		t.Fatalf("notice = %s", notice)
	}
	if strings.Contains(blob, "\x00") || len(tr.Sample[0].Request) > traceStrMax {
		t.Fatalf("sample request = %q", tr.Sample[0].Request)
	}
	if !strings.Contains(blob, "first:") || !strings.Contains(blob, "last:") || !strings.Contains(blob, "\n") {
		t.Fatalf("debug = %s", blob)
	}

	// A later minute past the cap still raises the peak.
	var many AuthTrace
	for i := 0; i < traceMinuteMax+3; i++ {
		many.Add(AuthEvent{Reason: ReasonBadScheme, At: start.Add(time.Duration(i) * time.Minute)})
	}
	many.Add(AuthEvent{Reason: ReasonBadScheme, At: start.Add(time.Duration(traceMinuteMax+2) * time.Minute)})
	if many.PeakPerMinute < 2 {
		t.Fatalf("overflow peak = %d", many.PeakPerMinute)
	}
	if len(many.Minutes) > traceMinuteMax+1 {
		t.Fatalf("minutes = %d", len(many.Minutes))
	}
}

func TestClientSourceLabelsForwardedAndRemote(t *testing.T) {
	token := strings.Repeat("12", 32)
	if got := ForwardedIP(token, "203.0.113.4, 10.0.0.1"); got != "203.0.113.4" {
		t.Fatalf("forwarded = %s", got)
	}
	if got := ForwardedIP("100.64.1.8", token); got != "100.64.1.8" {
		t.Fatalf("tailscale = %s", got)
	}
	if got := ClientSource(ForwardedIP("100.64.1.8", ""), "192.0.2.1:9"); got != "forwarded 100.64.1.8" {
		t.Fatalf("source = %s", got)
	}
	if got := ClientSource(ForwardedIP(token, "not-an-ip"), "[::1]:9"); got != "remote ::1" {
		t.Fatalf("remote = %s", got)
	}
}

func TestScrubAuthJSONKeepsTimestamps(t *testing.T) {
	token := strings.Repeat("ab", 32)
	raw := []byte(`{"failures":2,"trace":{"first_unix":1763500000,"agents":{"bot ` + token + `":1}}}`)
	out := string(ScrubAuthJSON(raw))
	if !strings.Contains(out, "1763500000") || !strings.Contains(out, `"failures":2`) {
		t.Fatalf("numbers were damaged: %s", out)
	}
	if strings.Contains(out, token) || strings.Contains(out, token[:8]) {
		t.Fatalf("token survived JSON scrub: %s", out)
	}
}
