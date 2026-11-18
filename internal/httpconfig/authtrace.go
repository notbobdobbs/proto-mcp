package httpconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Failure reasons recorded for the daily auth-failure detail.
// They are fixed strings. A presented token is never one of them.
const (
	ReasonMissingHeader = "missing header"
	ReasonBadScheme     = "bad scheme"
	ReasonWrongToken    = "wrong token"
	ReasonQueryToken    = "query-string token"
	ReasonBadOrigin     = "bad origin"
	ReasonRateLimited   = "rate-limited"
)

const (
	traceStrMax    = 64
	traceMapMax    = 8
	traceMinuteMax = 48
	traceSampleMax = 20
	traceHexRunMin = 8
)

// AuthEvent is one rejected HTTP attempt. Callers must not put a
// token, an Authorization value, or a query string in any field.
type AuthEvent struct {
	Reason  string
	Source  string
	Agent   string
	Request string
	At      time.Time
}

// AuthSample is one of the last few failures, already scrubbed.
type AuthSample struct {
	Unix    int64  `json:"unix"`
	Reason  string `json:"reason"`
	Source  string `json:"source"`
	Request string `json:"request"`
	Agent   string `json:"agent,omitempty"`
}

// AuthTrace is the bounded detail for one local day.
type AuthTrace struct {
	FirstUnix     int64 `json:"first_unix,omitempty"`
	LastUnix      int64 `json:"last_unix,omitempty"`
	PeakPerMinute int   `json:"peak_per_minute,omitempty"`
	// overflowMinute counts a minute that no longer fits in Minutes.
	// PeakPerMinute keeps the high-water mark after that minute is dropped.
	overflowMinute string
	overflowCount  int
	Reasons        map[string]int `json:"reasons,omitempty"`
	Sources        map[string]int `json:"sources,omitempty"`
	Agents         map[string]int `json:"agents,omitempty"`
	Requests       map[string]int `json:"requests,omitempty"`
	Minutes        map[string]int `json:"minutes,omitempty"`
	Sample         []AuthSample   `json:"sample,omitempty"`
}

var hexRun = regexp.MustCompile(`[0-9a-fA-F]{8,}`)

// ScrubAuthText removes control characters and any run that could be
// a token or a prefix of one, then clips the field. It does not hash
// the removed text.
func ScrubAuthText(s string) string {
	s = scrubRaw(s)
	if len(s) > traceStrMax {
		s = s[:traceStrMax]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}

// ScrubAuthJSON scrubs string values in a JSON document. Numbers are
// left as numbers, so a timestamp is not treated as a token.
func ScrubAuthJSON(raw []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	out, err := json.Marshal(scrubJSONValue(v))
	if err != nil {
		return raw
	}
	return out
}

func scrubJSONValue(v any) any {
	switch t := v.(type) {
	case string:
		return scrubRaw(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			nk := scrubRaw(k)
			if nk == "" {
				nk = "redacted"
			}
			out[nk] = scrubJSONValue(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = scrubJSONValue(t[i])
		}
		return t
	default:
		return v
	}
}

func scrubRaw(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return -1
		}
		return r
	}, s)
	lower := strings.ToLower(s)
	for _, mark := range []string{"bearer", "authorization:", "token="} {
		if i := strings.Index(lower, mark); i >= 0 {
			s = s[:i]
			lower = lower[:i]
		}
	}
	s = hexRun.ReplaceAllString(s, "")
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

// FunnelClientIP is the client address from X-Forwarded-For when
// Tailscale's proxy marked the request with Tailscale-Funnel-Request: ?1.
// That proxy overwrites X-Forwarded-For and does not set or strip
// Tailscale-Client-Ip, so that header is not read. Any other mark,
// including a missing one, returns empty and the caller records the
// remote address. Several X-Forwarded-For entries use only the
// right-most, and only when it is an IP.
func FunnelClientIP(funnelMark, xForwardedFor string) string {
	if strings.TrimSpace(funnelMark) != "?1" {
		return ""
	}
	return rightmostIP(xForwardedFor)
}

// ClientSource is "forwarded <ip>" when FunnelClientIP returned an
// address, otherwise "remote <addr>".
func ClientSource(forwarded, remote string) string {
	if ip := firstIP(forwarded); ip != "" {
		return "forwarded " + ip
	}
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = ScrubAuthText(host)
	if host == "" {
		host = "unknown"
	}
	return "remote " + host
}

func firstIP(header string) string {
	if header == "" {
		return ""
	}
	part := strings.TrimSpace(strings.Split(header, ",")[0])
	return parseIP(part)
}

func rightmostIP(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	return parseIP(parts[len(parts)-1])
}

func parseIP(part string) string {
	part = strings.TrimSpace(part)
	part = strings.Trim(part, "[]")
	ip := net.ParseIP(part)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// AddAuthEvent folds ev into the trace. ev is scrubbed here.
func (t *AuthTrace) Add(ev AuthEvent) {
	if t == nil {
		return
	}
	ev.Reason = ScrubAuthText(ev.Reason)
	ev.Source = ScrubAuthText(ev.Source)
	ev.Agent = ScrubAuthText(ev.Agent)
	ev.Request = ScrubAuthText(ev.Request)
	if ev.Reason == "" {
		ev.Reason = "unknown"
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	unix := ev.At.Unix()
	if t.FirstUnix == 0 || unix < t.FirstUnix {
		t.FirstUnix = unix
	}
	if unix > t.LastUnix {
		t.LastUnix = unix
	}
	t.Reasons = bumpKey(t.Reasons, ev.Reason, traceMapMax)
	if ev.Source != "" {
		t.Sources = bumpKey(t.Sources, ev.Source, traceMapMax)
	}
	if ev.Agent != "" {
		t.Agents = bumpKey(t.Agents, ev.Agent, traceMapMax)
	}
	if ev.Request != "" {
		t.Requests = bumpKey(t.Requests, ev.Request, traceMapMax)
	}
	t.noteMinute(strconv.FormatInt(ev.At.Unix()/60, 10))
	t.Sample = append(t.Sample, AuthSample{
		Unix: unix, Reason: ev.Reason, Source: ev.Source, Request: ev.Request, Agent: ev.Agent,
	})
	if len(t.Sample) > traceSampleMax {
		t.Sample = append([]AuthSample(nil), t.Sample[len(t.Sample)-traceSampleMax:]...)
	}
}

// Merge adds extra into t. extra is not modified. Caps still apply.
func (t *AuthTrace) Merge(extra AuthTrace) {
	if t == nil {
		return
	}
	if extra.FirstUnix != 0 && (t.FirstUnix == 0 || extra.FirstUnix < t.FirstUnix) {
		t.FirstUnix = extra.FirstUnix
	}
	if extra.LastUnix > t.LastUnix {
		t.LastUnix = extra.LastUnix
	}
	t.Reasons = mergeCounts(t.Reasons, extra.Reasons, traceMapMax)
	t.Sources = mergeCounts(t.Sources, extra.Sources, traceMapMax)
	t.Agents = mergeCounts(t.Agents, extra.Agents, traceMapMax)
	t.Requests = mergeCounts(t.Requests, extra.Requests, traceMapMax)
	t.Minutes = mergeCounts(t.Minutes, extra.Minutes, traceMinuteMax)
	if extra.PeakPerMinute > t.PeakPerMinute {
		t.PeakPerMinute = extra.PeakPerMinute
	}
	for _, n := range t.Minutes {
		if n > t.PeakPerMinute {
			t.PeakPerMinute = n
		}
	}
	if len(extra.Sample) == 0 {
		return
	}
	t.Sample = append(t.Sample, extra.Sample...)
	if len(t.Sample) > traceSampleMax {
		t.Sample = append([]AuthSample(nil), t.Sample[len(t.Sample)-traceSampleMax:]...)
	}
}

func mergeCounts(dst, src map[string]int, cap int) map[string]int {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]int, len(src))
	}
	for k, n := range src {
		if k == "" || n <= 0 {
			continue
		}
		if _, ok := dst[k]; ok || len(dst) < cap || k == "other" {
			dst[k] += n
			continue
		}
		dst["other"] += n
	}
	return dst
}

func (t *AuthTrace) noteMinute(minute string) {
	if t.Minutes == nil {
		t.Minutes = map[string]int{}
	}
	if _, ok := t.Minutes[minute]; ok || len(t.Minutes) < traceMinuteMax {
		t.Minutes[minute]++
		if t.Minutes[minute] > t.PeakPerMinute {
			t.PeakPerMinute = t.Minutes[minute]
		}
		return
	}
	if t.overflowMinute != minute {
		t.overflowMinute = minute
		t.overflowCount = 0
	}
	t.overflowCount++
	if t.overflowCount > t.PeakPerMinute {
		t.PeakPerMinute = t.overflowCount
	}
	t.Minutes["other"]++
}

func bumpKey(m map[string]int, key string, cap int) map[string]int {
	if m == nil {
		m = map[string]int{}
	}
	if _, ok := m[key]; ok {
		m[key]++
		return m
	}
	if len(m) >= cap {
		m["other"]++
		return m
	}
	m[key] = 1
	return m
}

// ShortAuthNotice is the OSNotify body: count, window, top reasons,
// top sources, and where to read the rest. It is scrubbed again.
func ShortAuthNotice(rec AuthDay, disabled bool) string {
	window := ""
	if rec.Trace.FirstUnix > 0 {
		window = time.Unix(rec.Trace.FirstUnix, 0).Format("15:04")
		if rec.Trace.LastUnix > 0 {
			window += "–" + time.Unix(rec.Trace.LastUnix, 0).Format("15:04")
		}
		window = " " + window
	}
	var b strings.Builder
	if disabled {
		fmt.Fprintf(&b, "proto-mcp: remote access turned off after %d failed sign-ins today%s.", rec.Failures, window)
	} else {
		fmt.Fprintf(&b, "proto-mcp: %d failed remote sign-ins today%s; remote access is still on.", rec.Failures, window)
	}
	if top := topN(rec.Trace.Reasons, 3); top != "" {
		b.WriteString(" ")
		b.WriteString(top)
		b.WriteByte('.')
	}
	if top := topN(rec.Trace.Sources, 3); top != "" {
		b.WriteString(" ")
		b.WriteString(top)
		b.WriteByte('.')
	}
	b.WriteString(" protonmcp http status --debug")
	return scrubRaw(b.String())
}

// FormatAuthDebug is the full detail for `http status --debug`.
func FormatAuthDebug(rec AuthDay) string {
	var b strings.Builder
	b.WriteString("auth failure detail\n")
	if rec.Trace.FirstUnix > 0 {
		b.WriteString("first: " + time.Unix(rec.Trace.FirstUnix, 0).Format(time.RFC3339) + "\n")
	}
	if rec.Trace.LastUnix > 0 {
		b.WriteString("last: " + time.Unix(rec.Trace.LastUnix, 0).Format(time.RFC3339) + "\n")
	}
	b.WriteString("peak per minute: " + strconv.Itoa(rec.Trace.PeakPerMinute) + "\n")
	writeMap(&b, "reasons", rec.Trace.Reasons)
	writeMap(&b, "sources", rec.Trace.Sources)
	writeMap(&b, "user agents", rec.Trace.Agents)
	writeMap(&b, "requests", rec.Trace.Requests)
	b.WriteString("sample:\n")
	for _, s := range rec.Trace.Sample {
		line := time.Unix(s.Unix, 0).Format(time.RFC3339) + " " + s.Reason + " " + s.Source + " " + s.Request
		if s.Agent != "" {
			line += " " + s.Agent
		}
		b.WriteString(scrubRaw(line) + "\n")
	}
	return scrubLines(b.String())
}

func scrubLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = scrubRaw(line)
	}
	return strings.Join(lines, "\n")
}

func writeMap(b *strings.Builder, title string, m map[string]int) {
	b.WriteString(title + ":\n")
	for _, p := range ranked(m) {
		b.WriteString("  " + ScrubAuthText(p.key) + " " + strconv.Itoa(p.n) + "\n")
	}
}

func topN(m map[string]int, n int) string {
	items := ranked(m)
	if len(items) > n {
		items = items[:n]
	}
	var parts []string
	for _, p := range items {
		parts = append(parts, ScrubAuthText(p.key)+" "+strconv.Itoa(p.n))
	}
	return strings.Join(parts, ", ")
}

type pair struct {
	key string
	n   int
}

func ranked(m map[string]int) []pair {
	out := make([]pair, 0, len(m))
	for k, n := range m {
		out = append(out, pair{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	return out
}
