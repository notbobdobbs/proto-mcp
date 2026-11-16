package httpmcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

const (
	bodyCap       = 8 << 20
	maxSessions   = 8
	sessionIdle   = 15 * time.Minute
	authFailLimit = 10
	inFlightLimit = 2
	requestLimit  = 45 * time.Second
)

// TokenFunc loads the current bearer token. It is called on every
// request and is not cached.
type TokenFunc func() (secret.Secret, error)

// Service is the loopback Streamable HTTP door. A disabled config or
// a missing token leaves it with no listener.
type Service struct {
	MCP   *mcp.Server
	Path  string
	Token TokenFunc
	Now   func() time.Time
	Clock *UnlockClock
	Reads *ReadCap
	// Audit records the auto-disable row. Nil skips that row.
	Audit *audit.Writer
	// Notify posts the auto-disable notice. Nil uses OSNotify.
	// A returned error does not undo the disable.
	Notify func(string) error

	mu        sync.Mutex
	failMu    sync.Mutex
	cfg       httpconfig.Config
	ln        net.Listener
	httpSrv   *http.Server
	sessions  map[string]*hsess
	tokenFP   [32]byte
	haveFP    bool
	authFails *window
	perMinute *window
	inFlight  chan struct{}
}

type hsess struct {
	conn    *mcp.Conn
	claimed string
	last    time.Time
}

type window struct {
	mu   sync.Mutex
	hits []time.Time
}

func (w *window) count(now time.Time) int {
	cutoff := now.Add(-time.Minute)
	kept := make([]time.Time, 0, len(w.hits))
	for _, t := range w.hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	w.hits = kept
	return len(kept)
}

func (w *window) over(now time.Time, limit int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count(now) >= limit
}

func (w *window) add(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count(now)
	w.hits = append(w.hits, now)
}

func (w *window) allow(now time.Time, limit int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count(now) >= limit {
		return false
	}
	w.hits = append(w.hits, now)
	return true
}

func New(mcpSrv *mcp.Server, path string, token TokenFunc) *Service {
	return &Service{
		MCP:       mcpSrv,
		Path:      path,
		Token:     token,
		Now:       time.Now,
		sessions:  map[string]*hsess{},
		authFails: &window{},
		perMinute: &window{},
		inFlight:  make(chan struct{}, inFlightLimit),
	}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Reload re-reads http.yaml. A bad file, a disabled file, or a missing
// token closes the listener and drops sessions. The previous enabled
// config is not kept. A changed token drops sessions immediately.
// The returned error never includes the token; callers should still
// pass it through SafeError before logging.
func (s *Service) Reload() error {
	cfg, loadErr := httpconfig.Load(s.Path)
	fp, have := s.currentFP()
	s.mu.Lock()
	var ret error
	if loadErr != nil {
		s.cfg.Enabled = false
		s.sessions = map[string]*hsess{}
		s.haveFP = false
		s.stopLocked()
		ret = loadErr
	} else {
		s.cfg = cfg
		if !cfg.Enabled || !have {
			s.sessions = map[string]*hsess{}
			s.haveFP = false
			s.stopLocked()
		} else {
			if s.haveFP && s.tokenFP != fp {
				s.sessions = map[string]*hsess{}
			}
			s.tokenFP = fp
			s.haveFP = true
			if s.ln == nil {
				ln, lerr := Listen(cfg.Listen)
				if lerr != nil {
					ret = lerr
				} else {
					srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
					s.ln = ln
					s.httpSrv = srv
					go func() { _ = srv.Serve(ln) }()
				}
			}
		}
	}
	st, path := s.snapshotLocked()
	s.mu.Unlock()
	writeDoor(path, st)
	return ret
}

func (s *Service) currentFP() (fp [32]byte, ok bool) {
	if s.Token == nil {
		return fp, false
	}
	tok, err := s.Token()
	if err != nil {
		return fp, false
	}
	defer tok.Zero()
	if len(tok.Bytes()) != keystore.HTTPTokenLen {
		return fp, false
	}
	return sha256.Sum256(tok.Bytes()), true
}

func (s *Service) stopLocked() {
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := s.httpSrv.Shutdown(ctx)
		cancel()
		if err != nil {
			_ = s.httpSrv.Close()
		}
		s.httpSrv = nil
	}
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func (s *Service) snapshotLocked() (httpconfig.DoorState, string) {
	st := httpconfig.DoorState{
		PID:       os.Getpid(),
		Listening: s.ln != nil,
		Sessions:  len(s.sessions),
	}
	if s.Clock != nil {
		st.UnlockUnix = s.Clock.Unix()
	}
	if s.Path == "" {
		return st, ""
	}
	return st, httpconfig.DoorStatePath(s.Path)
}

func writeDoor(path string, st httpconfig.DoorState) {
	if path == "" {
		return
	}
	_ = httpconfig.WriteDoorState(path, st)
}

// Publish writes the live door file for status and doctor.
func (s *Service) Publish() {
	s.mu.Lock()
	st, path := s.snapshotLocked()
	s.mu.Unlock()
	writeDoor(path, st)
}

// tokenHex matches the clipboard encoding of the bearer token.
var tokenHex = regexp.MustCompile(`[0-9a-fA-F]{64}`)

// SafeError is err's text with any 64-hex token replaced. Log this,
// not the raw error, when a reload or listen failure is reported.
func SafeError(err error) string {
	if err == nil {
		return ""
	}
	return tokenHex.ReplaceAllString(err.Error(), "[redacted]")
}

// Close stops the listener.
func (s *Service) Close() { s.mu.Lock(); s.stopLocked(); s.mu.Unlock() }

// Listening reports whether a TCP listener is open.
func (s *Service) Listening() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln != nil
}

// Addr is the bound address, or "" when nothing is listening.
func (s *Service) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Label is the configured caller label, or "remote".
func (s *Service) Label() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.CallerLabel == "" {
		return "remote"
	}
	return s.cfg.CallerLabel
}

// UnlockHours is the absolute unlock window. 0 means 8.
func (s *Service) UnlockHours() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxUnlockHours <= 0 {
		return 8
	}
	return s.cfg.MaxUnlockHours
}

// MaxReads is the daily remote read cap. 0 means 500.
func (s *Service) MaxReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxRemoteReadsPerDay <= 0 {
		return 500
	}
	return s.cfg.MaxRemoteReadsPerDay
}

// Allows reports whether name is on the current remote tool list.
func (s *Service) Allows(name string) bool {
	s.mu.Lock()
	tools := append([]string(nil), s.cfg.RemoteTools...)
	s.mu.Unlock()
	for _, t := range tools {
		if t == name {
			return true
		}
	}
	return false
}

// Handler is the /mcp handler. Tests call it without Listen.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if !LoopbackRemote(r.RemoteAddr) {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	now := s.now()
	if s.authFails.over(now, authFailLimit) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	// A bearer in the query is never accepted, even when the
	// Authorization header is also present. It counts as a failure
	// for every method, including GET and DELETE. The query is not logged.
	if hasBearerQuery(r) {
		s.authFails.add(now)
		s.recordAuthFailure(r.Context(), now)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodOptions:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	case http.MethodDelete, http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if !hostOK(r.Host, cfg.AllowedHosts) || !originOK(r.Header.Get("Origin"), cfg.AllowedOrigins) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	tok, ok := s.bearer(r)
	if !ok {
		s.authFails.add(now)
		s.recordAuthFailure(r.Context(), now)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	defer zero(tok)
	s.noteToken(tok)
	if r.Method == http.MethodDelete {
		s.deleteSession(w, r)
		return
	}

	if proto := r.Header.Get("MCP-Protocol-Version"); proto != "" && proto != "2025-06-18" && proto != "2025-03-26" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.ContentLength > bodyCap {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, bodyCap+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > bodyCap {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	limit := cfg.MaxRequestsPerMinute
	if limit <= 0 {
		limit = 60
	}
	if !s.perMinute.allow(now, limit) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	default:
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	var req mcp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusOK, &mcp.Response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: mcp.NewError(mcp.CodeParseError, "parse error")})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestLimit)
	defer cancel()
	ctx = withCaller(ctx, cfg)

	if req.Method == "initialize" {
		s.serveInitialize(w, ctx, &req)
		return
	}
	sess := s.session(r.Header.Get("Mcp-Session-Id"))
	if sess == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ctx = withCaller(ctx, cfg)
	if sess.claimed != "" {
		ctx = callerClaim(ctx, sess.claimed)
	}
	resp := s.MCP.Dispatch(ctx, sess.conn, &req)
	if req.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) serveInitialize(w http.ResponseWriter, ctx context.Context, req *mcp.Request) {
	conn := &mcp.Conn{}
	resp := s.MCP.Dispatch(ctx, conn, req)
	if resp.Error != nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	id := newSessionID()
	s.mu.Lock()
	s.sweepLocked(s.now())
	if len(s.sessions) >= maxSessions {
		s.dropOldestLocked()
	}
	s.sessions[id] = &hsess{conn: conn, claimed: clientName(req.Params), last: s.now()}
	s.mu.Unlock()
	s.Publish()
	w.Header().Set("Mcp-Session-Id", id)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) deleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("Mcp-Session-Id")
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	s.Publish()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) session(id string) *hsess {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	dropped := s.sweepLocked(s.now())
	sess := s.sessions[id]
	if sess != nil {
		sess.last = s.now()
	}
	st, path := s.snapshotLocked()
	s.mu.Unlock()
	if dropped {
		writeDoor(path, st)
	}
	return sess
}

func (s *Service) sweepLocked(now time.Time) bool {
	dropped := false
	for id, sess := range s.sessions {
		if now.Sub(sess.last) > sessionIdle {
			delete(s.sessions, id)
			dropped = true
		}
	}
	return dropped
}

func (s *Service) dropOldestLocked() {
	var oldest string
	var at time.Time
	for id, sess := range s.sessions {
		if oldest == "" || sess.last.Before(at) {
			oldest = id
			at = sess.last
		}
	}
	if oldest != "" {
		delete(s.sessions, oldest)
	}
}

func (s *Service) bearer(r *http.Request) ([]byte, bool) {
	if s.Token == nil {
		return nil, false
	}
	stored, err := s.Token()
	if err != nil {
		return nil, false
	}
	defer stored.Zero()
	if len(stored.Bytes()) != keystore.HTTPTokenLen {
		return nil, false
	}
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return nil, false
	}
	presented := strings.TrimSpace(h[len(p):])
	if !keystore.HTTPTokenMatches(stored.Bytes(), presented) {
		return nil, false
	}
	out := make([]byte, len(stored.Bytes()))
	copy(out, stored.Bytes())
	return out, true
}

func (s *Service) noteToken(raw []byte) {
	fp := sha256.Sum256(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.haveFP && s.tokenFP != fp {
		s.sessions = map[string]*hsess{}
	}
	s.tokenFP = fp
	s.haveFP = true
}

func hasBearerQuery(r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return false
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return true
	}
	for key, vals := range q {
		switch strings.ToLower(key) {
		case "token", "access_token", "authorization", "bearer":
			return true
		}
		for _, v := range vals {
			if looksLikeBearer(v) {
				return true
			}
		}
	}
	return false
}

func looksLikeBearer(v string) bool {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return true
	}
	if len(v) == 64 && isHex(v) {
		return true
	}
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func hostOK(host string, allowed []string) bool {
	host = strings.TrimSpace(host)
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return true
		}
	}
	return false
}

// originOK allows a missing Origin. A present Origin, including a
// loopback one, must be an exact allowed_origins entry. allowed_hosts
// is not consulted. "null" is present and is rejected unless listed.
func originOK(origin string, allowed []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true
	}
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

func withCaller(ctx context.Context, cfg httpconfig.Config) context.Context {
	return callerWith(ctx, cfg.CallerLabel)
}

func clientName(params json.RawMessage) string {
	var p struct {
		ClientInfo struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
	}
	_ = json.Unmarshal(params, &p)
	var b strings.Builder
	for _, r := range p.ClientInfo.Name {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 128 {
			break
		}
	}
	return b.String()
}

func newSessionID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
