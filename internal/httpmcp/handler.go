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
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

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

	mu        sync.Mutex
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

// Reload re-reads http.yaml. A bad file keeps the previous config and
// does not start a listener. Disabled, or no token, closes the listener.
func (s *Service) Reload() error {
	cfg, err := httpconfig.Load(s.Path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = cfg
	if !cfg.Enabled || !s.tokenPresent() {
		s.stopLocked()
		s.mu.Unlock()
		s.Publish()
		return nil
	}
	if s.ln != nil {
		s.mu.Unlock()
		s.Publish()
		return nil
	}
	ln, err := Listen(cfg.Listen)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.ln = ln
	s.httpSrv = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go s.httpSrv.Serve(ln)
	s.mu.Unlock()
	s.Publish()
	return nil
}

// Publish writes the live door picture next to http.yaml so
// `http status` and doctor can see the listener, the session count,
// and the unlock stamp. A missing path writes nothing.
func (s *Service) Publish() {
	if s == nil || s.Path == "" {
		return
	}
	s.mu.Lock()
	st := httpconfig.DoorState{
		PID:       os.Getpid(),
		Listening: s.ln != nil,
		Sessions:  len(s.sessions),
	}
	path := s.Path
	s.mu.Unlock()
	if s.Clock != nil {
		st.UnlockUnix = s.Clock.Unix()
	}
	_ = httpconfig.WriteDoorState(httpconfig.DoorStatePath(path), st)
}

func (s *Service) tokenPresent() bool {
	if s.Token == nil {
		return false
	}
	tok, err := s.Token()
	if err != nil {
		return false
	}
	defer tok.Zero()
	return len(tok.Bytes()) == keystore.HTTPTokenLen
}

func (s *Service) stopLocked() {
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.httpSrv.Shutdown(ctx)
		cancel()
		s.httpSrv = nil
	}
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
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
	switch r.Method {
	case http.MethodGet, http.MethodOptions:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		tok, ok := s.authed(w, r)
		if !ok {
			return
		}
		s.noteToken(tok)
		zero(tok)
		s.deleteSession(w, r)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tok, ok := s.authed(w, r)
	if !ok {
		return
	}
	defer zero(tok)
	s.noteToken(tok)

	if proto := r.Header.Get("MCP-Protocol-Version"); proto != "" && proto != "2025-06-18" && proto != "2025-03-26" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if !hostOK(r.Host, cfg.AllowedHosts) || !originOK(r.Header.Get("Origin"), cfg.AllowedOrigins) {
		w.WriteHeader(http.StatusForbidden)
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
	now := s.now()
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

// authed checks the shared failure bucket, then the bearer. A token
// in the query string is a failure even when the Authorization header
// is valid. The bucket covers POST and DELETE. GET and OPTIONS are
// not authentication attempts.
func (s *Service) authed(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	now := s.now()
	if s.authFails.over(now, authFailLimit) {
		w.WriteHeader(http.StatusTooManyRequests)
		return nil, false
	}
	if r.URL.RawQuery != "" && hasTokenQuery(r) {
		s.authFails.add(now)
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	tok, ok := s.bearer(r)
	if !ok {
		s.authFails.add(now)
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	return tok, true
}

func (s *Service) session(id string) *hsess {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	sess := s.sessions[id]
	if sess == nil {
		return nil
	}
	sess.last = s.now()
	return sess
}

func (s *Service) sweepLocked(now time.Time) {
	for id, sess := range s.sessions {
		if now.Sub(sess.last) > sessionIdle {
			delete(s.sessions, id)
		}
	}
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

func hasTokenQuery(r *http.Request) bool {
	q := r.URL.Query()
	return q.Has("token") || q.Has("access_token") || q.Has("authorization")
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

func originOK(origin string, allowed []string) bool {
	if origin == "" {
		return true
	}
	if strings.EqualFold(origin, "null") {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), origin) {
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
