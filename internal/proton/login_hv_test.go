package proton

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/go-proton-api/server"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// TestLogin_Auth9001RetriesWithIssuedToken is the setup failure: a 9001
// from POST /auth/v4 used to abort before tryWithHV ever ran. The retry
// must redo SRP (auth info is single-use) and send back the token and
// methods Proton issued, unmodified.
func TestLogin_Auth9001RetriesWithIssuedToken(t *testing.T) {
	const (
		user  = "user"
		pass  = "pass"
		token = "issued-token-unchanged"
		web   = "https://verify.proton.me/?methods=ownership-email&token=issued-token-unchanged"
	)

	upstream := server.New()
	t.Cleanup(upstream.Close)
	if _, _, err := upstream.CreateUser(user, []byte(pass)); err != nil {
		t.Fatalf("create user: %v", err)
	}
	upURL, err := url.Parse(upstream.GetHostURL())
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	infoPosts := 0
	type authHit struct {
		token string
		types string
	}
	var authHits []authHit

	proxy := httputil.NewSingleHostReverseProxy(upURL)
	// The fake server listens with TLS and a test certificate.
	proxy.Transport = gpa.InsecureTransport()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v4/info":
			mu.Lock()
			infoPosts++
			mu.Unlock()
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v4":
			mu.Lock()
			n := len(authHits)
			authHits = append(authHits, authHit{
				token: r.Header.Get("x-pm-human-verification-token"),
				types: r.Header.Get("x-pm-human-verification-token-type"),
			})
			mu.Unlock()
			if n == 0 {
				writeAuthHV(w, token, []string{"ownership-email"}, web)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)

	mgr := gpa.New(
		gpa.WithHostURL(front.URL),
		gpa.WithTransport(gpa.InsecureTransport()),
		gpa.WithCookieJar(NewCookieJar()),
	)
	t.Cleanup(mgr.Close)

	var shown string
	creds := &Credentials{
		Email:    user,
		Password: secret.New([]byte(pass)),
		AskHVBrowserConfirm: func(_ context.Context, webURL string, again bool) error {
			if again {
				t.Error("first confirmation should not be flagged again")
			}
			shown = webURL
			return nil
		},
	}
	t.Cleanup(func() { creds.Zero() })

	sess, err := Login(context.Background(), mgr, creds)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Cleanup(sess.Close)

	if shown != web {
		t.Errorf("shown url = %q, want %q", shown, web)
	}
	mu.Lock()
	defer mu.Unlock()
	if infoPosts < 2 {
		t.Errorf("POST /auth/v4/info count = %d, want at least 2 (fresh SRP auth info on retry)", infoPosts)
	}
	if len(authHits) < 2 {
		t.Fatalf("POST /auth/v4 count = %d, want at least 2", len(authHits))
	}
	if authHits[0].token != "" || authHits[0].types != "" {
		t.Errorf("first auth carried hv headers token=%q type=%q", authHits[0].token, authHits[0].types)
	}
	if authHits[1].token != token {
		t.Errorf("retry token = %q, want the issued token %q", authHits[1].token, token)
	}
	if authHits[1].types != "ownership-email" {
		t.Errorf("retry methods = %q, want ownership-email", authHits[1].types)
	}
}

func writeAuthHV(w http.ResponseWriter, token string, methods []string, webURL string) {
	body, err := json.Marshal(map[string]any{
		"Code":  9001,
		"Error": "Human verification required",
		"Details": map[string]any{
			"HumanVerificationToken":   token,
			"HumanVerificationMethods": methods,
			"WebUrl":                   webURL,
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Date", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	w.WriteHeader(http.StatusUnprocessableEntity)
	_, _ = w.Write(body)
}
