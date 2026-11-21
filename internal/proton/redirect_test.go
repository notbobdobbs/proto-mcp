package proton

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-resty/resty/v2"
)

// The SDK builds its client with resty.New(), which leaves CheckRedirect
// nil. Go's default policy follows the redirect and copies every header
// except Authorization and Cookie. The human-verification headers are
// not on that list, so a cross-host 302 carries the token to the new host.
func TestDefaultRestyForwardsHVAcrossHosts(t *testing.T) {
	const token = "hv-token-should-not-leave"
	var got atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("x-pm-human-verification-token"))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(other.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	c := resty.New()
	resp, err := c.R().
		SetHeader("x-pm-human-verification-token", token).
		SetHeader("x-pm-human-verification-token-type", "captcha").
		Post(origin.URL + "/auth/v4")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		t.Fatalf("status %d, want the redirect target", resp.StatusCode())
	}
	if got.Load() != token {
		t.Fatalf("cross-host request token = %v, want the HV token forwarded by the default client", got.Load())
	}
}

func TestRedirectGuardStopsAuthAndHV(t *testing.T) {
	const token = "hv-token-should-not-leave"
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(other.Close)

	for _, path := range []string{"/auth/v4", "/core/v4/users"} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
		}))
		c := resty.New()
		installRedirectGuard(c)
		req := c.R()
		if path != "/auth/v4" {
			req.SetHeader("x-pm-human-verification-token", token)
			req.SetHeader("x-pm-human-verification-token-type", "ownership-email")
		}
		resp, err := req.Post(origin.URL + path)
		origin.Close()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode() != http.StatusFound {
			t.Fatalf("%s status %d, want the unfollowed 302", path, resp.StatusCode())
		}
	}
	if otherHits.Load() != 0 {
		t.Fatalf("redirect target was hit %d times", otherHits.Load())
	}
}

func TestRedirectGuardAllowsOrdinaryRedirect(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			http.Redirect(w, r, srv.URL+"/done", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c := resty.New()
	installRedirectGuard(c)
	resp, err := c.R().Get(srv.URL + "/core/v4/users")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		t.Fatalf("status %d, want the followed redirect", resp.StatusCode())
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, want 2", hits.Load())
	}
}
