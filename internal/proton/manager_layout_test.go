package proton

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"
)

// managerResty reads the SDK manager's unexported first field. The SDK
// does not export the resty client, and nothing else reaches
// CheckRedirect. This fails the build of the assumption when that
// layout changes, instead of silently installing the guard on the
// wrong value.
func TestManagerRestyMatchesSDKLayout(t *testing.T) {
	typ := reflect.TypeOf(gpa.Manager{})
	if typ.NumField() == 0 {
		t.Fatal("gpa.Manager has no fields")
	}
	first := typ.Field(0)
	want := reflect.TypeOf((*resty.Client)(nil))
	if first.Name != "rc" || first.Type != want || first.Offset != 0 {
		t.Fatalf("gpa.Manager first field is %s %s at offset %d; want rc %s at offset 0. Update managerResty.",
			first.Name, first.Type, first.Offset, want)
	}
	m := NewManager(nil)
	t.Cleanup(m.Close)
	if managerResty(m) == nil {
		t.Fatal("managerResty returned nil")
	}
}

// A real /auth redirect goes through the manager NewManager configured.
// If managerResty no longer points at that client, the hook does not
// run or the redirect is followed.
func TestNewManagerRedirectUsesLiveClient(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(other.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	m := NewManager(nil)
	t.Cleanup(m.Close)
	var hooked atomic.Int32
	m.AddPreRequestHook(func(_ *resty.Client, _ *resty.Request) error {
		hooked.Add(1)
		return nil
	})
	c := managerResty(m)
	c.SetBaseURL(origin.URL)
	resp, err := c.R().Post("/auth/v4")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if hooked.Load() != 1 {
		t.Fatalf("manager hook ran %d times; managerResty is not the live client", hooked.Load())
	}
	if otherHits.Load() != 0 {
		t.Fatal("NewManager followed an /auth redirect")
	}
	if resp.StatusCode() != http.StatusFound {
		t.Fatalf("status %d, want the unfollowed 302", resp.StatusCode())
	}
}
