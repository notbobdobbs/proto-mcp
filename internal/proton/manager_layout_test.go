package proton

import (
	"reflect"
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
