package approval

import (
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

func TestCacheKeySeparatesTransportAndLabel(t *testing.T) {
	args := []byte(`{"message_id":"synthetic-1"}`)
	unix := caller.Caller{Transport: caller.TransportUnix, PID: 42}
	httpRemote := caller.Caller{Transport: caller.TransportHTTP, Label: "remote", PID: 42}
	httpOther := caller.Caller{Transport: caller.TransportHTTP, Label: "other-bot", PID: 42}

	unixKey := cacheKey("mail_move", unix, args)
	httpKey := cacheKey("mail_move", httpRemote, args)
	otherKey := cacheKey("mail_move", httpOther, args)
	if unixKey == httpKey || httpKey == otherKey || unixKey == otherKey {
		t.Fatalf("cache keys collided: unix=%s http=%s other=%s", unixKey, httpKey, otherKey)
	}
	if cacheKey("mail_move", unix, args) != unixKey {
		t.Fatal("same caller produced a different key")
	}

	// PID and args still split keys. Dropping either would let a
	// second socket client, or a different recipient list, reuse an
	// approval.
	if cacheKey("mail_move", caller.Caller{Transport: caller.TransportUnix, PID: 43}, args) == unixKey {
		t.Fatal("pid no longer changes the cache key")
	}
	if cacheKey("mail_move", unix, []byte(`{"message_id":"synthetic-2"}`)) == unixKey {
		t.Fatal("args no longer change the cache key")
	}

	// Length prefixes stop "ab"+"c" from matching "a"+"bc".
	ab := cacheKey("t", caller.Caller{Transport: "ab", Label: "c", PID: 1}, []byte("x"))
	a := cacheKey("t", caller.Caller{Transport: "a", Label: "bc", PID: 1}, []byte("x"))
	if ab == a {
		t.Fatal("transport and label are not separated in the cache key")
	}
}
