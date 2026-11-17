package caller

import (
	"context"
	"testing"
)

func TestFromContextZeroByDefault(t *testing.T) {
	got, ok := FromContext(context.Background())
	if ok {
		t.Error("FromContext on bare ctx reported a caller")
	}
	if got != (Caller{}) {
		t.Errorf("FromContext on bare ctx = %+v, want zero", got)
	}
}

func TestWithCallerRoundTrip(t *testing.T) {
	want := Caller{PID: 4242, UID: 501, Binary: "/Applications/Claude.app/Contents/MacOS/Claude", Transport: TransportUnix}
	ctx := WithCaller(context.Background(), want)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext missed a stashed caller")
	}
	if got != want {
		t.Errorf("FromContext after WithCaller = %+v, want %+v", got, want)
	}
}

func TestFromContextPIDZeroIsPresent(t *testing.T) {
	// HTTP has no peer PID. Presence is the bool, not a non-zero PID.
	want := Caller{Transport: TransportHTTP, Label: "remote", PID: 0, UID: 501}
	ctx := WithCaller(context.Background(), want)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("PID 0 caller was treated as absent")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestFromContextStashedZeroCallerIsPresent(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{})
	if _, ok := FromContext(ctx); !ok {
		t.Fatal("a stashed zero caller must still be present")
	}
}

func TestWithCallerDoesntLeakAcrossContexts(t *testing.T) {
	// Two independent ctx trees → two independent Caller values.
	a := WithCaller(context.Background(), Caller{PID: 1})
	b := WithCaller(context.Background(), Caller{PID: 2})
	aCaller, aOK := FromContext(a)
	bCaller, bOK := FromContext(b)
	if !aOK || !bOK {
		t.Fatal("stashed callers missing")
	}
	if aCaller.PID == bCaller.PID {
		t.Errorf("context values leaked across trees")
	}
}

func TestWithCallerOverlay(t *testing.T) {
	parent := WithCaller(context.Background(), Caller{PID: 1})
	child := WithCaller(parent, Caller{PID: 2})
	parentCaller, ok := FromContext(parent)
	if !ok || parentCaller.PID != 1 {
		t.Error("parent ctx mutated by child WithCaller")
	}
	childCaller, ok := FromContext(child)
	if !ok || childCaller.PID != 2 {
		t.Error("child WithCaller didn't override parent")
	}
}
