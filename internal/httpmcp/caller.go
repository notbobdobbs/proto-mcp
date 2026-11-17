package httpmcp

import (
	"context"
	"os"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

func callerWith(ctx context.Context, label string) context.Context {
	if label == "" {
		label = "remote"
	}
	return caller.WithCaller(ctx, caller.Caller{
		Transport: caller.TransportHTTP,
		Label:     label,
		PID:       0,
		UID:       os.Getuid(),
	})
}

func callerClaim(ctx context.Context, name string) context.Context {
	return caller.WithClaimedClient(ctx, name)
}
