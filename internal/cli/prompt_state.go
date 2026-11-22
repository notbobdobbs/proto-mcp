//go:build linux || darwin

package cli

import (
	"context"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"golang.org/x/term"
)

func termState(fd int) (*term.State, error) {
	return term.GetState(fd)
}

func termStatesEqual(a, b *term.State) bool {
	return reflect.DeepEqual(a, b)
}

func signalNotifyInterrupt() (context.Context, func()) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}
