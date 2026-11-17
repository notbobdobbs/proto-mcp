//go:build !darwin

package main

import "errors"

func platformPasteboard() (pasteboard, error) {
	return nil, errors.New("copying the remote token requires macOS")
}
