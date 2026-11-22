//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

type macPasteboard struct{}

func platformPasteboard() (pasteboard, error) {
	return macPasteboard{}, nil
}

func (macPasteboard) Read() (string, error) {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (macPasteboard) Write(s string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}

func (macPasteboard) Clear() error {
	return macPasteboard{}.Write("")
}
