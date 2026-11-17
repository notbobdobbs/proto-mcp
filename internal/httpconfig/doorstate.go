package httpconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// DoorState is the live picture of the HTTP door, written by the
// daemon and read by `http status` and doctor. A dead PID means the
// numbers are stale and must not be reported as live.
type DoorState struct {
	PID        int   `json:"pid"`
	Listening  bool  `json:"listening"`
	Sessions   int   `json:"sessions"`
	UnlockUnix int64 `json:"unlock_unix"`
}

// DoorStatePath is the status file next to http.yaml.
func DoorStatePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "http-status.json")
}

// WriteDoorState stores st as mode 0600.
func WriteDoorState(path string, st DoorState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(path, data)
}

// ReadLiveDoorState returns the daemon's state when that process is
// still running. A missing file or a dead PID is a zero state: not
// listening, no sessions, no unlock stamp.
func ReadLiveDoorState(path string) DoorState {
	data, err := os.ReadFile(path)
	if err != nil {
		return DoorState{}
	}
	var st DoorState
	if err := json.Unmarshal(data, &st); err != nil {
		return DoorState{}
	}
	if !pidAlive(st.PID) {
		return DoorState{}
	}
	return st
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// FormatUnlockAge is "none" when the stamp is missing, otherwise the
// age rounded to a second.
func FormatUnlockAge(unlockUnix int64, now time.Time) string {
	if unlockUnix <= 0 {
		return "none"
	}
	age := now.Sub(time.Unix(unlockUnix, 0))
	if age < 0 {
		age = 0
	}
	return age.Round(time.Second).String()
}
