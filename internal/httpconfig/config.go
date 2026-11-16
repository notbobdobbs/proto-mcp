// Package httpconfig reads and writes the remote-door config file.
// The file is separate from policy.yaml so editing tool rules cannot
// open a port. This package does not listen.
package httpconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListen               = "127.0.0.1:4765"
	DefaultCallerLabel          = "remote"
	DefaultMaxRequestsPerMinute = 60
	DefaultMaxRemoteReadsPerDay = 500
	DefaultMaxUnlockHours       = 8

	maxRequestsPerMinuteCeiling = 600
	maxRemoteReadsPerDayCeiling = 5000
	maxUnlockHoursCeiling       = 24
	maxCallerLabelLen           = 64
)

// DefaultRemoteTools is the remote door's tool list when http.yaml
// omits remote_tools or sets it empty. Empty is not every tool.
// Permanent delete and draft delete are not on it.
var DefaultRemoteTools = []string{
	"account_whoami",
	"mail_list",
	"mail_search",
	"mail_read",
	"mail_read_thread",
	"mail_list_attachments",
	"mail_sync",
	"labels_list",
	"folders_list",
	"calendar_list",
	"calendar_events",
	"calendar_read_event",
	"mail_draft_list",
	"mail_draft_create",
	"mail_draft_update",
	"mail_send",
	"mail_send_draft",
	"mail_reply",
	"mail_reply_all",
	"mail_forward",
	"mail_download_attachment",
	"mail_trash",
}

// knownTools are names that may appear in remote_tools. Anything else
// is ignored at load and does not create a tool. * and all are not
// in this set; they reject the file.
var knownTools = map[string]struct{}{
	"account_whoami":           {},
	"mail_list":                {},
	"mail_search":              {},
	"mail_read":                {},
	"mail_read_thread":         {},
	"mail_list_attachments":    {},
	"mail_sync":                {},
	"mail_download_attachment": {},
	"mail_save_attachment":     {},
	"labels_list":              {},
	"folders_list":             {},
	"calendar_list":            {},
	"calendar_events":          {},
	"calendar_read_event":      {},
	"mail_draft_create":        {},
	"mail_draft_update":        {},
	"mail_draft_delete":        {},
	"mail_draft_list":          {},
	"mail_send":                {},
	"mail_send_draft":          {},
	"mail_reply":               {},
	"mail_reply_all":           {},
	"mail_forward":             {},
	"mail_move":                {},
	"mail_label":               {},
	"mail_mark_read":           {},
	"mail_mark_unread":         {},
	"mail_trash":               {},
	"mail_delete_permanent":    {},
	"labels_create":            {},
	"labels_update":            {},
	"labels_delete":            {},
	"folders_create":           {},
	"folders_update":           {},
	"folders_delete":           {},
}

// ErrBadFile means the file must not be applied. The previous good
// file stays in effect, and a first load stays off.
var ErrBadFile = errors.New("http.yaml is not usable")

// Config is the effective remote-door config. Zero values for the
// caps have already been replaced with the defaults. There is no
// value here that means unlimited.
type Config struct {
	Enabled              bool
	Listen               string
	CallerLabel          string
	AllowedHosts         []string
	MaxRequestsPerMinute int
	MaxRemoteReadsPerDay int
	MaxUnlockHours       int
	// RemoteTools is the effective allowlist. It is never "every tool".
	RemoteTools []string
	// RemoteToolsSet is true when the file named a non-empty list.
	// Omitted and empty both leave this false and use DefaultRemoteTools.
	RemoteToolsSet bool
}

// Default returns the config of an absent file: off, with the
// built-in caps and tool list.
func Default() Config {
	return Config{
		Enabled:              false,
		Listen:               DefaultListen,
		CallerLabel:          DefaultCallerLabel,
		AllowedHosts:         []string{DefaultListen, "localhost:4765"},
		MaxRequestsPerMinute: DefaultMaxRequestsPerMinute,
		MaxRemoteReadsPerDay: DefaultMaxRemoteReadsPerDay,
		MaxUnlockHours:       DefaultMaxUnlockHours,
		RemoteTools:          append([]string(nil), DefaultRemoteTools...),
	}
}

type rawFile struct {
	Enabled              *bool     `yaml:"enabled"`
	Listen               *string   `yaml:"listen"`
	CallerLabel          *string   `yaml:"caller_label"`
	AllowedHosts         *[]string `yaml:"allowed_hosts"`
	MaxRequestsPerMinute *int      `yaml:"max_requests_per_minute"`
	MaxRemoteReadsPerDay *int      `yaml:"max_remote_reads_per_day"`
	MaxUnlockHours       *int      `yaml:"max_unlock_hours"`
	RemoteTools          *[]string `yaml:"remote_tools"`
}

// Parse interprets file bytes. A bad file returns ErrBadFile and a
// zero Config, which is disabled. Absent-file callers should use
// Default instead of Parse.
func Parse(data []byte) (Config, error) {
	var raw rawFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrBadFile, err)
	}
	cfg := Default()
	cfg.Enabled = raw.Enabled != nil && *raw.Enabled
	if raw.Listen != nil && strings.TrimSpace(*raw.Listen) != "" {
		cfg.Listen = strings.TrimSpace(*raw.Listen)
	}
	if raw.CallerLabel != nil {
		label, err := normalizeLabel(*raw.CallerLabel)
		if err != nil {
			return Config{}, err
		}
		cfg.CallerLabel = label
	}
	if raw.AllowedHosts != nil {
		cfg.AllowedHosts = append([]string(nil), (*raw.AllowedHosts)...)
	}
	rpm, err := capOrDefault(raw.MaxRequestsPerMinute, DefaultMaxRequestsPerMinute, maxRequestsPerMinuteCeiling, "max_requests_per_minute")
	if err != nil {
		return Config{}, err
	}
	cfg.MaxRequestsPerMinute = rpm
	reads, err := capOrDefault(raw.MaxRemoteReadsPerDay, DefaultMaxRemoteReadsPerDay, maxRemoteReadsPerDayCeiling, "max_remote_reads_per_day")
	if err != nil {
		return Config{}, err
	}
	cfg.MaxRemoteReadsPerDay = reads
	hours, err := capOrDefault(raw.MaxUnlockHours, DefaultMaxUnlockHours, maxUnlockHoursCeiling, "max_unlock_hours")
	if err != nil {
		return Config{}, err
	}
	cfg.MaxUnlockHours = hours
	tools, set, err := remoteTools(raw.RemoteTools)
	if err != nil {
		return Config{}, err
	}
	cfg.RemoteTools = tools
	cfg.RemoteToolsSet = set
	return cfg, nil
}

func normalizeLabel(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DefaultCallerLabel, nil
	}
	if utf8.RuneCountInString(s) > maxCallerLabelLen {
		return "", fmt.Errorf("%w: caller_label is longer than %d characters", ErrBadFile, maxCallerLabelLen)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return "", fmt.Errorf("%w: caller_label contains a control character", ErrBadFile)
		}
	}
	return s, nil
}

func capOrDefault(raw *int, def, ceiling int, name string) (int, error) {
	if raw == nil || *raw == 0 {
		return def, nil
	}
	if *raw < 0 || *raw > ceiling {
		return 0, fmt.Errorf("%w: %s must be 0 (the default) or 1–%d", ErrBadFile, name, ceiling)
	}
	return *raw, nil
}

func remoteTools(raw *[]string) ([]string, bool, error) {
	if raw == nil || len(*raw) == 0 {
		return append([]string(nil), DefaultRemoteTools...), false, nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, name := range *raw {
		name = strings.TrimSpace(name)
		if name == "*" || strings.EqualFold(name, "all") {
			return nil, false, fmt.Errorf("%w: remote_tools cannot be %q", ErrBadFile, name)
		}
		if _, ok := knownTools[name]; !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	// A list was set. Unknown names were dropped. If nothing known
	// remains, the list is empty — that allows no remote tool. It
	// is not the default list and it is not every tool.
	return out, true, nil
}

// Load reads path. A missing file is Default and a nil error.
// A bad file is ErrBadFile and a zero Config, so enabled is false.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, err
	}
	return Parse(data)
}

// Save writes cfg as mode 0600. The directory is created mode 0700.
// The default tool list is omitted so an absent remote_tools key
// keeps meaning "the default", not "every tool".
func Save(path string, cfg Config) error {
	doc := map[string]any{
		"enabled":                  cfg.Enabled,
		"listen":                   cfg.Listen,
		"caller_label":             cfg.CallerLabel,
		"allowed_hosts":            cfg.AllowedHosts,
		"max_requests_per_minute":  cfg.MaxRequestsPerMinute,
		"max_remote_reads_per_day": cfg.MaxRemoteReadsPerDay,
		"max_unlock_hours":         cfg.MaxUnlockHours,
	}
	if cfg.RemoteToolsSet {
		doc["remote_tools"] = cfg.RemoteTools
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0o600)
}
