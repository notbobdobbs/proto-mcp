package httpconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbsentFileIsOffWithDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("missing file enabled the door")
	}
	if cfg.MaxUnlockHours != DefaultMaxUnlockHours || cfg.MaxRequestsPerMinute != DefaultMaxRequestsPerMinute || cfg.MaxRemoteReadsPerDay != DefaultMaxRemoteReadsPerDay {
		t.Fatalf("caps = %+v", cfg)
	}
	assertDefaultTools(t, cfg)
}

func TestZeroCapsMeanDefaultsNotUnlimited(t *testing.T) {
	cfg, err := Parse([]byte("enabled: false\nmax_unlock_hours: 0\nmax_requests_per_minute: 0\nmax_remote_reads_per_day: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxUnlockHours != 8 || cfg.MaxRequestsPerMinute != 60 || cfg.MaxRemoteReadsPerDay != 500 {
		t.Fatalf("zero was not the default: %+v", cfg)
	}
}

func TestBadFileStaysUnusable(t *testing.T) {
	cases := []string{
		"enabled: true\nmax_unlock_hours: 25\n",
		"enabled: true\nmax_unlock_hours: -1\n",
		"enabled: true\nmax_requests_per_minute: 601\n",
		"enabled: true\nmax_remote_reads_per_day: 5001\n",
		"enabled: true\nmax_requests_per_minute: -5\n",
		"enabled: true\nremote_tools: ['*']\n",
		"enabled: true\nremote_tools: [all]\n",
		"enabled: true\ncaller_label: \"has\\nnewline\"\n",
		"enabled: true\ncaller_label: \"" + strings.Repeat("a", 65) + "\"\n",
	}
	for _, body := range cases {
		cfg, err := Parse([]byte(body))
		if !errors.Is(err, ErrBadFile) {
			t.Errorf("body %q err = %v, want ErrBadFile", body, err)
		}
		if cfg.Enabled {
			t.Errorf("bad file was enabled: %q", body)
		}
	}
}

func TestEmptyRemoteToolsIsTheDefaultNotAll(t *testing.T) {
	for _, body := range []string{"enabled: false\n", "enabled: false\nremote_tools: []\n"} {
		cfg, err := Parse([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RemoteToolsSet {
			t.Fatalf("empty list was treated as an explicit set: %q", body)
		}
		assertDefaultTools(t, cfg)
	}
}

func TestRemoteToolsReplaceTheDefault(t *testing.T) {
	cfg, err := Parse([]byte("remote_tools: [mail_read, not_a_tool, mail_read]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RemoteToolsSet {
		t.Fatal("explicit list was not marked set")
	}
	if len(cfg.RemoteTools) != 1 || cfg.RemoteTools[0] != "mail_read" {
		t.Fatalf("tools = %v", cfg.RemoteTools)
	}
}

func TestSaveIsOwnerOnlyAndRoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "protonmcp")
	path := filepath.Join(dir, "http.yaml")
	cfg := Default()
	cfg.Enabled = true
	cfg.CallerLabel = "remote"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.CallerLabel != "remote" {
		t.Fatalf("reloaded %+v", got)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "remote_tools") {
		t.Fatalf("default tool list was written out, which would look like an explicit set:\n%s", data)
	}
}

func TestLoadRefusesGroupOrWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http.yaml")
	if err := Save(path, Default()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o660, 0o606, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrBadFile) {
			t.Errorf("mode %o: err = %v, want ErrBadFile", mode, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestWriteDisabledIgnoresOldContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http.yaml")
	if err := os.WriteFile(path, []byte("::::"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteDisabled(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("disabled file is enabled")
	}
}

func assertDefaultTools(t *testing.T, cfg Config) {
	t.Helper()
	set := map[string]bool{}
	for _, name := range cfg.RemoteTools {
		set[name] = true
	}
	for _, name := range []string{"mail_download_attachment", "mail_trash", "mail_read", "mail_send"} {
		if !set[name] {
			t.Errorf("default list missing %s: %v", name, cfg.RemoteTools)
		}
	}
	for _, name := range []string{"mail_draft_delete", "mail_delete_permanent"} {
		if set[name] {
			t.Errorf("default list includes %s", name)
		}
	}
}
