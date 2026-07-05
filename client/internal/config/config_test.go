package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseList(t *testing.T) {
	got := parseList("a, b ,,c")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected: %v", got)
	}
	if len(parseList("")) != 0 {
		t.Fatal("empty string should yield empty list")
	}
}

func TestLoadRequiresSetupKey(t *testing.T) {
	os.Unsetenv("BLINEX_SETUP_KEY")
	if _, err := Load(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Fatal("expected error when setup key missing")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("BLINEX_SETUP_KEY", "sk-123")
	t.Setenv("BLINEX_MANAGEMENT_URL", "mgmt:1")
	t.Setenv("BLINEX_STUN_URLS", "stun:a:1, stun:b:2")
	cfg, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SetupKey != "sk-123" || cfg.ManagementURL != "mgmt:1" {
		t.Fatalf("env not applied: %+v", cfg)
	}
	if len(cfg.STUNURLs) != 2 {
		t.Fatalf("expected 2 STUN urls, got %v", cfg.STUNURLs)
	}
}

func TestLoadFromJSONFile(t *testing.T) {
	t.Setenv("BLINEX_SETUP_KEY", "envkey")
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	// JSON overrides env-loaded defaults for fields it specifies.
	_ = os.WriteFile(path, []byte(`{"setup_key":"filekey","wg_interface":"wg9"}`), 0600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SetupKey != "filekey" {
		t.Fatalf("file value should override: %s", cfg.SetupKey)
	}
	if cfg.WGInterface != "wg9" {
		t.Fatalf("expected wg9, got %s", cfg.WGInterface)
	}
}

func TestTLSConfigSkipVerifyDefault(t *testing.T) {
	c := &Config{TLSSkipVerify: true}
	tc, err := c.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !tc.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify true")
	}
}

func TestTLSConfigWithBadCACert(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0600)
	c := &Config{TLSCACert: bad}
	if _, err := c.TLSConfig(); err == nil {
		t.Fatal("expected error for invalid CA cert")
	}
}

func TestTLSConfigWithMissingCACert(t *testing.T) {
	c := &Config{TLSCACert: "/nonexistent/ca.pem"}
	if _, err := c.TLSConfig(); err == nil {
		t.Fatal("expected error for missing CA file")
	}
}
