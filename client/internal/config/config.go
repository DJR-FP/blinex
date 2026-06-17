package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ManagementURL string   `json:"management_url"` // e.g. "localhost:50051"
	SignalURL     string   `json:"signal_url"`     // e.g. "localhost:10000"
	SetupKey      string   `json:"setup_key"`
	WGInterface   string   `json:"wg_interface"` // e.g. "meshnet0"
	StateDir      string   `json:"state_dir"`    // dir for state.json
	STUNURLs      []string `json:"stun_urls"`    // e.g. ["stun:stun.l.google.com:19302"]
	LogLevel      string   `json:"log_level"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = "/etc/meshnet/agent.json"
	}

	cfg := &Config{
		ManagementURL: getEnv("MESHNET_MANAGEMENT_URL", "localhost:50051"),
		SignalURL:     getEnv("MESHNET_SIGNAL_URL", "localhost:10000"),
		SetupKey:      getEnv("MESHNET_SETUP_KEY", ""),
		WGInterface:   getEnv("MESHNET_WG_IFACE", "meshnet0"),
		StateDir:      getEnv("MESHNET_STATE_DIR", "/var/lib/meshnet"),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		STUNURLs:      parseList(getEnv("MESHNET_STUN_URLS", "stun:stun.l.google.com:19302")),
	}

	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config: %w", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}

	if cfg.SetupKey == "" {
		return nil, fmt.Errorf("setup key required (set MESHNET_SETUP_KEY or setup_key in config)")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
