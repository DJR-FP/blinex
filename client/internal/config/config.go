package config

import (
	"crypto/tls"
	"crypto/x509"
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
	// TLS options for connecting to management and signal servers.
	// TLSSkipVerify=true (default) allows self-signed server certificates.
	// Set TLSCACert to pin a specific CA cert PEM file instead.
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	TLSCACert     string `json:"tls_ca_cert"` // path to CA cert PEM
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
		// Default to skip-verify so the agent works with self-signed server certs.
		TLSSkipVerify: getEnv("MESHNET_TLS_SKIP_VERIFY", "true") != "false",
		TLSCACert:     getEnv("MESHNET_TLS_CA_CERT", ""),
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

// TLSConfig returns a *tls.Config for outbound gRPC connections.
// When TLSCACert is set the certificate is used as the only trusted CA.
// When TLSSkipVerify is true (the default) server cert verification is skipped,
// which is safe for self-signed certs on trusted networks.
func (c *Config) TLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: c.TLSSkipVerify, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
	if c.TLSCACert != "" {
		pem, err := os.ReadFile(c.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert %q: %w", c.TLSCACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certificates found in %q", c.TLSCACert)
		}
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
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
