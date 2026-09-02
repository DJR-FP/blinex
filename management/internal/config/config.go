package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

type Config struct {
	GRPCAddr      string
	HTTPAddr      string
	JWTSecret     string
	LogLevel      string
	NetworkCIDR   string
	DNSSuffix     string
	DatabaseURL   string // postgres DSN; empty = in-memory store
	DefaultKey    string // seed setup key value
	TLSCertFile   string // path to TLS certificate PEM; empty = self-signed
	TLSKeyFile    string // path to TLS private key PEM; empty = self-signed
	TLSStateDir   string // dir to persist the self-signed cert across restarts
	AdminUser     string // dashboard admin username; default "admin"
	AdminPassword string // dashboard admin password; empty = admin login disabled

	BlocklistURL     string // threat-intel feed URL; empty = domain filtering disabled
	BlocklistRefresh string // e.g. "6h" — how often to re-fetch the feed
}

func Load() *Config {
	secret := os.Getenv("MGMT_JWT_SECRET")
	if len(secret) < 32 {
		fmt.Fprintln(os.Stderr, "FATAL: MGMT_JWT_SECRET must be set to at least 32 random characters")
		fmt.Fprintln(os.Stderr, "       Generate one with: openssl rand -hex 32")
		os.Exit(1)
	}

	defaultKey := os.Getenv("BLINEX_DEFAULT_KEY")
	if defaultKey == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: failed to generate random setup key: %v\n", err)
			os.Exit(1)
		}
		defaultKey = "msk-" + hex.EncodeToString(b)
		fmt.Fprintf(os.Stderr, "\n  *** GENERATED SETUP KEY: %s ***\n", defaultKey)
		fmt.Fprintln(os.Stderr, "  Set BLINEX_DEFAULT_KEY to use a fixed key across restarts.")
	}

	return &Config{
		GRPCAddr:      getEnv("MGMT_GRPC_ADDR", ":50051"),
		HTTPAddr:      getEnv("MGMT_HTTP_ADDR", ":8080"),
		JWTSecret:     secret,
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		NetworkCIDR:   getEnv("MGMT_NETWORK_CIDR", "100.64.0.0/10"),
		DNSSuffix:     getEnv("MGMT_DNS_SUFFIX", "blinex"),
		DatabaseURL:   getEnv("DATABASE_URL", ""),
		DefaultKey:    defaultKey,
		TLSCertFile:   getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:    getEnv("TLS_KEY_FILE", ""),
		TLSStateDir:   getEnv("TLS_STATE_DIR", "/var/lib/blinex"),
		AdminUser:     getEnv("MGMT_ADMIN_USER", "admin"),
		AdminPassword: getEnv("MGMT_ADMIN_PASSWORD", ""),

		// Default feed: abuse.ch URLhaus, a public malware/C2 domain hostfile.
		// On by default — set MGMT_BLOCKLIST_URL="" to disable domain filtering.
		BlocklistURL:     getEnv("MGMT_BLOCKLIST_URL", "https://urlhaus.abuse.ch/downloads/hostfile/"),
		BlocklistRefresh: getEnv("MGMT_BLOCKLIST_REFRESH", "6h"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
