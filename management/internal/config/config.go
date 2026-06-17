package config

import (
	"os"
	"strconv"
)

type Config struct {
	GRPCAddr    string
	HTTPAddr    string
	JWTSecret   string
	LogLevel    string
	NetworkCIDR string
	DNSSuffix   string
	DatabaseURL string // postgres DSN; empty = in-memory store
	DefaultKey  string // seed setup key value
}

func Load() *Config {
	return &Config{
		GRPCAddr:    getEnv("MGMT_GRPC_ADDR", ":50051"),
		HTTPAddr:    getEnv("MGMT_HTTP_ADDR", ":8080"),
		JWTSecret:   getEnv("MGMT_JWT_SECRET", "change-me-in-production"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		NetworkCIDR: getEnv("MGMT_NETWORK_CIDR", "100.64.0.0/10"),
		DNSSuffix:   getEnv("MGMT_DNS_SUFFIX", "mesh"),
		DatabaseURL: getEnv("DATABASE_URL", ""),
		DefaultKey:  getEnv("MESHNET_DEFAULT_KEY", "MESHNET-DEFAULT-KEY"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
