package main

import (
	"os"
	"strconv"

	"github.com/meshnet/relay/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var version = "dev"

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("meshnet relay starting")

	cfg := server.Config{
		PublicIP: getEnv("RELAY_PUBLIC_IP", "127.0.0.1"),
		UDPPort:  getEnvInt("RELAY_UDP_PORT", 3478),
		Realm:    getEnv("RELAY_REALM", "meshnet.io"),
		AuthUser: getEnv("RELAY_AUTH_USER", "meshnet"),
		AuthPass: getEnv("RELAY_AUTH_PASS", "change-me"),
	}

	log.Info().Str("ip", cfg.PublicIP).Int("port", cfg.UDPPort).Msg("relay server starting")
	if err := server.Start(cfg); err != nil {
		log.Fatal().Err(err).Msg("relay server error")
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
