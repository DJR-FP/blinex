package main

import (
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	signalv1 "github.com/blinex/gen/signal/v1"
	signalauth "github.com/blinex/signal/internal/auth"
	"github.com/blinex/signal/internal/server"
	"github.com/blinex/signal/internal/tlsconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var version = "dev"

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("blinex signal starting")

	addr := getEnv("SIGNAL_ADDR", ":10000")

	tlsCfg, selfSigned, err := tlsconfig.Load(
		getEnv("TLS_CERT_FILE", ""),
		getEnv("TLS_KEY_FILE", ""),
		getEnv("TLS_STATE_DIR", "/var/lib/blinex"),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("TLS setup failed")
	}
	if selfSigned {
		log.Warn().Msg("using persistent self-signed TLS certificate (set TLS_CERT_FILE + TLS_KEY_FILE for a real cert)")
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", addr).Msg("failed to listen")
	}

	opts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))}
	jwtSecret := os.Getenv("MGMT_JWT_SECRET")
	if jwtSecret != "" {
		opts = append(opts, grpc.StreamInterceptor(signalauth.StreamInterceptor(jwtSecret)))
		log.Info().Msg("signal: JWT authentication enabled")
	} else {
		log.Warn().Msg("signal: MGMT_JWT_SECRET not set — connections are unauthenticated")
	}

	s := grpc.NewServer(opts...)
	signalv1.RegisterSignalServiceServer(s, server.New())
	if os.Getenv("GRPC_REFLECTION") == "true" {
		reflection.Register(s)
	}

	log.Info().Str("addr", addr).Msg("gRPC/TLS signal server starting")
	if err := s.Serve(lis); err != nil {
		log.Fatal().Err(err).Msg("signal server error")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
