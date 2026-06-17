package main

import (
	"net"
	"os"

	signalv1 "github.com/meshnet/gen/signal/v1"
	"github.com/meshnet/signal/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	addr := getEnv("SIGNAL_ADDR", ":10000")

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", addr).Msg("failed to listen")
	}

	s := grpc.NewServer()
	signalv1.RegisterSignalServiceServer(s, server.New())
	reflection.Register(s)

	log.Info().Str("addr", addr).Msg("signal server starting")
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
