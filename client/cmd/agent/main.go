package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/blinex/client/internal/config"
	"github.com/blinex/client/internal/engine"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "", "path to agent config JSON (default: /etc/blinex/agent.json)")
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("blinex agent starting")

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise engine")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info().Msg("blinex agent starting")
	if err := eng.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal().Err(err).Msg("agent error")
	}
	log.Info().Msg("agent stopped")
}
