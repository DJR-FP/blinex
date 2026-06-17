package main

import (
	"net"
	"os"

	managementv1 "github.com/meshnet/gen/management/v1"
	"github.com/meshnet/management/internal/auth"
	"github.com/meshnet/management/internal/config"
	"github.com/meshnet/management/internal/grpcserver"
	"github.com/meshnet/management/internal/httpserver"
	"github.com/meshnet/management/internal/store"
	"github.com/meshnet/management/internal/store/memory"
	"github.com/meshnet/management/internal/store/postgres"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg := config.Load()

	var st store.Store
	if cfg.DatabaseURL != "" {
		pgStore, err := postgres.New(cfg.DatabaseURL)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to connect to postgres")
		}
		if err := pgStore.Seed("default", cfg.DefaultKey); err != nil {
			log.Fatal().Err(err).Msg("failed to seed database")
		}
		st = pgStore
		log.Info().Msg("using PostgreSQL store")
	} else {
		st = memory.New()
		log.Info().Msg("using in-memory store (set DATABASE_URL for persistence)")
	}

	authMgr := auth.NewManager(cfg.JWTSecret)

	ipam, err := grpcserver.NewIPAM(cfg.NetworkCIDR)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise IPAM")
	}

	grpcSrv := grpcserver.New(st, authMgr, ipam, cfg.NetworkCIDR, cfg.DNSSuffix)
	httpSrv := httpserver.New(st, authMgr)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", cfg.GRPCAddr).Msg("failed to listen")
	}

	s := grpc.NewServer()
	managementv1.RegisterManagementServiceServer(s, grpcSrv)
	reflection.Register(s)

	go func() {
		log.Info().Str("addr", cfg.GRPCAddr).Msg("gRPC server starting")
		if err := s.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("gRPC server error")
		}
	}()

	if err := httpSrv.Run(cfg.HTTPAddr); err != nil {
		log.Fatal().Err(err).Msg("HTTP server error")
	}
}
