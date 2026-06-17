package main

import (
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	managementv1 "github.com/meshnet/gen/management/v1"
	"github.com/meshnet/management/internal/auth"
	"github.com/meshnet/management/internal/config"
	"github.com/meshnet/management/internal/grpcserver"
	"github.com/meshnet/management/internal/httpserver"
	"github.com/meshnet/management/internal/store"
	"github.com/meshnet/management/internal/store/memory"
	"github.com/meshnet/management/internal/store/postgres"
	"github.com/meshnet/management/internal/tlsconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// version is injected at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("meshnet management starting")

	cfg := config.Load()

	tlsCfg, selfSigned, err := tlsconfig.Load(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		log.Fatal().Err(err).Msg("TLS setup failed")
	}
	if selfSigned {
		log.Warn().Msg("using self-signed TLS certificate — set TLS_CERT_FILE + TLS_KEY_FILE for production")
	}

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
	httpSrv := httpserver.New(st, authMgr, grpcSrv.NotifyAccount, version)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", cfg.GRPCAddr).Msg("failed to listen")
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	managementv1.RegisterManagementServiceServer(s, grpcSrv)
	reflection.Register(s)

	go func() {
		log.Info().Str("addr", cfg.GRPCAddr).Msg("gRPC/TLS server starting")
		if err := s.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("gRPC server error")
		}
	}()

	if err := httpSrv.Run(cfg.HTTPAddr, tlsCfg); err != nil {
		log.Fatal().Err(err).Msg("HTTPS server error")
	}
}
