package main

import (
	"context"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	managementv1 "github.com/blinex/gen/management/v1"
	"github.com/blinex/management/internal/auth"
	"github.com/blinex/management/internal/config"
	"github.com/blinex/management/internal/grpcserver"
	"github.com/blinex/management/internal/httpserver"
	"github.com/blinex/management/internal/store"
	"github.com/blinex/management/internal/store/memory"
	"github.com/blinex/management/internal/store/postgres"
	"github.com/blinex/management/internal/tlsconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// version is injected at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("blinex management starting")

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
		st = memory.New(cfg.DefaultKey)
		log.Info().Msg("using in-memory store (set DATABASE_URL for persistence)")
	}

	authMgr := auth.NewManager(cfg.JWTSecret)

	ipam, err := grpcserver.NewIPAM(cfg.NetworkCIDR)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise IPAM")
	}

	// Restore IPAM state from persisted peers so IPs are not re-allocated after restart.
	allPeers, err := st.GetAllPeers(context.Background())
	if err != nil {
		log.Warn().Err(err).Msg("failed to preload IPAM from existing peers")
	} else {
		ipam.PreloadPeers(allPeers)
		log.Info().Int("peers", len(allPeers)).Msg("IPAM restored from existing peers")
	}

	grpcSrv := grpcserver.New(st, authMgr, ipam, cfg.NetworkCIDR, cfg.DNSSuffix)
	httpSrv := httpserver.New(st, authMgr, grpcSrv.NotifyAccount, grpcSrv.ConnectedKeys, version, cfg.AdminUser, cfg.AdminPassword)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", cfg.GRPCAddr).Msg("failed to listen")
	}

	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.StreamInterceptor(grpcserver.AuthStreamInterceptor(authMgr)),
		grpc.UnaryInterceptor(grpcserver.AuthUnaryInterceptor(authMgr)),
	)
	managementv1.RegisterManagementServiceServer(s, grpcSrv)
	if os.Getenv("GRPC_REFLECTION") == "true" {
		reflection.Register(s)
		log.Info().Msg("gRPC reflection enabled")
	}

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
