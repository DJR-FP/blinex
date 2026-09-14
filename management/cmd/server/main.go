package main

import (
	"context"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	managementv1 "github.com/blinex/gen/management/v1"
	"github.com/blinex/management/internal/auth"
	"github.com/blinex/management/internal/blocklist"
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

// grpcKeepalive lets clients ping often enough to notice a silently dead
// connection, and has the server do the same in the other direction.
//
// EnforcementPolicy is the half that is easy to miss: a server rejects pings
// more frequent than MinTime (default 5 minutes) with GOAWAY
// ENHANCE_YOUR_CALM and closes the connection — so shipping client keepalive
// without this would break the connections it is meant to protect. MinTime is
// held below the clients' 30s interval to leave room for jitter.
//
// ServerParameters make detection mutual: without it the server keeps dead
// streams and their subscriptions alive until the OS eventually times the
// socket out. Deliberately no MaxConnectionIdle or MaxConnectionAge — the
// Sync and signal streams are meant to stay open and idle for hours.
var grpcEnforcementPolicy = keepalive.EnforcementPolicy{
	MinTime:             10 * time.Second,
	PermitWithoutStream: true,
}

var grpcServerParams = keepalive.ServerParameters{
	Time:    30 * time.Second,
	Timeout: 10 * time.Second,
}

func grpcKeepalive() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(grpcEnforcementPolicy),
		grpc.KeepaliveParams(grpcServerParams),
	}
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", version).Msg("blinex management starting")

	cfg := config.Load()

	tlsCfg, selfSigned, err := tlsconfig.Load(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSStateDir)
	if err != nil {
		log.Fatal().Err(err).Msg("TLS setup failed")
	}
	if selfSigned {
		log.Warn().Msg("using persistent self-signed TLS certificate (set TLS_CERT_FILE + TLS_KEY_FILE for a real cert)")
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

	blocklistRefresh, err := time.ParseDuration(cfg.BlocklistRefresh)
	if err != nil {
		log.Warn().Err(err).Str("value", cfg.BlocklistRefresh).Msg("invalid MGMT_BLOCKLIST_REFRESH, defaulting to 6h")
		blocklistRefresh = 6 * time.Hour
	}
	blocklistStore := blocklist.NewStore()
	go blocklistStore.Run(context.Background(), cfg.BlocklistURL, blocklistRefresh)

	grpcSrv := grpcserver.New(st, authMgr, ipam, cfg.NetworkCIDR, cfg.DNSSuffix, blocklistStore)
	httpSrv := httpserver.New(st, authMgr, grpcSrv.NotifyAccount, grpcSrv.ConnectedKeys, grpcSrv.ReleaseIP, version, cfg.AdminUser, cfg.AdminPassword)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", cfg.GRPCAddr).Msg("failed to listen")
	}

	grpcOpts := append([]grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.StreamInterceptor(grpcserver.AuthStreamInterceptor(authMgr)),
		grpc.UnaryInterceptor(grpcserver.AuthUnaryInterceptor(authMgr)),
	}, grpcKeepalive()...)
	s := grpc.NewServer(grpcOpts...)
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
