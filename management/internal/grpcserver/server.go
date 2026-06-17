package grpcserver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/meshnet/management/internal/auth"
	"github.com/meshnet/management/internal/domain"
	"github.com/meshnet/management/internal/store"
	commonv1 "github.com/meshnet/gen/common/v1"
	managementv1 "github.com/meshnet/gen/management/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// syncSub is a channel that receives peer-list updates for one connected peer.
type syncSub struct {
	peerKey string
	ch      chan struct{}
}

// Server implements the ManagementService gRPC interface.
type Server struct {
	managementv1.UnimplementedManagementServiceServer
	store   store.Store
	auth    *auth.Manager
	ipam    *IPAM
	network string // full mesh CIDR, e.g. "100.64.0.0/10"
	dns     string // dns suffix, e.g. "mesh"

	subsMu sync.RWMutex
	subs   map[string]*syncSub // wgPubKey → subscriber
}

func New(st store.Store, authMgr *auth.Manager, ipam *IPAM, networkCIDR, dnsSuffix string) *Server {
	return &Server{
		store:   st,
		auth:    authMgr,
		ipam:    ipam,
		network: networkCIDR,
		dns:     dnsSuffix,
		subs:    make(map[string]*syncSub),
	}
}

func (s *Server) GetServerKey(_ context.Context, _ *managementv1.GetServerKeyRequest) (*managementv1.GetServerKeyResponse, error) {
	// TODO: replace with a real WireGuard key pair loaded from config/disk.
	return &managementv1.GetServerKeyResponse{Key: "SERVER_WG_PUBLIC_KEY_PLACEHOLDER"}, nil
}

func (s *Server) Login(ctx context.Context, req *managementv1.LoginRequest) (*managementv1.LoginResponse, error) {
	if req.SetupKey == "" || req.WgPubKey == "" {
		return nil, status.Error(codes.InvalidArgument, "setup_key and wg_pub_key are required")
	}

	sk, err := s.store.GetSetupKey(ctx, req.SetupKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid setup key: %v", err)
	}

	// Allocate a stable IP for this public key.
	ip, err := s.ipam.Allocate(req.WgPubKey)
	if err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "IP allocation failed: %v", err)
	}

	hostname := ""
	os := ""
	if req.Meta != nil {
		hostname = req.Meta.Hostname
		os = req.Meta.Os
	}

	peer := &domain.Peer{
		ID:         uuid.NewString(),
		AccountID:  sk.AccountID,
		WGPubKey:   req.WgPubKey,
		IP:         ip,
		Hostname:   hostname,
		OS:         os,
		DNSLabel:   toDNSLabel(hostname),
		AllowedIPs: []string{ip + "/32"},
		LastSeen:   time.Now(),
		CreatedAt:  time.Now(),
	}

	if existing, err := s.store.GetPeer(ctx, req.WgPubKey); err == nil {
		// Re-enrollment: preserve the existing peer ID and IP.
		peer.ID = existing.ID
		peer.CreatedAt = existing.CreatedAt
	}

	if err := s.store.SavePeer(ctx, peer); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save peer: %v", err)
	}
	if err := s.store.IncrementSetupKeyUsage(ctx, sk.ID); err != nil {
		log.Warn().Err(err).Msg("failed to increment setup key usage")
	}

	s.notifyAll(peer.AccountID)

	token, err := s.auth.IssueToken(peer.ID, peer.WGPubKey, peer.AccountID)
	if err != nil {
		log.Warn().Err(err).Msg("failed to create peer token")
	}

	return &managementv1.LoginResponse{
		PeerId: peer.ID,
		Token:  token,
		NetworkConfig: &commonv1.NetworkConfig{
			Address: ip + "/32",
			Network: s.network,
			Serial:  fmt.Sprintf("%d", time.Now().UnixNano()),
		},
	}, nil
}

func (s *Server) Sync(req *managementv1.SyncRequest, stream managementv1.ManagementService_SyncServer) error {
	if req.WgPubKey == "" {
		return status.Error(codes.InvalidArgument, "wg_pub_key is required")
	}

	peer, err := s.store.GetPeer(stream.Context(), req.WgPubKey)
	if err != nil {
		return status.Errorf(codes.NotFound, "peer not registered: %v", err)
	}

	sub := &syncSub{peerKey: req.WgPubKey, ch: make(chan struct{}, 1)}
	s.registerSub(req.WgPubKey, sub)
	defer s.unregisterSub(req.WgPubKey)

	// Send the current state immediately, then stream updates.
	send := func() error {
		peers, err := s.store.GetPeersByAccount(stream.Context(), peer.AccountID)
		if err != nil {
			return fmt.Errorf("listing peers: %w", err)
		}
		resp := s.buildSyncResponse(peers)
		return stream.Send(resp)
	}

	if err := send(); err != nil {
		return status.Errorf(codes.Internal, "initial sync failed: %v", err)
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-sub.ch:
			if err := send(); err != nil {
				return status.Errorf(codes.Internal, "sync push failed: %v", err)
			}
		}
	}
}

func (s *Server) UpdatePeerMeta(ctx context.Context, req *managementv1.UpdatePeerMetaRequest) (*managementv1.UpdatePeerMetaResponse, error) {
	if req.WgPubKey == "" {
		return nil, status.Error(codes.InvalidArgument, "wg_pub_key is required")
	}
	peer, err := s.store.GetPeer(ctx, req.WgPubKey)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not found: %v", err)
	}
	if req.Meta != nil {
		peer.Hostname = req.Meta.Hostname
		peer.OS = req.Meta.Os
		peer.Kernel = req.Meta.Kernel
		peer.DNSLabel = toDNSLabel(req.Meta.Hostname)
	}
	peer.LastSeen = time.Now()
	if err := s.store.SavePeer(ctx, peer); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update peer: %v", err)
	}
	return &managementv1.UpdatePeerMetaResponse{}, nil
}

func (s *Server) buildSyncResponse(peers []*domain.Peer) *managementv1.SyncResponse {
	var pbPeers []*commonv1.Peer
	for _, p := range peers {
		pbPeers = append(pbPeers, &commonv1.Peer{
			Id:         p.ID,
			WgPubKey:   p.WGPubKey,
			Ip:         p.IP,
			Hostname:   p.Hostname,
			Os:         p.OS,
			AllowedIps: p.AllowedIPs,
			DnsLabel:   p.DNSLabel,
		})
	}
	return &managementv1.SyncResponse{
		Peers:  pbPeers,
		Serial: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

func (s *Server) notifyAll(accountID string) {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	for _, sub := range s.subs {
		select {
		case sub.ch <- struct{}{}:
		default:
		}
	}
}

func (s *Server) registerSub(key string, sub *syncSub) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	s.subs[key] = sub
}

func (s *Server) unregisterSub(key string) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	delete(s.subs, key)
}

func toDNSLabel(hostname string) string {
	label := strings.ToLower(hostname)
	label = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, label)
	label = strings.Trim(label, "-")
	if label == "" {
		label = "peer-" + uuid.NewString()[:8]
	}
	return label
}
