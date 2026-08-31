package grpcserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/blinex/management/internal/auth"
	"github.com/blinex/management/internal/domain"
	"github.com/blinex/management/internal/geoip"
	"github.com/blinex/management/internal/store"
	commonv1 "github.com/blinex/gen/common/v1"
	managementv1 "github.com/blinex/gen/management/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// syncSub is a channel that receives peer-list updates for one connected peer.
type syncSub struct {
	peerKey   string
	accountID string
	ch        chan struct{}
}

// Server implements the ManagementService gRPC interface.
type Server struct {
	managementv1.UnimplementedManagementServiceServer
	store       store.Store
	auth        *auth.Manager
	ipam        *IPAM
	network     string // full mesh CIDR, e.g. "100.64.0.0/10"
	dns         string // dns suffix, e.g. "blinex"
	loginLimits *rateLimiter

	subsMu sync.RWMutex
	subs   map[string]*syncSub // wgPubKey → subscriber
}

func New(st store.Store, authMgr *auth.Manager, ipam *IPAM, networkCIDR, dnsSuffix string) *Server {
	return &Server{
		store:       st,
		auth:        authMgr,
		ipam:        ipam,
		network:     networkCIDR,
		dns:         dnsSuffix,
		subs:        make(map[string]*syncSub),
		loginLimits: newRateLimiter(),
	}
}

func (s *Server) GetServerKey(_ context.Context, _ *managementv1.GetServerKeyRequest) (*managementv1.GetServerKeyResponse, error) {
	// TODO: replace with a real WireGuard key pair loaded from config/disk.
	return &managementv1.GetServerKeyResponse{Key: "SERVER_WG_PUBLIC_KEY_PLACEHOLDER"}, nil
}

func (s *Server) Login(ctx context.Context, req *managementv1.LoginRequest) (*managementv1.LoginResponse, error) {
	// Rate limit by source IP: 5 attempts per 60 seconds. Key on the host only —
	// the ephemeral source port differs on every dial, so including it would let
	// a caller bypass the limit by reconnecting.
	peerIP := sourceIP(ctx)
	if !s.loginLimits.Allow(peerIP) {
		return nil, status.Error(codes.ResourceExhausted, "too many login attempts, please try again later")
	}

	if req.SetupKey == "" || req.WgPubKey == "" {
		return nil, status.Error(codes.InvalidArgument, "setup_key and wg_pub_key are required")
	}

	sk, err := s.store.GetSetupKey(ctx, req.SetupKey)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired setup key")
	}
	if sk.Ephemeral && sk.UsedCount > 0 {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired setup key")
	}

	// Allocate a stable IP for this public key.
	ip, err := s.ipam.Allocate(req.WgPubKey)
	if err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "IP allocation failed: %v", err)
	}

	hostname := ""
	os := ""
	kernel := ""
	coreVersion := ""
	localIP := ""
	if req.Meta != nil {
		hostname = req.Meta.Hostname
		os = req.Meta.Os
		kernel = req.Meta.Kernel
		coreVersion = req.Meta.CoreVersion
		localIP = req.Meta.LocalIp
	}

	// Every peer is always in Default, regardless of enrollment path. A
	// setup key can additionally drop a first-time enrollee straight into
	// its own group(s), same as NetBird's auto-groups.
	groups := []string{domain.DefaultGroupName}
	for _, g := range sk.AutoGroups {
		if g != domain.DefaultGroupName {
			groups = append(groups, g)
		}
	}

	peer := &domain.Peer{
		ID:         uuid.NewString(),
		AccountID:  sk.AccountID,
		WGPubKey:   req.WgPubKey,
		IP:         ip,
		LocalIP:    localIP,
		PublicIP:   peerIP,
		Hostname:   hostname,
		OS:         os,
		Kernel:     kernel,
		Version:    coreVersion,
		DNSLabel:   toDNSLabel(hostname),
		Groups:     groups,
		AllowedIPs: []string{ip + "/32"},
		LastSeen:   time.Now(),
		CreatedAt:  time.Now(),
	}

	if existing, err := s.store.GetPeer(ctx, req.WgPubKey); err == nil {
		// A WireGuard public key is not secret. Refuse to re-enroll a key that
		// already belongs to a different account, which would otherwise let a
		// holder of one account's setup key hijack another account's peer record.
		if existing.AccountID != sk.AccountID {
			return nil, status.Error(codes.PermissionDenied, "public key already enrolled in another account")
		}
		// Re-enrollment: preserve the existing peer ID and IP.
		peer.ID = existing.ID
		peer.CreatedAt = existing.CreatedAt
		// Preserve operator-managed fields that enrollment must not reset —
		// re-applying the setup key's auto-groups here would silently
		// resurrect a group an operator deliberately removed the peer from.
		peer.Groups = existing.Groups
		peer.AdvertisedRoutes = existing.AdvertisedRoutes
	}

	if err := s.store.SavePeer(ctx, peer); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save peer: %v", err)
	}
	if err := s.store.IncrementSetupKeyUsage(ctx, sk.ID); err != nil {
		log.Warn().Err(err).Msg("failed to increment setup key usage")
	}
	s.resolveCountryAsync(peer.WGPubKey, peer.PublicIP)

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
	// Verify the caller's token matches the key they claim to be.
	if claims := claimsFromContext(stream.Context()); claims != nil && claims.WGPubKey != req.WgPubKey {
		return status.Error(codes.PermissionDenied, "wg_pub_key does not match token")
	}

	peer, err := s.store.GetPeer(stream.Context(), req.WgPubKey)
	if err != nil {
		return status.Errorf(codes.NotFound, "peer not registered: %v", err)
	}

	sub := &syncSub{peerKey: req.WgPubKey, accountID: peer.AccountID, ch: make(chan struct{}, 1)}
	s.registerSub(req.WgPubKey, sub)
	s.touchLastSeen(stream.Context(), peer)
	if ip := sourceIP(stream.Context()); ip != "" && ip != "unknown" && ip != peer.PublicIP {
		peer.PublicIP = ip
		if err := s.store.SavePeer(stream.Context(), peer); err == nil {
			s.resolveCountryAsync(peer.WGPubKey, ip)
		}
	}
	defer func() {
		s.unregisterSub(req.WgPubKey)
		// Record the disconnect time so the dashboard can show "last seen".
		s.touchLastSeen(context.Background(), peer)
		// Notify other peers so the dashboard refreshes connection state.
		s.notifyAll(peer.AccountID)
	}()

	// Send the current state immediately, then stream updates.
	send := func() error {
		peers, err := s.store.GetPeersByAccount(stream.Context(), peer.AccountID)
		if err != nil {
			return fmt.Errorf("listing peers: %w", err)
		}
		rules, err := s.store.GetRulesByAccount(stream.Context(), peer.AccountID)
		if err != nil {
			return fmt.Errorf("listing rules: %w", err)
		}
		resp := s.buildSyncResponse(peers, rules)
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
	if claims := claimsFromContext(ctx); claims != nil && claims.WGPubKey != req.WgPubKey {
		return nil, status.Error(codes.PermissionDenied, "wg_pub_key does not match token")
	}
	peer, err := s.store.GetPeer(ctx, req.WgPubKey)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not found: %v", err)
	}
	if req.Meta != nil {
		peer.Hostname = req.Meta.Hostname
		peer.OS = req.Meta.Os
		peer.Kernel = req.Meta.Kernel
		peer.Version = req.Meta.CoreVersion
		peer.DNSLabel = toDNSLabel(req.Meta.Hostname)
		if req.Meta.LocalIp != "" {
			peer.LocalIP = req.Meta.LocalIp
		}
	}
	peer.LastSeen = time.Now()
	if err := s.store.SavePeer(ctx, peer); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update peer: %v", err)
	}
	return &managementv1.UpdatePeerMetaResponse{}, nil
}

func (s *Server) buildSyncResponse(peers []*domain.Peer, domainRules []*domain.Rule) *managementv1.SyncResponse {
	var pbPeers []*commonv1.Peer
	var routes []*commonv1.Route

	// Build group → IPs index for resolving group-based rules.
	groupIPs := make(map[string][]string)
	for _, p := range peers {
		for _, g := range p.Groups {
			groupIPs[g] = append(groupIPs[g], p.IP)
		}
	}

	for _, p := range peers {
		allowedIPs := make([]string, 0, len(p.AllowedIPs)+len(p.AdvertisedRoutes))
		allowedIPs = append(allowedIPs, p.AllowedIPs...)
		allowedIPs = append(allowedIPs, p.AdvertisedRoutes...)

		pbPeers = append(pbPeers, &commonv1.Peer{
			Id:         p.ID,
			WgPubKey:   p.WGPubKey,
			Ip:         p.IP,
			Hostname:   p.Hostname,
			Os:         p.OS,
			AllowedIps: allowedIPs,
			DnsLabel:   p.DNSLabel,
			LocalIp:    p.LocalIP,
			PublicIp:   p.PublicIP,
			Country:    p.Country,
		})

		for i, cidr := range p.AdvertisedRoutes {
			routes = append(routes, &commonv1.Route{
				Id:      fmt.Sprintf("%s:%d", p.WGPubKey, i),
				Network: cidr,
				Gateway: p.WGPubKey,
				Metric:  100,
				Enabled: true,
			})
		}
	}

	var pbRules []*commonv1.Rule
	for _, r := range domainRules {
		expanded := expandGroupRule(r, groupIPs)
		for _, er := range expanded {
			pbRules = append(pbRules, &commonv1.Rule{
				Id:       er.ID,
				Name:     er.Name,
				Src:      er.Src,
				Dst:      er.Dst,
				Protocol: er.Protocol,
				Port:     int32(er.Port),
				Action:   er.Action,
				Enabled:  er.Enabled,
				Priority: int32(er.Priority),
			})
		}
	}

	return &managementv1.SyncResponse{
		Peers:  pbPeers,
		Routes: routes,
		Rules:  pbRules,
		Serial: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

func expandGroupRule(r *domain.Rule, groupIPs map[string][]string) []*domain.Rule {
	srcGroup := strings.TrimPrefix(r.Src, "group:")
	dstGroup := strings.TrimPrefix(r.Dst, "group:")
	hasSrcGroup := strings.HasPrefix(r.Src, "group:")
	hasDstGroup := strings.HasPrefix(r.Dst, "group:")

	if !hasSrcGroup && !hasDstGroup {
		return []*domain.Rule{r}
	}

	srcIPs := []string{r.Src}
	if hasSrcGroup {
		srcIPs = groupIPs[srcGroup]
		if len(srcIPs) == 0 {
			return nil
		}
	}

	dstIPs := []string{r.Dst}
	if hasDstGroup {
		dstIPs = groupIPs[dstGroup]
		if len(dstIPs) == 0 {
			return nil
		}
	}

	var out []*domain.Rule
	for _, s := range srcIPs {
		for _, d := range dstIPs {
			expanded := *r
			expanded.Src = s
			expanded.Dst = d
			out = append(out, &expanded)
		}
	}
	return out
}

// NotifyAccount triggers a sync push to all connected peers in the account.
func (s *Server) NotifyAccount(accountID string) {
	s.notifyAll(accountID)
}

// ReleaseIP returns a deleted peer's leased mesh IP to the IPAM pool.
func (s *Server) ReleaseIP(wgPubKey string) {
	s.ipam.Release(wgPubKey)
}

func (s *Server) notifyAll(accountID string) {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	for _, sub := range s.subs {
		if sub.accountID != accountID {
			continue
		}
		select {
		case sub.ch <- struct{}{}:
		default:
		}
	}
}

// touchLastSeen updates a peer's LastSeen timestamp to now (best-effort).
func (s *Server) touchLastSeen(ctx context.Context, peer *domain.Peer) {
	fresh, err := s.store.GetPeer(ctx, peer.WGPubKey)
	if err != nil {
		return
	}
	fresh.LastSeen = time.Now()
	_ = s.store.SavePeer(ctx, fresh)
}

// ConnectedKeys returns the set of WireGuard public keys with an active Sync
// stream — i.e. the peers currently connected to the control plane.
func (s *Server) ConnectedKeys() map[string]bool {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	out := make(map[string]bool, len(s.subs))
	for key := range s.subs {
		out[key] = true
	}
	return out
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

// sourceIP extracts the caller's source IP from the gRPC peer context.
func sourceIP(ctx context.Context) string {
	p, ok := grpcpeer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
		return host
	}
	return p.Addr.String()
}

// resolveCountryAsync looks up ip's country and persists it on the peer
// identified by wgPubKey, without blocking the caller. Private/loopback/
// unresolvable IPs are skipped — geoIP has nothing useful to say about them.
func (s *Server) resolveCountryAsync(wgPubKey, ip string) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsUnspecified() {
		return
	}
	go func() {
		country, err := geoip.Lookup(ip)
		if err != nil {
			log.Debug().Err(err).Str("ip", ip).Msg("geoip lookup failed")
			return
		}
		peer, err := s.store.GetPeer(context.Background(), wgPubKey)
		if err != nil || peer.PublicIP != ip {
			return // peer gone, or public IP already moved on — stale result
		}
		peer.Country = country
		if err := s.store.SavePeer(context.Background(), peer); err != nil {
			log.Warn().Err(err).Msg("failed to save resolved country")
		}
	}()
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
