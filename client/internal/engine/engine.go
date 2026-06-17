package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	commonv1 "github.com/meshnet/gen/common/v1"
	managementv1 "github.com/meshnet/gen/management/v1"
	signalv1 "github.com/meshnet/gen/signal/v1"
	"github.com/meshnet/client/internal/config"
	"github.com/meshnet/client/internal/dns"
	"github.com/meshnet/client/internal/ice"
	"github.com/meshnet/client/internal/mgmclient"
	"github.com/meshnet/client/internal/peer"
	"github.com/meshnet/client/internal/signalclient"
	"github.com/meshnet/client/internal/state"
	"github.com/meshnet/client/internal/wgmgr"
	"github.com/rs/zerolog/log"
)

// Engine orchestrates the agent.
type Engine struct {
	cfg   *config.Config
	wg    *wgmgr.Manager
	mgm   *mgmclient.Client
	sig   *signalclient.Client
	ice   *ice.Manager
	dns   *dns.Resolver
	peers *peer.Manager
	ctx   context.Context
}

// New creates an Engine. Loads or generates the WireGuard private key from state.
func New(cfg *config.Config) (*Engine, error) {
	_, privKey, err := state.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}

	wg, err := wgmgr.New(cfg.WGInterface, privKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}

	mgm, err := mgmclient.New(cfg.ManagementURL)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("management client: %w", err)
	}

	sig, err := signalclient.New(cfg.SignalURL, wg.PublicKey())
	if err != nil {
		_ = wg.Close()
		_ = mgm.Close()
		return nil, fmt.Errorf("signal client: %w", err)
	}

	iceMgr := ice.New(wg.PublicKey(), cfg.STUNURLs, sig)
	dnsResolver := dns.New("127.0.0.1:53535", "mesh", "8.8.8.8:53")

	return &Engine{
		cfg:   cfg,
		wg:    wg,
		mgm:   mgm,
		sig:   sig,
		ice:   iceMgr,
		dns:   dnsResolver,
		peers: peer.New(),
	}, nil
}

// Run starts the agent and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	e.ctx = ctx
	defer e.wg.Close()
	defer e.mgm.Close()
	defer e.sig.Close()

	// Wire ICE → WireGuard: once ICE establishes a conn, update the endpoint.
	e.ice.OnConnected = func(peerKey, endpoint string, conn net.Conn) {
		if err := e.wg.UpdateEndpoint(peerKey, endpoint, conn); err != nil {
			log.Error().Err(err).Str("peer", shortKey(peerKey)).Msg("endpoint update failed")
		}
	}

	hostname, _ := os.Hostname()
	meta := &commonv1.PeerMeta{
		Hostname:    hostname,
		Os:          runtime.GOOS,
		Kernel:      runtime.GOARCH,
		CoreVersion: "0.1.0",
	}

	loginResp, err := e.enrollWithRetry(ctx, meta)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	if err := e.wg.SetAddress(loginResp.NetworkConfig.Address); err != nil {
		return fmt.Errorf("setting WireGuard address: %w", err)
	}

	log.Info().
		Str("ip", loginResp.NetworkConfig.Address).
		Str("peer_id", loginResp.PeerId).
		Msg("enrolled")

	// Magic DNS.
	go func() {
		if err := e.dns.Serve(); err != nil && ctx.Err() == nil {
			log.Error().Err(err).Msg("DNS resolver error")
		}
	}()

	// Signal client: open stream, register, and dispatch ICE messages.
	sigErrCh := make(chan error, 1)
	go func() {
		err := e.sig.Connect(ctx, func(msg *signalv1.Message) {
			e.ice.HandleSignal(msg)
		})
		sigErrCh <- err
	}()

	// Management sync: receive peer list updates.
	syncErrCh := make(chan error, 1)
	go func() {
		syncErrCh <- e.mgm.Sync(ctx, e.wg.PublicKey(), e.applySync)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-sigErrCh:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("signal error: %w", err)
	case err := <-syncErrCh:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("sync error: %w", err)
	}
}

func (e *Engine) enrollWithRetry(ctx context.Context, meta *commonv1.PeerMeta) (*managementv1.LoginResponse, error) {
	backoff := time.Second
	for {
		resp, err := e.mgm.Login(ctx, e.cfg.SetupKey, e.wg.PublicKey(), meta)
		if err == nil {
			return resp, nil
		}
		log.Warn().Err(err).Dur("retry_in", backoff).Msg("enrollment failed, retrying")
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func (e *Engine) applySync(resp *managementv1.SyncResponse) error {
	added, updated, removed := e.peers.Diff(resp.Peers)
	selfKey := e.wg.PublicKey()

	for _, p := range added {
		if p.WgPubKey == selfKey {
			continue
		}
		if err := e.wg.UpsertPeer(p.WgPubKey, p.AllowedIps, ""); err != nil {
			log.Warn().Err(err).Str("peer", p.Id).Msg("add peer failed")
		}
		e.dns.Upsert(p.DnsLabel, p.Ip)
		e.ice.StartConnect(e.ctx, p.WgPubKey)
		log.Info().Str("peer", p.Hostname).Str("ip", p.Ip).Msg("peer added, ICE starting")
	}

	for _, p := range updated {
		if p.WgPubKey == selfKey {
			continue
		}
		if err := e.wg.UpsertPeer(p.WgPubKey, p.AllowedIps, ""); err != nil {
			log.Warn().Err(err).Str("peer", p.Id).Msg("update peer failed")
		}
		e.dns.Upsert(p.DnsLabel, p.Ip)
	}

	for _, p := range removed {
		if p.WgPubKey == selfKey {
			continue
		}
		if err := e.wg.RemovePeer(p.WgPubKey); err != nil {
			log.Warn().Err(err).Str("peer", p.Id).Msg("remove peer failed")
		}
		e.dns.Remove(p.DnsLabel)
		e.ice.ClosePeer(p.WgPubKey)
		log.Info().Str("peer", p.Hostname).Msg("peer removed")
	}

	return nil
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}
