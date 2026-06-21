package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	commonv1 "github.com/meshnet/gen/common/v1"
	managementv1 "github.com/meshnet/gen/management/v1"
	signalv1 "github.com/meshnet/gen/signal/v1"
	"github.com/meshnet/client/internal/acl"
	"github.com/meshnet/client/internal/config"
	"github.com/meshnet/client/internal/dns"
	"github.com/meshnet/client/internal/ice"
	"github.com/meshnet/client/internal/mgmclient"
	"github.com/meshnet/client/internal/peer"
	"github.com/meshnet/client/internal/routing"
	"github.com/meshnet/client/internal/signalclient"
	"github.com/meshnet/client/internal/state"
	"github.com/meshnet/client/internal/wgmgr"
	"github.com/rs/zerolog/log"
)

// exitNodeState holds the routing state installed when an exit node is active.
type exitNodeState struct {
	gwIP    net.IP
	gwIface string
	hostIPs []net.IP // management + signal IPs pinned via original gateway
}

// Engine orchestrates the agent.
type Engine struct {
	cfg           *config.Config
	wg            *wgmgr.Manager
	mgm           *mgmclient.Client
	sig           *signalclient.Client
	ice           *ice.Manager
	dns           *dns.Resolver
	peers         *peer.Manager
	forwarder     *wgmgr.Forwarder
	appliedRoutes map[string][]string // peerKey → route CIDRs currently installed in OS
	exitNode      *exitNodeState      // non-nil when exit node routing is active
	ctx           context.Context
}

// New creates an Engine. Loads or generates the WireGuard private key from state.
func New(cfg *config.Config) (*Engine, error) {
	st, privKey, err := state.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}

	mgmTLS, sigTLS, err := buildTLSConfigs(cfg, st)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}

	wg, err := wgmgr.New(cfg.WGInterface, privKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}

	mgm, err := mgmclient.New(cfg.ManagementURL, mgmTLS)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("management client: %w", err)
	}

	sig, err := signalclient.New(cfg.SignalURL, wg.PublicKey(), sigTLS)
	if err != nil {
		_ = wg.Close()
		_ = mgm.Close()
		return nil, fmt.Errorf("signal client: %w", err)
	}

	iceMgr := ice.New(wg.PublicKey(), cfg.STUNURLs, sig)
	dnsResolver := dns.New("127.0.0.1:53535", "mesh", cfg.DNSUpstream)

	return &Engine{
		cfg:           cfg,
		wg:            wg,
		mgm:           mgm,
		sig:           sig,
		ice:           iceMgr,
		dns:           dnsResolver,
		peers:         peer.New(),
		appliedRoutes: make(map[string][]string),
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

	// In netstack mode, start the transparent forwarder so local processes
	// can reach mesh peers via iptables REDIRECT.
	if e.wg.NetstackMode() {
		meshCIDR := guessMeshCIDR(loginResp.NetworkConfig.Address)
		fwd := wgmgr.NewForwarder(e.wg.NetstackNet(), meshCIDR)
		if err := fwd.Start(ctx); err != nil {
			log.Warn().Err(err).Msg("netstack forwarder failed to start — mesh may not be reachable from local processes")
		} else {
			e.forwarder = fwd
			defer fwd.Stop()
		}
	}

	log.Info().
		Str("ip", loginResp.NetworkConfig.Address).
		Str("peer_id", loginResp.PeerId).
		Bool("netstack", e.wg.NetstackMode()).
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
		err := e.sig.Connect(ctx, loginResp.Token, func(msg *signalv1.Message) {
			e.ice.HandleSignal(msg)
		})
		sigErrCh <- err
	}()

	// Management sync: receive peer list updates.
	syncErrCh := make(chan error, 1)
	go func() {
		syncErrCh <- e.mgm.Sync(ctx, loginResp.Token, e.wg.PublicKey(), e.applySync)
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
	selfKey := e.wg.PublicKey()

	// Build gateway → route CIDRs map from this sync response.
	routesByGateway := make(map[string][]string)
	for _, r := range resp.Routes {
		if r.Enabled {
			routesByGateway[r.Gateway] = append(routesByGateway[r.Gateway], r.Network)
		}
	}

	// OS-level routing and exit node support require a kernel TUN interface.
	if !e.wg.NetstackMode() {
		// If we are the gateway for any route, set up IP forwarding + masquerade.
		if selfRoutes := routesByGateway[selfKey]; len(selfRoutes) > 0 {
			if err := routing.EnableForwarding(); err != nil {
				log.Warn().Err(err).Msg("failed to enable IP forwarding")
			}
			if err := routing.AddMasquerade(); err != nil {
				log.Warn().Err(err).Msg("failed to add iptables masquerade")
			}
			log.Info().Strs("routes", selfRoutes).Msg("advertising routes — forwarding enabled")
		}

		// Detect whether a peer (not ourselves) is advertising a default route.
		hasExitNode := false
		for _, r := range resp.Routes {
			if r.Enabled && isDefaultRoute(r.Network) && r.Gateway != selfKey {
				hasExitNode = true
				break
			}
		}
		if hasExitNode && e.exitNode == nil {
			e.activateExitNode()
		} else if !hasExitNode && e.exitNode != nil {
			e.deactivateExitNode()
		}
	}

	added, updated, removed := e.peers.Diff(resp.Peers)

	for _, p := range added {
		if p.WgPubKey == selfKey {
			continue
		}
		// AllowedIps already includes any advertised route CIDRs (set by management).
		if err := e.wg.UpsertPeer(p.WgPubKey, p.AllowedIps, ""); err != nil {
			log.Warn().Err(err).Str("peer", p.Id).Msg("add peer failed")
		}
		if !e.wg.NetstackMode() {
			e.applyOSRoutes(p.WgPubKey, nil, routesByGateway[p.WgPubKey])
		}
		e.dns.Upsert(p.DnsLabel, p.Ip)
		e.ice.StartConnect(e.ctx, p.WgPubKey)
		log.Info().Str("peer", p.Hostname).Str("ip", p.Ip).
			Strs("routes", routesByGateway[p.WgPubKey]).Msg("peer added, ICE starting")
	}

	for _, p := range updated {
		if p.WgPubKey == selfKey {
			continue
		}
		if err := e.wg.UpsertPeer(p.WgPubKey, p.AllowedIps, ""); err != nil {
			log.Warn().Err(err).Str("peer", p.Id).Msg("update peer failed")
		}
		if !e.wg.NetstackMode() {
			e.applyOSRoutes(p.WgPubKey, e.appliedRoutes[p.WgPubKey], routesByGateway[p.WgPubKey])
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
		if !e.wg.NetstackMode() {
			e.applyOSRoutes(p.WgPubKey, e.appliedRoutes[p.WgPubKey], nil)
		}
		delete(e.appliedRoutes, p.WgPubKey)
		e.dns.Remove(p.DnsLabel)
		e.ice.ClosePeer(p.WgPubKey)
		log.Info().Str("peer", p.Hostname).Msg("peer removed")
	}

	// Apply ACL rules (iptables-based, only in kernel TUN mode).
	if !e.wg.NetstackMode() && len(resp.Rules) > 0 {
		if err := acl.EnsureChain(e.cfg.WGInterface); err != nil {
			log.Warn().Err(err).Msg("ACL chain setup failed")
		} else if err := acl.ApplyRules(resp.Rules, e.cfg.WGInterface); err != nil {
			log.Warn().Err(err).Msg("ACL rule apply failed")
		}
	}

	return nil
}

// activateExitNode sets up split-tunnel routing so all internet traffic flows
// through the exit node peer while management/signal connections stay on the
// original gateway.
//
// Instead of replacing the OS default route (which breaks the management
// connection), we add two more-specific /1 routes via the WireGuard interface.
// They cover all of 0.0.0.0/0 but leave the real default route in place.
// Host /32 routes for the management and signal servers are pinned via the
// original gateway so those connections always bypass the tunnel.
func (e *Engine) activateExitNode() {
	gwIP, gwIface, err := routing.GetDefaultGateway()
	if err != nil {
		log.Warn().Err(err).Msg("exit node: cannot determine default gateway — skipping OS route setup")
		return
	}

	// Resolve management and signal server IPs to pin via original gateway.
	var hostIPs []net.IP
	for _, addr := range []string{e.cfg.ManagementURL, e.cfg.SignalURL} {
		ip, err := resolveHost(addr)
		if err != nil {
			log.Warn().Err(err).Str("addr", addr).Msg("exit node: cannot resolve host — not pinning")
			continue
		}
		if ip.IsLoopback() {
			continue // localhost never routes through the tunnel anyway
		}
		if err := routing.AddHostRoute(ip, gwIP, gwIface); err != nil {
			log.Warn().Err(err).Str("ip", ip.String()).Msg("exit node: pin host route failed")
			continue
		}
		hostIPs = append(hostIPs, ip)
		log.Debug().Str("ip", ip.String()).Str("gw", gwIP.String()).Msg("exit node: pinned host route")
	}

	// Two /1 routes cover all of IPv4 and are more specific than the /0
	// default, so they win in the routing table without replacing it.
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := routing.AddRoute(cidr, e.cfg.WGInterface); err != nil {
			log.Warn().Err(err).Str("cidr", cidr).Msg("exit node: add split route failed")
		}
	}

	e.exitNode = &exitNodeState{gwIP: gwIP, gwIface: gwIface, hostIPs: hostIPs}
	log.Info().Str("gateway", gwIP.String()).Str("iface", gwIface).Msg("exit node routing activated")
}

// deactivateExitNode tears down split-tunnel routing installed by activateExitNode.
func (e *Engine) deactivateExitNode() {
	if e.exitNode == nil {
		return
	}
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		routing.RemoveRoute(cidr, e.cfg.WGInterface)
	}
	for _, ip := range e.exitNode.hostIPs {
		routing.RemoveHostRoute(ip, e.exitNode.gwIface)
	}
	e.exitNode = nil
	log.Info().Msg("exit node routing deactivated")
}

// resolveHost extracts the host from a host:port address and resolves it to an IP.
func resolveHost(addr string) (net.IP, error) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4(), nil
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	// Prefer IPv4.
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address for %q", host)
}

// applyOSRoutes diffs old vs new route CIDRs for a peer and updates the OS
// routing table. Default routes (0.0.0.0/0) are handled via activateExitNode /
// deactivateExitNode — this function skips them.
func (e *Engine) applyOSRoutes(peerKey string, oldRoutes, newRoutes []string) {
	for _, cidr := range diffRemoved(oldRoutes, newRoutes) {
		if isDefaultRoute(cidr) {
			continue
		}
		routing.RemoveRoute(cidr, e.cfg.WGInterface)
		log.Debug().Str("cidr", cidr).Msg("OS route removed")
	}
	for _, cidr := range diffAdded(oldRoutes, newRoutes) {
		if isDefaultRoute(cidr) {
			continue // operator must configure policy routing for exit nodes
		}
		if err := routing.AddRoute(cidr, e.cfg.WGInterface); err != nil {
			log.Warn().Err(err).Str("cidr", cidr).Msg("failed to add OS route")
		} else {
			log.Info().Str("cidr", cidr).Str("iface", e.cfg.WGInterface).Msg("OS route added")
		}
	}
	if newRoutes != nil {
		e.appliedRoutes[peerKey] = newRoutes
	}
}

func isDefaultRoute(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

func diffRemoved(old, new []string) []string {
	newSet := make(map[string]bool, len(new))
	for _, s := range new {
		newSet[s] = true
	}
	var out []string
	for _, s := range old {
		if !newSet[s] {
			out = append(out, s)
		}
	}
	return out
}

func diffAdded(old, new []string) []string {
	oldSet := make(map[string]bool, len(old))
	for _, s := range old {
		oldSet[s] = true
	}
	var out []string
	for _, s := range new {
		if !oldSet[s] {
			out = append(out, s)
		}
	}
	return out
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

// guessMeshCIDR derives a broad CIDR for the mesh from the assigned address.
// e.g. "100.64.0.5/32" → "100.64.0.0/10"
func guessMeshCIDR(addr string) string {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		ip = net.ParseIP(addr)
	}
	if ip == nil {
		return "100.64.0.0/10"
	}
	// Use a /10 covering the CGNAT range (100.64.0.0/10) which is standard for mesh VPNs.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 {
		return "100.64.0.0/10"
	}
	// Fallback: /16 of whatever we got.
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.0.0/16", ip4[0], ip4[1])
	}
	return "100.64.0.0/10"
}

// buildTLSConfigs returns per-server TLS configs.
// When TLSCACert is set or TLSSkipVerify is explicitly false, standard TLS is used.
// Otherwise TOFU (Trust On First Use) fingerprint pinning is used: the certificate
// fingerprint is stored in state on first connect and verified on subsequent connects.
func buildTLSConfigs(cfg *config.Config, st *state.State) (*tls.Config, *tls.Config, error) {
	if cfg.TLSCACert != "" || !cfg.TLSSkipVerify {
		tlsCfg, err := cfg.TLSConfig()
		return tlsCfg, tlsCfg, err
	}
	mgmTLS := makeTOFUConfig(st, cfg.StateDir, cfg.ManagementURL)
	sigTLS := makeTOFUConfig(st, cfg.StateDir, cfg.SignalURL)
	return mgmTLS, sigTLS, nil
}

// makeTOFUConfig creates a *tls.Config that implements TOFU fingerprint pinning
// for the given server address. The fingerprint is stored in / verified from state.
func makeTOFUConfig(st *state.State, stateDir, serverAddr string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec — custom verification via VerifyPeerCertificate
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			h := sha256.Sum256(rawCerts[0])
			fp := hex.EncodeToString(h[:])

			if st.ServerFingerprints == nil {
				st.ServerFingerprints = make(map[string]string)
			}
			pinned, exists := st.ServerFingerprints[serverAddr]
			if !exists {
				st.ServerFingerprints[serverAddr] = fp
				_ = st.Save(stateDir)
				log.Info().
					Str("server", serverAddr).
					Str("fingerprint", fp[:16]+"…").
					Msg("TOFU: pinned server certificate — verify this fingerprint on first use")
				return nil
			}
			if pinned != fp {
				return fmt.Errorf("TOFU: server certificate changed for %s (pinned=%s…, got=%s…) — delete state.json to re-pin", serverAddr, pinned[:16], fp[:16])
			}
			return nil
		},
	}
}
