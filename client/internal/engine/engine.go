package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/blinex/client/internal/acl"
	"github.com/blinex/client/internal/config"
	"github.com/blinex/client/internal/controlapi"
	"github.com/blinex/client/internal/dns"
	"github.com/blinex/client/internal/dnsconfig"
	"github.com/blinex/client/internal/ice"
	"github.com/blinex/client/internal/mgmclient"
	"github.com/blinex/client/internal/peer"
	"github.com/blinex/client/internal/peerlink"
	"github.com/blinex/client/internal/relay"
	"github.com/blinex/client/internal/routing"
	"github.com/blinex/client/internal/signalclient"
	"github.com/blinex/client/internal/state"
	"github.com/blinex/client/internal/wgmgr"
	commonv1 "github.com/blinex/gen/common/v1"
	managementv1 "github.com/blinex/gen/management/v1"
	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/rs/zerolog/log"
)

// dnsListenAddr is where the Magic DNS resolver listens — shared with
// dnsconfig.Apply so the OS is pointed at the same address the resolver
// actually answers on.
const dnsListenAddr = "127.0.0.1:53535"

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
	relayConns    map[string]*relay.Conn    // peerKey → relay connection (for sending)
	relayEndpts   map[string]netip.AddrPort // peerKey → virtual endpoint address
	mu            sync.Mutex
	links         map[string]*peerlink.Link // peerKey → data path link (relay + ICE)
	appliedRoutes map[string][]string       // peerKey → route CIDRs currently installed in OS
	exitNode      *exitNodeState            // non-nil when exit node routing is active
	ctx           context.Context

	selfIP     string            // own mesh IP (CIDR), set after enrollment
	lastRoutes []*commonv1.Route // routes from the most recent sync (for status)
	ctrlClose  func()            // stops the local control socket
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

	iceMgr := ice.New(wg.PublicKey(), cfg.STUNURLs, cfg.TURNUser, cfg.TURNPass, sig)
	dnsResolver := dns.New(dnsListenAddr, "blinex", cfg.DNSUpstream)

	return &Engine{
		cfg:           cfg,
		wg:            wg,
		mgm:           mgm,
		sig:           sig,
		ice:           iceMgr,
		dns:           dnsResolver,
		peers:         peer.New(),
		relayConns:    make(map[string]*relay.Conn),
		relayEndpts:   make(map[string]netip.AddrPort),
		links:         make(map[string]*peerlink.Link),
		appliedRoutes: make(map[string][]string),
	}, nil
}

// Run starts the agent and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	e.ctx = ctx
	defer e.wg.Close()
	defer e.mgm.Close()
	defer e.sig.Close()

	// Wire ICE → peerLink: when ICE establishes a direct conn, hand it to the
	// peer's link, which probes it and switches the send path only if healthy.
	// The relay remains the always-available default and fallback.
	e.ice.OnConnected = func(peerKey, endpoint string, conn net.Conn) {
		e.mu.Lock()
		link := e.links[peerKey]
		e.mu.Unlock()
		if link != nil {
			link.SetICEConn(conn)
		}
	}

	hostname, _ := os.Hostname()
	meta := &commonv1.PeerMeta{
		Hostname:    hostname,
		Os:          runtime.GOOS,
		Kernel:      runtime.GOARCH,
		CoreVersion: e.cfg.Version,
		LocalIp:     localOutboundIP(),
	}

	loginResp, err := e.enrollWithRetry(ctx, meta)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	e.selfIP = loginResp.NetworkConfig.Address

	if err := e.wg.SetAddress(loginResp.NetworkConfig.Address); err != nil {
		return fmt.Errorf("setting WireGuard address: %w", err)
	}

	// Point the OS at our own Magic DNS resolver, the way NetBird/Tailscale's
	// MagicDNS does — without this, mesh hostnames and domain filtering only
	// work if a user manually reconfigures their system DNS. Kernel-TUN only
	// for now (a real interface to attach the override's lifetime to): if the
	// agent dies uncleanly, the OS destroys the interface and the DNS
	// override goes with it, so there's nothing to leave stuck. Netstack
	// peers (no real interface) aren't covered yet.
	if !e.wg.NetstackMode() {
		dnsconfig.Apply(e.cfg.WGInterface, dnsListenAddr)
		defer dnsconfig.Revert(e.cfg.WGInterface)
	}

	// Local control socket for `blinex-agent status|peers|routes`.
	if closeFn, err := controlapi.Serve(controlapi.DefaultSocket, e.Status); err != nil {
		log.Warn().Err(err).Msg("control socket unavailable (status CLI disabled)")
	} else {
		e.ctrlClose = closeFn
		defer closeFn()
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

	// Malicious-domain blocklist: polled on its own slow cadence rather than
	// pushed via Sync — the compiled feed can run into the tens of thousands
	// of domains, far too large to bundle into every peer/rule update.
	go e.pollBlocklist(ctx, loginResp.Token)

	// Signal client: open stream, register, and dispatch messages.
	sigErrCh := make(chan error, 1)
	go func() {
		err := e.sig.Connect(ctx, loginResp.Token, func(msg *signalv1.Message) {
			if msg.Body != nil && msg.Body.Type == signalv1.Body_RELAY {
				e.mu.Lock()
				ep, ok := e.relayEndpts[msg.Key]
				e.mu.Unlock()
				if ok {
					e.wg.Bind().ReceiveFromRelay(msg.Body.Data, ep)
				}
				return
			}
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

// blocklistPollInterval is deliberately much shorter than the server's own
// feed-refresh cadence (default 6h) — the version check makes an unchanged
// poll cheap (a small RPC, no domain list), so polling often just means the
// agent picks up a refreshed feed promptly without needing a server push.
const blocklistPollInterval = 15 * time.Minute

// pollBlocklist periodically fetches the malicious-domain feed and installs
// it into the DNS resolver. It never returns an error upward — a feed fetch
// failure just means filtering stays on the last-known list (or off, if none
// has ever loaded), which shouldn't take down the whole agent.
func (e *Engine) pollBlocklist(ctx context.Context, token string) {
	var knownVersion string
	fetch := func() {
		resp, err := e.mgm.GetBlocklist(ctx, token, e.wg.PublicKey(), knownVersion)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn().Err(err).Msg("blocklist fetch failed, keeping previous list")
			}
			return
		}
		if resp.NotModified || resp.Version == "" {
			return
		}
		e.dns.SetBlocklist(resp.Domains)
		knownVersion = resp.Version
		log.Info().Int("domains", len(resp.Domains)).Msg("blocklist updated")
	}

	fetch()
	ticker := time.NewTicker(blocklistPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fetch()
		}
	}
}

// Status builds a live snapshot of the agent state for the control socket.
func (e *Engine) Status() controlapi.Status {
	hostname, _ := os.Hostname()
	selfKey := e.wg.PublicKey()

	mode := "kernel"
	if e.wg.NetstackMode() {
		mode = "netstack"
	}

	st := controlapi.Status{
		Version:   e.cfg.Version,
		Hostname:  hostname,
		SelfIP:    e.selfIP,
		Interface: e.cfg.WGInterface,
		Mode:      mode,
		DNSSuffix: "blinex",
	}

	// pubkey → hostname for resolving route gateways.
	keyToName := map[string]string{selfKey: hostname}

	for _, p := range e.peers.All() {
		if p.WgPubKey == selfKey {
			continue
		}
		keyToName[p.WgPubKey] = p.Hostname
		path := "relay"
		e.mu.Lock()
		link := e.links[p.WgPubKey]
		e.mu.Unlock()
		if link != nil && link.UsingICE() {
			path = "direct"
		}
		dnsName := ""
		if p.DnsLabel != "" {
			dnsName = p.DnsLabel + "." + st.DNSSuffix
		}
		st.Peers = append(st.Peers, controlapi.PeerInfo{
			Hostname: p.Hostname,
			IP:       p.Ip,
			DNSName:  dnsName,
			Path:     path,
		})
	}

	e.mu.Lock()
	routes := e.lastRoutes
	e.mu.Unlock()
	for _, r := range routes {
		via := keyToName[r.Gateway]
		self := r.Gateway == selfKey
		if self {
			via = "this device"
		} else if via == "" {
			via = shortKey(r.Gateway)
		}
		st.Routes = append(st.Routes, controlapi.RouteInfo{
			Network: r.Network,
			Via:     via,
			Self:    self,
			Enabled: r.Enabled,
		})
	}

	return st
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
	e.mu.Lock()
	e.lastRoutes = resp.Routes
	e.mu.Unlock()

	// Build gateway → route CIDRs map from this sync response.
	routesByGateway := make(map[string][]string)
	for _, r := range resp.Routes {
		if r.Enabled {
			routesByGateway[r.Gateway] = append(routesByGateway[r.Gateway], r.Network)
		}
	}

	// OS-level routing and exit node support require a kernel TUN interface.
	if !e.wg.NetstackMode() {
		// If we are the gateway for any route, set up IP forwarding + masquerade;
		// otherwise tear the masquerade down so withdrawing all advertised routes
		// stops NATting (mirror of the ACL reconcile — never leave stale state).
		if selfRoutes := routesByGateway[selfKey]; len(selfRoutes) > 0 {
			if err := routing.EnableForwarding(); err != nil {
				log.Warn().Err(err).Msg("failed to enable IP forwarding")
			}
			if err := routing.AddMasquerade(e.cfg.WGInterface); err != nil {
				log.Warn().Err(err).Msg("failed to add iptables masquerade")
			}
			log.Info().Strs("routes", selfRoutes).Msg("advertising routes — forwarding enabled")
		} else {
			routing.RemoveMasquerade(e.cfg.WGInterface)
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
	} else {
		// Netstack mode: act as a userspace subnet router / exit node
		// (NetBird/Tailscale style). The netstack forwards mesh→LAN (or
		// mesh→internet, for a 0.0.0.0/0 exit advertisement) connections out via
		// the host socket (auto-SNAT, no iptables). Default routes are included
		// here — the forwarder handles TCP/UDP/ICMP for any destination.
		var subnets []netip.Prefix
		for _, cidr := range routesByGateway[selfKey] {
			if p, err := netip.ParsePrefix(cidr); err == nil {
				subnets = append(subnets, p)
			}
		}
		e.wg.SetRouterSubnets(subnets)
		// Enforce ACLs on forwarded traffic in userspace — kernel peers do this
		// via the BLINEX-ACL iptables chain, which a netstack peer has no access
		// to, so without this a netstack router/exit would bypass ACL policy.
		e.wg.SetRouterACL(resp.Rules)
	}

	added, updated, removed := e.peers.Diff(resp.Peers)

	for _, p := range added {
		if p.WgPubKey == selfKey {
			continue
		}
		if err := e.wg.UpsertPeer(p.WgPubKey, p.AllowedIps, ""); err != nil {
			log.Warn().Err(err).Str("peer", p.Id).Msg("add peer failed")
		}
		if !e.wg.NetstackMode() {
			e.applyOSRoutes(p.WgPubKey, nil, routesByGateway[p.WgPubKey])
		}
		e.dns.Upsert(p.DnsLabel, p.Ip)

		// Data path: a peerLink wraps the relay conn (always-on default) and,
		// once ICE connects and probes succeed, a direct ICE conn.
		//   Send:    WireGuard → RelayBind.Send → peerLink.Write → relay|ICE
		//   Receive: signal relay → ReceiveFromRelay → bind, and
		//            ICE conn → peerLink read loop → ReceiveFromRelay → bind
		rc := relay.New(e.wg.PublicKey(), p.WgPubKey, e.sig)
		endpoint := rc.Endpoint()
		ep, _ := netip.ParseAddrPort(endpoint)

		link := peerlink.New(ep, p.WgPubKey, rc, e.wg.Bind().ReceiveFromRelay)
		e.mu.Lock()
		e.relayConns[p.WgPubKey] = rc
		e.relayEndpts[p.WgPubKey] = ep
		e.links[p.WgPubKey] = link
		e.mu.Unlock()

		// Register the link as the send conn and set the WireGuard endpoint.
		if err := e.wg.UpdateEndpoint(p.WgPubKey, endpoint, link); err != nil {
			log.Error().Err(err).Str("peer", shortKey(p.WgPubKey)).Msg("relay endpoint setup failed")
		} else {
			log.Info().Str("peer", p.Hostname).Str("ip", p.Ip).Msg("peer added, relay connected via signal")
		}

		// Start ICE to try for a direct path; peerLink upgrades only if healthy.
		e.ice.StartConnect(e.ctx, p.WgPubKey)
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
		e.mu.Lock()
		if link, ok := e.links[p.WgPubKey]; ok {
			link.Close()
			delete(e.links, p.WgPubKey)
		}
		delete(e.relayEndpts, p.WgPubKey)
		rc, hasRC := e.relayConns[p.WgPubKey]
		delete(e.relayConns, p.WgPubKey)
		e.mu.Unlock()
		if hasRC {
			rc.Close()
		}
		log.Info().Str("peer", p.Hostname).Msg("peer removed")
	}

	// Apply ACL rules (iptables-based, only in kernel TUN mode). This must run on
	// every sync regardless of rule count: when the last rule is deleted, resp.Rules
	// is empty and ApplyRules([]) flushes the chain. Guarding on len(resp.Rules) > 0
	// would leave stale DROP rules installed after a rule is removed.
	if !e.wg.NetstackMode() {
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

// localOutboundIP returns the local address the OS would use to reach the
// public internet, without sending any packets (UDP dial just picks a
// route). Best-effort — returns "" if no route is available.
func localOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
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
