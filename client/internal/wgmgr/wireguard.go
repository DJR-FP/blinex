package wgmgr

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const defaultMTU = 1420

// Manager manages a userspace WireGuard device whose UDP transport is provided
// by per-peer ICE connections (via IceBind).
type Manager struct {
	ifaceName    string
	dev          *device.Device
	tunDev       tun.Device
	bind         *IceBind
	privKey      wgtypes.Key
	pubKeyB64    string
	netstackMode bool
	tnet         *netstack.Net // non-nil in netstack mode after SetAddress
}

// New creates (or recreates) the named WireGuard interface using wireguard-go.
// privKey is the persistent Curve25519 private key loaded from state.
// If /dev/net/tun is unavailable (e.g. in unprivileged LXC, Windows, macOS),
// defers TUN creation to SetAddress and uses a userspace netstack.
func New(ifaceName string, privKey wgtypes.Key) (*Manager, error) {
	pubKeyArr := privKey.PublicKey()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyArr[:])

	tunDev, err := createTUN(ifaceName)
	if err != nil && isTUNUnavailable(err) {
		log.Warn().Msg("TUN device unavailable — using userspace netstack mode (no kernel interface)")
		return &Manager{
			ifaceName:    ifaceName,
			bind:         NewIceBind(),
			privKey:      privKey,
			pubKeyB64:    pubKeyB64,
			netstackMode: true,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("creating TUN %q: %w", ifaceName, err)
	}

	bind := NewIceBind()
	logger := device.NewLogger(device.LogLevelError, "[wg] ")
	dev := device.NewDevice(tunDev, bind, logger)

	privHex := hex.EncodeToString(privKey[:])
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", privHex)); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("configuring WireGuard key: %w", err)
	}

	if err := dev.Up(); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("bringing up WireGuard device: %w", err)
	}

	log.Info().Str("iface", ifaceName).Str("pubkey", pubKeyB64[:16]+"…").Msg("WireGuard device ready")

	return &Manager{
		ifaceName: ifaceName,
		dev:       dev,
		tunDev:    tunDev,
		bind:      bind,
		privKey:   privKey,
		pubKeyB64: pubKeyB64,
	}, nil
}

// PublicKey returns the base64-encoded WireGuard public key.
func (m *Manager) PublicKey() string { return m.pubKeyB64 }

// Bind returns the IceBind so the ICE manager can register peer connections.
func (m *Manager) Bind() *IceBind { return m.bind }

// NetstackMode returns true when the manager is operating in userspace
// netstack mode (no kernel TUN device).
func (m *Manager) NetstackMode() bool { return m.netstackMode }

// NetstackNet returns the netstack Net for dialing through the tunnel.
// Only valid in netstack mode after SetAddress has been called.
func (m *Manager) NetstackNet() *netstack.Net { return m.tnet }

// SetAddress assigns a CIDR address to the TUN interface.
// In netstack mode, this creates the userspace TUN and WireGuard device.
func (m *Manager) SetAddress(cidr string) error {
	if m.netstackMode {
		return m.initNetstack(cidr)
	}
	return m.setKernelAddress(cidr)
}

// initNetstack creates the netstack TUN and WireGuard device now that we
// know the local address.
func (m *Manager) initNetstack(cidr string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", cidr, err)
	}

	tunDev, tnet, err := createNetstackTUN(prefix.Addr())
	if err != nil {
		return err
	}

	logger := device.NewLogger(device.LogLevelError, "[wg] ")
	dev := device.NewDevice(tunDev, m.bind, logger)

	privHex := hex.EncodeToString(m.privKey[:])
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", privHex)); err != nil {
		tunDev.Close()
		return fmt.Errorf("configuring WireGuard key: %w", err)
	}

	if err := dev.Up(); err != nil {
		tunDev.Close()
		return fmt.Errorf("bringing up WireGuard device: %w", err)
	}

	m.dev = dev
	m.tunDev = tunDev
	m.tnet = tnet
	log.Info().Str("addr", cidr).Msg("WireGuard netstack device ready")
	return nil
}

// UpsertPeer adds or updates a WireGuard peer.
func (m *Manager) UpsertPeer(pubKeyB64 string, allowedIPs []string, endpoint string) error {
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding pubkey: %w", err)
	}
	pubHex := hex.EncodeToString(pubKeyRaw)

	var sb strings.Builder
	fmt.Fprintf(&sb, "public_key=%s\n", pubHex)
	for _, ip := range allowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", ip)
	}
	if endpoint != "" {
		fmt.Fprintf(&sb, "endpoint=%s\n", endpoint)
	}
	fmt.Fprintf(&sb, "persistent_keepalive_interval=25\n")

	return m.dev.IpcSet(sb.String())
}

// SetPeerEndpoint sets the endpoint of an existing WireGuard peer without registering a conn.
func (m *Manager) SetPeerEndpoint(pubKeyB64 string, endpoint string) error {
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return err
	}
	pubHex := hex.EncodeToString(pubKeyRaw)
	return m.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", pubHex, endpoint))
}

// UpdateEndpoint sets/updates the endpoint of an existing peer and registers
// the ICE net.Conn with the bind layer.
func (m *Manager) UpdateEndpoint(pubKeyB64 string, endpoint string, iceConn net.Conn) error {
	if err := m.bind.AddConn(endpoint, iceConn); err != nil {
		return err
	}
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return err
	}
	pubHex := hex.EncodeToString(pubKeyRaw)
	return m.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", pubHex, endpoint))
}

// RemovePeer removes a WireGuard peer.
func (m *Manager) RemovePeer(pubKeyB64 string) error {
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding pubkey: %w", err)
	}
	pubHex := hex.EncodeToString(pubKeyRaw)
	return m.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
}

// Close shuts down the WireGuard device and the TUN interface.
func (m *Manager) Close() error {
	if m.dev != nil {
		m.dev.Close()
	}
	m.bind.Close()
	if !m.netstackMode {
		m.cleanupKernelTUN()
	}
	return nil
}
