package wgmgr

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const defaultMTU = 1420

// Manager manages a userspace WireGuard device whose UDP transport is provided
// by per-peer ICE connections (via IceBind).
type Manager struct {
	ifaceName string
	dev       *device.Device
	tunDev    tun.Device
	bind      *IceBind
	privKey   wgtypes.Key
	pubKeyB64 string
}

// New creates (or recreates) the named WireGuard interface using wireguard-go.
// privKey is the persistent Curve25519 private key loaded from state.
func New(ifaceName string, privKey wgtypes.Key) (*Manager, error) {
	// Create kernel TUN device.
	tunDev, err := tun.CreateTUN(ifaceName, defaultMTU)
	if err != nil {
		return nil, fmt.Errorf("creating TUN %q: %w", ifaceName, err)
	}

	bind := NewIceBind()
	logger := device.NewLogger(device.LogLevelError, "[wg] ")
	dev := device.NewDevice(tunDev, bind, logger)

	// Configure private key. wireguard-go IPC uses lowercase hex.
	privHex := hex.EncodeToString(privKey[:])
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", privHex)); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("configuring WireGuard key: %w", err)
	}

	if err := dev.Up(); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("bringing up WireGuard device: %w", err)
	}

	pubKeyArr := privKey.PublicKey()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyArr[:])
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

// SetAddress assigns a CIDR address to the TUN interface.
func (m *Manager) SetAddress(cidr string) error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return fmt.Errorf("link %q not found: %w", m.ifaceName, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", cidr, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("setting address: %w", err)
	}
	return netlink.LinkSetUp(link)
}

// UpsertPeer adds or updates a WireGuard peer.
// endpoint is "IP:port" of the ICE-established connection; pass "" to configure
// the peer without an endpoint (WireGuard will wait for an incoming handshake).
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
	m.dev.Close()
	m.bind.Close()
	link, err := netlink.LinkByName(m.ifaceName)
	if err == nil {
		_ = netlink.LinkDel(link)
	}
	return nil
}
