package server

import (
	"fmt"
	"net"

	"github.com/pion/logging"
	"github.com/pion/turn/v3"
)

type Config struct {
	PublicIP      string // public IP of this relay server
	UDPPort       int    // TURN/STUN UDP port (default 3478)
	RelayMinPort  int    // minimum relay allocation port (default 49152)
	RelayMaxPort  int    // maximum relay allocation port (default 49252)
	Realm         string // TURN realm (e.g. "blinex.co.uk")
	AuthUser      string // TURN long-term credential user
	AuthPass      string // TURN long-term credential password
}

// Start starts a STUN+TURN server and blocks until it exits.
func Start(cfg Config) error {
	udpAddr := fmt.Sprintf("0.0.0.0:%d", cfg.UDPPort)
	udpListener, err := net.ListenPacket("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP %s: %w", udpAddr, err)
	}

	logFactory := logging.NewDefaultLoggerFactory()
	logFactory.DefaultLogLevel = logging.LogLevelDebug

	relayIP := net.ParseIP(cfg.PublicIP)

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm,
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			if username == cfg.AuthUser {
				return turn.GenerateAuthKey(username, realm, cfg.AuthPass), true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: relayIP,
					Address:      "0.0.0.0",
					MinPort:      uint16(cfg.RelayMinPort),
					MaxPort:      uint16(cfg.RelayMaxPort),
				},
				// Allow all peers including the relay's own IP (hairpin).
				PermissionHandler: func(clientAddr net.Addr, peerIP net.IP) bool {
					return true
				},
			},
		},
		LoggerFactory: logFactory,
	})
	if err != nil {
		return fmt.Errorf("failed to create TURN server: %w", err)
	}
	defer s.Close()

	// Block forever; the caller manages lifecycle via context/signal.
	select {}
}
