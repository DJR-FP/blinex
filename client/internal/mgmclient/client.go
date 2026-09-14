package mgmclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	commonv1 "github.com/blinex/gen/common/v1"
	managementv1 "github.com/blinex/gen/management/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// Client wraps the ManagementService gRPC client.
type Client struct {
	conn *grpc.ClientConn
	rpc  managementv1.ManagementServiceClient
}

// keepaliveParams makes a silently dead connection fail instead of hanging.
//
// gRPC sends nothing on an idle stream by default, so if the underlying TCP
// connection dies without a FIN — a NAT or firewall evicting its state, which
// is routine on home broadband and cloud NAT — the client blocks in Recv()
// forever. No error, no log, no reconnect. That is exactly what happened live:
// an agent's Sync stream went quiet and the peer stayed unreachable for nearly
// two hours while the agent sat there believing it was connected, until it was
// restarted by hand. The Sync stream is push-only and mostly idle, which is
// precisely the traffic pattern NAT state eviction punishes.
//
// PermitWithoutStream keeps pinging when no RPC is in flight, since an idle
// long-lived stream is the case that needs it most. Time must stay above the
// servers' EnforcementPolicy MinTime or they answer with GOAWAY
// ENHANCE_YOUR_CALM and drop the connection this is meant to protect.
//
// Detection is the whole fix: once the stream errors, Engine.Run returns and
// the existing restart path (systemd Restart=on-failure, the Windows SCM's
// sc failure config) reconnects from scratch.
var keepaliveParams = keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: true,
}

func New(serverAddr string, tlsCfg *tls.Config) (*Client, error) {
	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepaliveParams))
	if err != nil {
		return nil, fmt.Errorf("dial management server: %w", err)
	}
	return &Client{conn: conn, rpc: managementv1.NewManagementServiceClient(conn)}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Login(ctx context.Context, setupKey, wgPubKey string, meta *commonv1.PeerMeta) (*managementv1.LoginResponse, error) {
	return c.rpc.Login(ctx, &managementv1.LoginRequest{
		SetupKey: setupKey,
		WgPubKey: wgPubKey,
		Meta:     meta,
	})
}

// Sync opens a server-streaming RPC and calls handler for every update.
// token is the JWT received from Login and is sent as gRPC metadata.
// It blocks until ctx is cancelled.
func (c *Client) Sync(ctx context.Context, token, wgPubKey string, handler func(*managementv1.SyncResponse) error) error {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	stream, err := c.rpc.Sync(ctx, &managementv1.SyncRequest{WgPubKey: wgPubKey})
	if err != nil {
		return fmt.Errorf("opening sync stream: %w", err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("sync recv: %w", err)
		}
		if err := handler(resp); err != nil {
			return err
		}
	}
}

// GetBlocklist polls for the current malicious-domain feed. knownVersion is
// the version last received (empty on first call); the response reports
// NotModified and omits Domains when the feed hasn't changed since.
func (c *Client) GetBlocklist(ctx context.Context, token, wgPubKey, knownVersion string) (*managementv1.GetBlocklistResponse, error) {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	return c.rpc.GetBlocklist(ctx, &managementv1.GetBlocklistRequest{
		WgPubKey:     wgPubKey,
		KnownVersion: knownVersion,
	})
}

func (c *Client) UpdateMeta(ctx context.Context, wgPubKey string, meta *commonv1.PeerMeta) error {
	_, err := c.rpc.UpdatePeerMeta(ctx, &managementv1.UpdatePeerMetaRequest{
		WgPubKey: wgPubKey,
		Meta:     meta,
	})
	return err
}
