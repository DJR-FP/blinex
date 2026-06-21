package mgmclient

import (
	"context"
	"crypto/tls"
	"fmt"

	commonv1 "github.com/blinex/gen/common/v1"
	managementv1 "github.com/blinex/gen/management/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Client wraps the ManagementService gRPC client.
type Client struct {
	conn *grpc.ClientConn
	rpc  managementv1.ManagementServiceClient
}

func New(serverAddr string, tlsCfg *tls.Config) (*Client, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
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

func (c *Client) UpdateMeta(ctx context.Context, wgPubKey string, meta *commonv1.PeerMeta) error {
	_, err := c.rpc.UpdatePeerMeta(ctx, &managementv1.UpdatePeerMetaRequest{
		WgPubKey: wgPubKey,
		Meta:     meta,
	})
	return err
}
