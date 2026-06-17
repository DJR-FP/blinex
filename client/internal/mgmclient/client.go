package mgmclient

import (
	"context"
	"fmt"

	managementv1 "github.com/meshnet/gen/management/v1"
	commonv1 "github.com/meshnet/gen/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the ManagementService gRPC client.
type Client struct {
	conn *grpc.ClientConn
	rpc  managementv1.ManagementServiceClient
}

func New(serverAddr string) (*Client, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
// It blocks until ctx is cancelled.
func (c *Client) Sync(ctx context.Context, wgPubKey string, handler func(*managementv1.SyncResponse) error) error {
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
