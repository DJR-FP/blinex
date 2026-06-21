package signalclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"

	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Client wraps the SignalService bidirectional stream.
type Client struct {
	conn    *grpc.ClientConn
	rpc     signalv1.SignalServiceClient
	stream  signalv1.SignalService_SendClient
	selfKey string
}

func New(serverAddr, selfWGKey string, tlsCfg *tls.Config) (*Client, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("dial signal server: %w", err)
	}
	return &Client{conn: conn, rpc: signalv1.NewSignalServiceClient(conn), selfKey: selfWGKey}, nil
}

func (c *Client) Close() error {
	if c.stream != nil {
		_ = c.stream.CloseSend()
	}
	return c.conn.Close()
}

// Connect opens the bidirectional stream, registers self, and dispatches
// inbound messages to handler. Blocks until ctx is done or an error occurs.
// If token is non-empty it is attached as a Bearer authorization header.
func (c *Client) Connect(ctx context.Context, token string, handler func(*signalv1.Message)) error {
	if token != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	}
	stream, err := c.rpc.Send(ctx)
	if err != nil {
		return fmt.Errorf("opening signal stream: %w", err)
	}
	c.stream = stream

	// Register self on the signal server (first message with our key registers us).
	if err := stream.Send(&signalv1.Message{
		Key:  c.selfKey,
		Body: &signalv1.Body{Type: signalv1.Body_MODE},
	}); err != nil {
		return fmt.Errorf("signal registration: %w", err)
	}

	log.Info().Str("self", c.selfKey[:8]+"…").Msg("signal: registered")

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("signal recv: %w", err)
		}
		handler(msg)
	}
}

// Send routes a message to a remote peer via the signal server.
func (c *Client) Send(remoteKey string, body *signalv1.Body) error {
	if c.stream == nil {
		return fmt.Errorf("signal stream not connected")
	}
	return c.stream.Send(&signalv1.Message{
		Key:       c.selfKey,
		RemoteKey: remoteKey,
		Body:      body,
	})
}
