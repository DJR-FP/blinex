package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	signalv1 "github.com/blinex/gen/signal/v1"
	sigauth "github.com/blinex/signal/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const secret = "signal-secret-at-least-32-bytes-xx!!"

func makeToken(key string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	cb, _ := json.Marshal(map[string]any{"wg_pub_key": key, "exp": time.Now().Add(time.Hour).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

// startServer spins up the signal server over bufconn with the auth interceptor.
func startServer(t *testing.T) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(grpc.StreamInterceptor(sigauth.StreamInterceptor(secret)))
	signalv1.RegisterSignalServiceServer(srv, New())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func openStream(t *testing.T, conn *grpc.ClientConn, token string) signalv1.SignalService_SendClient {
	t.Helper()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	stream, err := signalv1.NewSignalServiceClient(conn).Send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestSignalRoutesBetweenPeers(t *testing.T) {
	conn := startServer(t)
	a := openStream(t, conn, makeToken("keyA"))
	b := openStream(t, conn, makeToken("keyB"))

	// Register both by sending an initial MODE message.
	if err := a.Send(&signalv1.Message{Key: "keyA", Body: &signalv1.Body{Type: signalv1.Body_MODE}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Send(&signalv1.Message{Key: "keyB", Body: &signalv1.Body{Type: signalv1.Body_MODE}}); err != nil {
		t.Fatal(err)
	}
	// Give the server a moment to register both streams.
	time.Sleep(100 * time.Millisecond)

	// A sends an OFFER to B.
	if err := a.Send(&signalv1.Message{Key: "keyA", RemoteKey: "keyB", Body: &signalv1.Body{Type: signalv1.Body_OFFER, Payload: "hello"}}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Recv()
	if err != nil {
		t.Fatalf("B did not receive routed message: %v", err)
	}
	if msg.Key != "keyA" || msg.Body.Payload != "hello" {
		t.Fatalf("unexpected routed message: %+v", msg)
	}
}

func TestSignalRejectsIdentitySpoofing(t *testing.T) {
	conn := startServer(t)
	// Authenticated as keyA but attempts to register as keyB.
	spoof := openStream(t, conn, makeToken("keyA"))
	if err := spoof.Send(&signalv1.Message{Key: "keyB", Body: &signalv1.Body{Type: signalv1.Body_MODE}}); err != nil {
		t.Fatal(err)
	}
	// The server must terminate the stream with an error.
	if _, err := spoof.Recv(); err == nil {
		t.Fatal("expected stream to be rejected for key/identity mismatch")
	}
}

func TestSignalRejectsKeyChangeMidStream(t *testing.T) {
	conn := startServer(t)
	s := openStream(t, conn, makeToken("keyA"))
	if err := s.Send(&signalv1.Message{Key: "keyA", Body: &signalv1.Body{Type: signalv1.Body_MODE}}); err != nil {
		t.Fatal(err)
	}
	// Now try to switch identity mid-stream.
	if err := s.Send(&signalv1.Message{Key: "keyB", RemoteKey: "keyA", Body: &signalv1.Body{Type: signalv1.Body_OFFER}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(); err == nil {
		t.Fatal("expected stream to be rejected for mid-stream key change")
	}
}
