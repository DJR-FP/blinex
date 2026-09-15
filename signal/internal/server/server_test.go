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

// TestConcurrentSendersToOnePeer is the regression for the unsynchronised
// target.Send. Several peers relay into the same target's stream from their
// own handler goroutines, which is exactly what a mesh does: WireGuard data
// is carried as type=RELAY messages over these streams, so every packet from
// every peer contends for the same target.
//
// grpc-go documents that SendMsg must not be called concurrently on one
// stream. This test does not prove corruption — it passes against the
// unsynchronised version too, and -race is unavailable in this environment
// (no cgo toolchain). It is a smoke test that fan-in still delivers every
// message, and a place for the contract to be stated; the serialisation in
// peerStream.send is justified by the documented API contract, not by a
// reproduction here.
func TestConcurrentSendersToOnePeer(t *testing.T) {
	conn := startServer(t)

	const (
		target  = "target-peer-key"
		senders = 6
		each    = 40
	)

	recvStream := openStream(t, conn, makeToken(target))
	if err := recvStream.Send(&signalv1.Message{Key: target}); err != nil {
		t.Fatal(err)
	}
	// Wait until the server has actually processed that registration, by
	// round-tripping a message the target addresses to itself. Without this
	// the senders can start first and every message is dropped by the
	// "target not connected" path — which is a real production behaviour
	// worth knowing about, but not what this test is measuring.
	if err := recvStream.Send(&signalv1.Message{
		Key: target, RemoteKey: target,
		Body: &signalv1.Body{Type: signalv1.Body_RELAY},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := recvStream.Recv(); err != nil {
		t.Fatalf("target registration never took effect: %v", err)
	}

	done := make(chan struct{})
	received := 0
	go func() {
		defer close(done)
		for received < senders*each {
			if _, err := recvStream.Recv(); err != nil {
				return
			}
			received++
		}
	}()

	sendErrs := make(chan error, senders)
	for i := 0; i < senders; i++ {
		key := "sender-" + string(rune('a'+i))
		go func(key string) {
			ctx := metadata.NewOutgoingContext(context.Background(),
				metadata.Pairs("authorization", "Bearer "+makeToken(key)))
			st, err := signalv1.NewSignalServiceClient(conn).Send(ctx)
			if err != nil {
				sendErrs <- err
				return
			}
			if err := st.Send(&signalv1.Message{Key: key}); err != nil {
				sendErrs <- err
				return
			}
			for j := 0; j < each; j++ {
				if err := st.Send(&signalv1.Message{
					Key:       key,
					RemoteKey: target,
					Body:      &signalv1.Body{Type: signalv1.Body_RELAY},
				}); err != nil {
					sendErrs <- err
					return
				}
			}
			sendErrs <- nil
		}(key)
	}
	for i := 0; i < senders; i++ {
		if err := <-sendErrs; err != nil {
			t.Fatalf("sender failed: %v", err)
		}
	}

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out: %d/%d relayed messages arrived under fan-in from %d senders",
			received, senders*each, senders)
	}
}

// Signaling addressed to a peer that is mid-reconnect must survive. A peer is
// absent for a few seconds whenever its agent restarts, and an OFFER lost in
// that window stalls ICE negotiation with nothing reported to the sender.
// Against the old behaviour this fails: the message was discarded with only a
// debug line.
func TestSignalingHeldForReconnectingPeerIsDelivered(t *testing.T) {
	conn := startServer(t)
	const absent = "absent-peer"
	const sender = "sender-peer"

	// Sender is up; target has not registered yet.
	send := openStream(t, conn, makeToken(sender))
	if err := send.Send(&signalv1.Message{Key: sender}); err != nil {
		t.Fatal(err)
	}
	if err := send.Send(&signalv1.Message{
		Key: sender, RemoteKey: absent,
		Body: &signalv1.Body{Type: signalv1.Body_OFFER, Payload: `{"ufrag":"u1"}`},
	}); err != nil {
		t.Fatal(err)
	}
	// Make sure the server has actually routed that OFFER while the target is
	// still absent. Messages on one stream are processed in order, so a
	// self-addressed message that comes back proves the OFFER was handled
	// first. Without this the target can register before the OFFER is routed,
	// it gets delivered normally, and the test passes against the old
	// drop-everything behaviour — verified by reverting.
	if err := send.Send(&signalv1.Message{
		Key: sender, RemoteKey: sender,
		Body: &signalv1.Body{Type: signalv1.Body_CANDIDATE, Payload: "sync"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := send.Recv(); err != nil {
		t.Fatalf("sync round-trip failed: %v", err)
	}

	// Now the target arrives, as it would after an agent restart.
	recv := openStream(t, conn, makeToken(absent))
	if err := recv.Send(&signalv1.Message{Key: absent}); err != nil {
		t.Fatal(err)
	}

	done := make(chan *signalv1.Message, 1)
	go func() {
		m, err := recv.Recv()
		if err == nil {
			done <- m
		}
	}()

	select {
	case m := <-done:
		if m.Body.GetType() != signalv1.Body_OFFER || m.Body.GetPayload() != `{"ufrag":"u1"}` {
			t.Fatalf("wrong message delivered: %v", m.Body)
		}
		if m.Key != sender {
			t.Errorf("sender key = %q, want %q", m.Key, sender)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("signaling sent while the peer was reconnecting was never delivered")
	}
}

// WireGuard data is deliberately NOT held: it has UDP semantics, WireGuard
// retransmits on its own, and queueing it would deliver stale packets after a
// reconnect and let a busy link grow the queue without bound.
func TestRelayDataForAbsentPeerIsNotQueued(t *testing.T) {
	srv := New()
	srv.handleAbsentTarget(&signalv1.Message{
		Key: "a", RemoteKey: "gone",
		Body: &signalv1.Body{Type: signalv1.Body_RELAY, Data: []byte("wg packet")},
	})
	if len(srv.pending) != 0 {
		t.Fatalf("relay data must not be queued, got %d queued peers", len(srv.pending))
	}
}

func TestPendingQueueIsBoundedAndExpires(t *testing.T) {
	srv := New()
	const peer = "peer"
	for i := 0; i < pendingPerPeer+10; i++ {
		srv.handleAbsentTarget(&signalv1.Message{
			Key: "s", RemoteKey: peer,
			Body: &signalv1.Body{Type: signalv1.Body_CANDIDATE, Payload: string(rune('a' + i%26))},
		})
	}
	if got := len(srv.pending[peer].msgs); got != pendingPerPeer {
		t.Errorf("queue length = %d, want it capped at %d", got, pendingPerPeer)
	}

	// Stale queues are not delivered, and are not left to leak either.
	srv.pending[peer].at = time.Now().Add(-pendingTTL - time.Second)
	srv.mu.Lock()
	got := srv.takePendingLocked(peer)
	srv.mu.Unlock()
	if got != nil {
		t.Error("an expired queue must not be delivered")
	}
	if _, still := srv.pending[peer]; still {
		t.Error("an expired queue must be removed")
	}
}
