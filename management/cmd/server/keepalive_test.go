package main

import (
	"testing"
	"time"
)

// clientKeepaliveInterval is the ping interval the agent uses
// (client/internal/mgmclient and signalclient). It cannot be imported — those
// live in a separate module — so it is restated here, and these tests exist to
// catch the two sides drifting apart.
const clientKeepaliveInterval = 30 * time.Second

// A server rejects pings arriving faster than MinTime with GOAWAY
// ENHANCE_YOUR_CALM and closes the connection. Set MinTime above the client's
// interval and enabling client keepalive would start killing exactly the
// long-lived streams it was added to protect — a worse failure than the silent
// wedge it fixes, because it would be constant rather than occasional.
func TestEnforcementPolicyPermitsTheClientsPingRate(t *testing.T) {
	if grpcEnforcementPolicy.MinTime >= clientKeepaliveInterval {
		t.Fatalf("MinTime %v must stay below the client's %v ping interval, or the server sends GOAWAY ENHANCE_YOUR_CALM",
			grpcEnforcementPolicy.MinTime, clientKeepaliveInterval)
	}
	// The streams this protects are idle by design: Sync is push-only and the
	// signal stream is quiet between peer events. Pings only when an RPC is in
	// flight would never fire on precisely the connections that wedge.
	if !grpcEnforcementPolicy.PermitWithoutStream {
		t.Error("PermitWithoutStream must be true; idle long-lived streams are the case that wedges")
	}
}

func TestServerParamsDetectDeadClients(t *testing.T) {
	if grpcServerParams.Time <= 0 || grpcServerParams.Timeout <= 0 {
		t.Fatal("server keepalive must be configured, or dead streams and their subscriptions linger until the OS times the socket out")
	}
	if grpcServerParams.Timeout >= grpcServerParams.Time {
		t.Errorf("Timeout %v should be well under Time %v so a missed ack is noticed before the next ping",
			grpcServerParams.Timeout, grpcServerParams.Time)
	}
	// No MaxConnectionIdle/MaxConnectionAge: both streams are meant to stay
	// open and idle for hours, and either would tear them down on a timer.
	if grpcServerParams.MaxConnectionIdle != 0 {
		t.Error("MaxConnectionIdle must stay unset; Sync and signal streams are idle by design")
	}
	if grpcServerParams.MaxConnectionAge != 0 {
		t.Error("MaxConnectionAge must stay unset; it would recycle healthy long-lived streams")
	}
}
