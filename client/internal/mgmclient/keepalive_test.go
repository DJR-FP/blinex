package mgmclient

import (
	"testing"
	"time"
)

// serverMinTime is the EnforcementPolicy MinTime the management and signal
// servers run with. It cannot be imported — separate modules — so it is
// restated, and this test exists to catch the two sides drifting apart. The
// server-side half lives in management/cmd/server/keepalive_test.go.
const serverMinTime = 10 * time.Second

// The wedge this fixes: an agent's Sync stream went silent under a NAT that
// dropped its state, and because gRPC sends nothing on an idle stream the
// client sat in Recv() believing it was connected. The peer was unreachable
// for nearly two hours with no error logged anywhere, until a manual restart.
// Detection is the entire fix — Engine.Run returns on stream error and the
// service manager restarts the agent.
func TestKeepaliveDetectsSilentlyDeadConnections(t *testing.T) {
	if keepaliveParams.Time <= 0 {
		t.Fatal("keepalive must be enabled, or a half-open connection blocks Recv() forever")
	}
	// Ping faster than the server permits and it answers GOAWAY
	// ENHANCE_YOUR_CALM and closes the connection — turning an occasional
	// silent wedge into a constant one.
	if keepaliveParams.Time <= serverMinTime {
		t.Errorf("ping interval %v must stay above the servers' MinTime %v", keepaliveParams.Time, serverMinTime)
	}
	// The streams that wedge are idle by design, so pings must not require an
	// in-flight RPC.
	if !keepaliveParams.PermitWithoutStream {
		t.Error("PermitWithoutStream must be true; the Sync stream is push-only and idle for long stretches")
	}
	if keepaliveParams.Timeout <= 0 || keepaliveParams.Timeout >= keepaliveParams.Time {
		t.Errorf("Timeout %v must be positive and below Time %v so a dead link is noticed within roughly one interval",
			keepaliveParams.Timeout, keepaliveParams.Time)
	}
}
