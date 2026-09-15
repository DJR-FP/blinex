package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/blinex/client/internal/peerlink"
)

// A peer that already has a data path must be left alone. Both the added and
// updated sync paths call ensureRelayLink now, and a sync arrives on every
// peer change — rebuilding the link each time would tear down a working
// (possibly ICE-promoted) path on every unrelated update.
//
// The assertion is indirect but strict: this Engine has a nil wg, so if
// ensureRelayLink did anything past the guard it would panic.
func TestEnsureRelayLinkLeavesAnExistingPathAlone(t *testing.T) {
	const peer = "peer-key"
	e := &Engine{
		relayEndpts:        map[string]netip.AddrPort{peer: netip.MustParseAddrPort("127.0.0.1:51820")},
		links:              map[string]*peerlink.Link{peer: {}},
		unknownRelayLogged: map[string]time.Time{},
	}
	e.ensureRelayLink(peer, "host", "100.64.0.5") // must not panic
}

// Half-built state must be rebuilt, not treated as present. An endpoint with
// no link (or the reverse) is exactly the shape that left a peer able to send
// to us but never receive.
func TestEnsureRelayLinkRebuildsHalfBuiltState(t *testing.T) {
	const peer = "peer-key"
	for _, tc := range []struct {
		name  string
		setup func(e *Engine)
	}{
		{"endpoint without link", func(e *Engine) {
			e.relayEndpts[peer] = netip.MustParseAddrPort("127.0.0.1:51820")
		}},
		{"link without endpoint", func(e *Engine) {
			e.links[peer] = &peerlink.Link{}
		}},
		{"neither", func(e *Engine) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{
				relayEndpts:        map[string]netip.AddrPort{},
				links:              map[string]*peerlink.Link{},
				unknownRelayLogged: map[string]time.Time{},
			}
			tc.setup(e)
			defer func() {
				if recover() == nil {
					t.Fatal("expected ensureRelayLink to proceed past the guard and rebuild")
				}
			}()
			e.ensureRelayLink(peer, "host", "100.64.0.5")
		})
	}
}

// The warning fires once per interval per peer. WireGuard retransmits
// handshakes roughly every 5s, so an unbounded log would bury the file the
// moment one peer's data path went missing — which is precisely when the rest
// of the log matters most.
func TestUnknownRelayPeerLogIsRateLimitedPerPeer(t *testing.T) {
	e := &Engine{unknownRelayLogged: map[string]time.Time{}}

	e.logUnknownRelayPeer("peer-a")
	first := e.unknownRelayLogged["peer-a"]
	if first.IsZero() {
		t.Fatal("first drop for a peer must be recorded")
	}

	e.logUnknownRelayPeer("peer-a")
	if got := e.unknownRelayLogged["peer-a"]; !got.Equal(first) {
		t.Error("a second drop inside the interval must not re-log or refresh the timestamp")
	}

	// A different peer is tracked independently — one noisy peer must not
	// suppress the warning for another.
	e.logUnknownRelayPeer("peer-b")
	if e.unknownRelayLogged["peer-b"].IsZero() {
		t.Error("rate limiting must be per peer, not global")
	}

	// Once the interval lapses it logs again.
	e.unknownRelayLogged["peer-a"] = time.Now().Add(-unknownRelayLogInterval - time.Second)
	e.logUnknownRelayPeer("peer-a")
	if e.unknownRelayLogged["peer-a"].Equal(first) {
		t.Error("after the interval lapses the warning must fire again")
	}
}
