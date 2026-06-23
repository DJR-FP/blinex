package ice

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	pion "github.com/pion/ice/v2"
	"github.com/pion/stun"
	"github.com/pion/turn/v3"
)

func TestTwoAgentsRelayOnly(t *testing.T) {
	// Start a local TURN server.
	udpListener, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	turnPort := udpListener.LocalAddr().(*net.UDPAddr).Port
	t.Logf("TURN server on port %d", turnPort)

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: "test",
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			return turn.GenerateAuthKey("user", "test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: udpListener,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer turnServer.Close()

	turnURL, _ := stun.ParseURI(fmt.Sprintf("turn:127.0.0.1:%d?transport=udp", turnPort))
	turnURL.Username = "user"
	turnURL.Password = "pass"

	// RELAY ONLY — no STUN, no host candidates.
	urls := []*stun.URI{turnURL}

	agentA, err := pion.NewAgent(&pion.AgentConfig{
		NetworkTypes:   []pion.NetworkType{pion.NetworkTypeUDP4},
		Urls:           urls,
		CandidateTypes: []pion.CandidateType{pion.CandidateTypeRelay},
	})
	if err != nil {
		t.Fatal("agent A:", err)
	}
	defer agentA.Close()

	agentB, err := pion.NewAgent(&pion.AgentConfig{
		NetworkTypes:   []pion.NetworkType{pion.NetworkTypeUDP4},
		Urls:           urls,
		CandidateTypes: []pion.CandidateType{pion.CandidateTypeRelay},
	})
	if err != nil {
		t.Fatal("agent B:", err)
	}
	defer agentB.Close()

	candA := gatherAll(t, agentA, "A")
	candB := gatherAll(t, agentB, "B")

	t.Logf("Agent A gathered %d candidates", len(candA))
	t.Logf("Agent B gathered %d candidates", len(candB))

	ufragA, pwdA, _ := agentA.GetLocalUserCredentials()
	ufragB, pwdB, _ := agentB.GetLocalUserCredentials()

	for _, c := range candB {
		agentA.AddRemoteCandidate(c)
	}
	for _, c := range candA {
		agentB.AddRemoteCandidate(c)
	}

	t.Logf("Starting Dial/Accept (relay only)")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	connCh := make(chan *pion.Conn, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := agentA.Dial(ctx, ufragB, pwdB)
		if err != nil {
			errCh <- fmt.Errorf("A.Dial: %w", err)
			return
		}
		connCh <- conn
	}()

	connB, err := agentB.Accept(ctx, ufragA, pwdA)
	if err != nil {
		t.Fatal("B.Accept:", err)
	}
	t.Logf("Agent B connected via RELAY: %s", connB.RemoteAddr())

	select {
	case conn := <-connCh:
		t.Logf("Agent A connected via RELAY: %s", conn.RemoteAddr())
	case err := <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("timeout")
	}

	t.Log("SUCCESS: Relay-only connection works!")
}

func TestTwoAgentsConnect(t *testing.T) {
	// Start a local TURN server.
	udpListener, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	turnPort := udpListener.LocalAddr().(*net.UDPAddr).Port
	t.Logf("TURN server on port %d", turnPort)

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: "test",
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			return turn.GenerateAuthKey("user", "test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: udpListener,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer turnServer.Close()

	turnURL, _ := stun.ParseURI(fmt.Sprintf("turn:127.0.0.1:%d?transport=udp", turnPort))
	turnURL.Username = "user"
	turnURL.Password = "pass"

	stunURL, _ := stun.ParseURI(fmt.Sprintf("stun:127.0.0.1:%d", turnPort))

	urls := []*stun.URI{stunURL, turnURL}

	// Create two ICE agents.
	agentA, err := pion.NewAgent(&pion.AgentConfig{
		NetworkTypes: []pion.NetworkType{pion.NetworkTypeUDP4},
		Urls:         urls,
	})
	if err != nil {
		t.Fatal("agent A:", err)
	}
	defer agentA.Close()

	agentB, err := pion.NewAgent(&pion.AgentConfig{
		NetworkTypes: []pion.NetworkType{pion.NetworkTypeUDP4},
		Urls:         urls,
	})
	if err != nil {
		t.Fatal("agent B:", err)
	}
	defer agentB.Close()

	// Gather candidates for both.
	candA := gatherAll(t, agentA, "A")
	candB := gatherAll(t, agentB, "B")

	t.Logf("Agent A gathered %d candidates", len(candA))
	t.Logf("Agent B gathered %d candidates", len(candB))

	// Get credentials.
	ufragA, pwdA, _ := agentA.GetLocalUserCredentials()
	ufragB, pwdB, _ := agentB.GetLocalUserCredentials()

	// Add remote candidates.
	for _, c := range candB {
		agentA.AddRemoteCandidate(c)
	}
	for _, c := range candA {
		agentB.AddRemoteCandidate(c)
	}

	t.Logf("Credentials exchanged, starting Dial/Accept")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	connCh := make(chan *pion.Conn, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := agentA.Dial(ctx, ufragB, pwdB)
		if err != nil {
			errCh <- fmt.Errorf("A.Dial: %w", err)
			return
		}
		connCh <- conn
	}()

	connB, err := agentB.Accept(ctx, ufragA, pwdA)
	if err != nil {
		t.Fatal("B.Accept:", err)
	}
	t.Logf("Agent B connected: %s", connB.RemoteAddr())

	select {
	case conn := <-connCh:
		t.Logf("Agent A connected: %s", conn.RemoteAddr())
	case err := <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("timeout")
	}

	t.Log("SUCCESS: Both agents connected!")
}

func gatherAll(t *testing.T, agent *pion.Agent, label string) []pion.Candidate {
	var candidates []pion.Candidate
	done := make(chan struct{})

	agent.OnCandidate(func(c pion.Candidate) {
		if c == nil {
			close(done)
			return
		}
		t.Logf("%s: gathered %s %s:%d", label, c.Type(), c.Address(), c.Port())
		candidates = append(candidates, c)
	})

	if err := agent.GatherCandidates(); err != nil {
		t.Fatal(label, "gather:", err)
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal(label, "gather timeout")
	}

	return candidates
}
