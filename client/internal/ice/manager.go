package ice

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	pion "github.com/pion/ice/v2"
	"github.com/pion/stun"
	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/rs/zerolog/log"
)

const iceTimeout = 30 * time.Second

// Sender is the subset of signalclient.Client needed by the ICE manager.
type Sender interface {
	Send(remoteKey string, body *signalv1.Body) error
}

// ConnectCallback is called once ICE is established for a peer.
// endpoint is the ICE-established remote address and conn is the live net.Conn.
type ConnectCallback func(peerKey, endpoint string, conn net.Conn)

// Manager handles ICE NAT traversal for all peers.
type Manager struct {
	selfKey  string
	stunURLs []*stun.URI
	signal   Sender

	OnConnected ConnectCallback

	mu    sync.RWMutex
	peers map[string]*peerConn
}

type peerConn struct {
	agent       *pion.Agent
	offerCh     chan Offer
	answerCh    chan Answer
	candidateCh chan string
	cancel      context.CancelFunc
}

func newPeerConn(cancel context.CancelFunc) *peerConn {
	return &peerConn{
		offerCh:     make(chan Offer, 1),
		answerCh:    make(chan Answer, 1),
		candidateCh: make(chan string, 64),
		cancel:      cancel,
	}
}

// New creates an ICE Manager. stunHosts are full URIs like "stun:host:port".
func New(selfKey string, stunHosts []string, signal Sender) *Manager {
	return &Manager{
		selfKey:  selfKey,
		stunURLs: parseSTUNURLs(stunHosts),
		signal:   signal,
		peers:    make(map[string]*peerConn),
	}
}

// StartConnect initiates ICE towards peerKey (idempotent).
func (m *Manager) StartConnect(ctx context.Context, peerKey string) {
	m.mu.Lock()
	if _, exists := m.peers[peerKey]; exists {
		m.mu.Unlock()
		return
	}
	pCtx, cancel := context.WithCancel(ctx)
	pc := newPeerConn(cancel)
	m.peers[peerKey] = pc
	m.mu.Unlock()

	go m.runPeer(pCtx, peerKey, pc)
}

// ClosePeer tears down ICE for a specific peer.
func (m *Manager) ClosePeer(peerKey string) {
	m.mu.Lock()
	pc, ok := m.peers[peerKey]
	delete(m.peers, peerKey)
	m.mu.Unlock()
	if ok {
		pc.cancel()
		if pc.agent != nil {
			_ = pc.agent.Close()
		}
	}
}

// HandleSignal dispatches an incoming signal message to the correct peer.
func (m *Manager) HandleSignal(msg *signalv1.Message) {
	if msg.Body == nil {
		return
	}
	peerKey := msg.Key

	switch msg.Body.Type {
	case signalv1.Body_OFFER:
		offer, err := unmarshalOffer(msg.Body.Payload)
		if err != nil {
			log.Warn().Err(err).Msg("ICE: bad offer payload")
			return
		}
		// Responder side: create peerConn if not already started.
		m.mu.Lock()
		pc, exists := m.peers[peerKey]
		if !exists {
			pCtx, cancel := context.WithCancel(context.Background())
			pc = newPeerConn(cancel)
			m.peers[peerKey] = pc
			m.mu.Unlock()
			go m.runPeer(pCtx, peerKey, pc)
		} else {
			m.mu.Unlock()
		}
		select {
		case pc.offerCh <- offer:
		default:
		}

	case signalv1.Body_ANSWER:
		answer, err := unmarshalAnswer(msg.Body.Payload)
		if err != nil {
			return
		}
		m.mu.RLock()
		pc, ok := m.peers[peerKey]
		m.mu.RUnlock()
		if ok {
			select {
			case pc.answerCh <- answer:
			default:
			}
		}

	case signalv1.Body_CANDIDATE:
		cand, err := unmarshalCandidate(msg.Body.Payload)
		if err != nil {
			return
		}
		m.mu.RLock()
		pc, ok := m.peers[peerKey]
		m.mu.RUnlock()
		if ok {
			select {
			case pc.candidateCh <- cand.Candidate:
			default:
			}
		}
	}
}

// runPeer runs the full ICE lifecycle for one peer.
func (m *Manager) runPeer(ctx context.Context, peerKey string, pc *peerConn) {
	defer func() {
		m.mu.Lock()
		if m.peers[peerKey] == pc {
			delete(m.peers, peerKey)
		}
		m.mu.Unlock()
	}()

	// Lexicographically smaller key = controller.
	isController := m.selfKey < peerKey

	agent, err := pion.NewAgent(&pion.AgentConfig{
		NetworkTypes: []pion.NetworkType{pion.NetworkTypeUDP4, pion.NetworkTypeUDP6},
		Urls:         m.stunURLs,
	})
	if err != nil {
		log.Error().Err(err).Str("peer", shortKey(peerKey)).Msg("ICE: agent create failed")
		return
	}
	pc.agent = agent
	defer agent.Close()

	if err := agent.OnCandidate(func(c pion.Candidate) {
		if c == nil {
			return
		}
		m.signal.Send(peerKey, &signalv1.Body{ //nolint:errcheck
			Type:    signalv1.Body_CANDIDATE,
			Payload: marshalCandidate(Candidate{Candidate: c.Marshal()}),
		})
	}); err != nil {
		return
	}

	if err := agent.GatherCandidates(); err != nil {
		log.Error().Err(err).Msg("ICE: gather failed")
		return
	}

	localUfrag, localPwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, iceTimeout)
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case raw := <-pc.candidateCh:
				c, err := pion.UnmarshalCandidate(raw)
				if err != nil {
					continue
				}
				_ = agent.AddRemoteCandidate(c)
			}
		}
	}()

	var conn net.Conn

	if isController {
		m.signal.Send(peerKey, &signalv1.Body{ //nolint:errcheck
			Type:    signalv1.Body_OFFER,
			Payload: marshalOffer(Offer{Ufrag: localUfrag, Pwd: localPwd}),
		})
		select {
		case <-ctx.Done():
			return
		case answer := <-pc.answerCh:
			if err := agent.SetRemoteCredentials(answer.Ufrag, answer.Pwd); err != nil {
				return
			}
		}
		conn, err = agent.Dial(ctx, localUfrag, localPwd)
	} else {
		select {
		case <-ctx.Done():
			return
		case offer := <-pc.offerCh:
			if err := agent.SetRemoteCredentials(offer.Ufrag, offer.Pwd); err != nil {
				return
			}
			m.signal.Send(peerKey, &signalv1.Body{ //nolint:errcheck
				Type:    signalv1.Body_ANSWER,
				Payload: marshalAnswer(Answer{Ufrag: localUfrag, Pwd: localPwd}),
			})
		}
		conn, err = agent.Accept(ctx, localUfrag, localPwd)
	}

	if err != nil {
		log.Warn().Err(err).Str("peer", shortKey(peerKey)).Bool("controller", isController).Msg("ICE connect failed")
		return
	}

	endpoint := conn.RemoteAddr().String()
	log.Info().
		Str("peer", shortKey(peerKey)).
		Str("endpoint", endpoint).
		Bool("controller", isController).
		Msg("ICE connected")

	if m.OnConnected != nil {
		m.OnConnected(peerKey, endpoint, conn)
	}
}

func parseSTUNURLs(hosts []string) []*stun.URI {
	var urls []*stun.URI
	for _, h := range hosts {
		u, err := stun.ParseURI(h)
		if err == nil {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		u, _ := stun.ParseURI(fmt.Sprintf("stun:stun.l.google.com:19302"))
		urls = append(urls, u)
	}
	return urls
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}
