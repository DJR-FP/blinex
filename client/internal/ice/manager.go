package ice

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	pion "github.com/pion/ice/v2"
	"github.com/pion/logging"
	"github.com/pion/stun"
	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/rs/zerolog/log"
)

const iceTimeout = 90 * time.Second

type Sender interface {
	Send(remoteKey string, body *signalv1.Body) error
}

type ConnectCallback func(peerKey, endpoint string, conn net.Conn)

type Manager struct {
	selfKey  string
	stunURLs []*stun.URI
	turnUser string
	turnPass string
	signal   Sender

	OnConnected ConnectCallback

	mu    sync.RWMutex
	peers map[string]*peerConn
}

type peerConn struct {
	offerCh  chan iceExchange
	answerCh chan iceExchange
	cancel   context.CancelFunc
}

// iceExchange bundles credentials + all candidates in one message.
type iceExchange struct {
	Ufrag      string   `json:"ufrag"`
	Pwd        string   `json:"pwd"`
	Candidates []string `json:"candidates"`
}

func newPeerConn(cancel context.CancelFunc) *peerConn {
	return &peerConn{
		offerCh:  make(chan iceExchange, 1),
		answerCh: make(chan iceExchange, 1),
		cancel:   cancel,
	}
}

func New(selfKey string, stunHosts []string, turnUser, turnPass string, signal Sender) *Manager {
	urls := parseSTUNURLs(stunHosts)
	for _, u := range urls {
		if u.Scheme == stun.SchemeTypeTURN || u.Scheme == stun.SchemeTypeTURNS {
			u.Username = turnUser
			u.Password = turnPass
		}
	}
	return &Manager{
		selfKey:  selfKey,
		stunURLs: urls,
		turnUser: turnUser,
		turnPass: turnPass,
		signal:   signal,
		peers:    make(map[string]*peerConn),
	}
}

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

	go m.runPeerWithRetry(pCtx, peerKey)
}

func (m *Manager) ClosePeer(peerKey string) {
	m.mu.Lock()
	pc, ok := m.peers[peerKey]
	delete(m.peers, peerKey)
	m.mu.Unlock()
	if ok {
		pc.cancel()
	}
}

func (m *Manager) HandleSignal(msg *signalv1.Message) {
	if msg.Body == nil {
		return
	}
	peerKey := msg.Key

	switch msg.Body.Type {
	case signalv1.Body_OFFER:
		var ex iceExchange
		if err := json.Unmarshal([]byte(msg.Body.Payload), &ex); err != nil {
			log.Warn().Err(err).Msg("ICE: bad offer payload")
			return
		}
		m.mu.Lock()
		pc, exists := m.peers[peerKey]
		if !exists {
			pCtx, cancel := context.WithCancel(context.Background())
			pc = newPeerConn(cancel)
			m.peers[peerKey] = pc
			m.mu.Unlock()
			go m.runPeerWithRetry(pCtx, peerKey)
		} else {
			m.mu.Unlock()
		}
		select {
		case pc.offerCh <- ex:
		default:
		}

	case signalv1.Body_ANSWER:
		var ex iceExchange
		if err := json.Unmarshal([]byte(msg.Body.Payload), &ex); err != nil {
			return
		}
		m.mu.RLock()
		pc, ok := m.peers[peerKey]
		m.mu.RUnlock()
		if ok {
			select {
			case pc.answerCh <- ex:
			default:
			}
		}
	}
}

func (m *Manager) runPeerWithRetry(ctx context.Context, peerKey string) {
	backoff := 5 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		m.mu.Lock()
		pc, exists := m.peers[peerKey]
		if !exists {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()

		m.runPeer(ctx, peerKey, pc)

		select {
		case <-ctx.Done():
			return
		default:
		}

		m.mu.RLock()
		_, stillTracked := m.peers[peerKey]
		m.mu.RUnlock()
		if !stillTracked {
			return
		}

		m.mu.Lock()
		newPC := newPeerConn(pc.cancel)
		m.peers[peerKey] = newPC
		m.mu.Unlock()

		log.Debug().Str("peer", shortKey(peerKey)).Dur("backoff", backoff).Msg("ICE: retrying connection")

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxBackoff)
	}
}

func (m *Manager) runPeer(ctx context.Context, peerKey string, pc *peerConn) {
	isController := m.selfKey < peerKey

	logFactory := logging.NewDefaultLoggerFactory()
	logFactory.DefaultLogLevel = logging.LogLevelInfo

	agent, err := pion.NewAgent(&pion.AgentConfig{
		NetworkTypes:        []pion.NetworkType{pion.NetworkTypeUDP4},
		Urls:                m.stunURLs,
		CandidateTypes:      []pion.CandidateType{pion.CandidateTypeHost, pion.CandidateTypeServerReflexive, pion.CandidateTypeRelay},
		LoggerFactory:       logFactory,
		DisconnectedTimeout: durationPtr(iceTimeout),
		FailedTimeout:       durationPtr(iceTimeout),
		CheckInterval:       durationPtr(200 * time.Millisecond),
	})
	if err != nil {
		log.Error().Err(err).Str("peer", shortKey(peerKey)).Msg("ICE: agent create failed")
		return
	}
	defer agent.Close()

	if err := agent.OnConnectionStateChange(func(state pion.ConnectionState) {
		log.Info().Str("peer", shortKey(peerKey)).Str("state", state.String()).Msg("ICE: state")
	}); err != nil {
		return
	}

	if err := agent.OnSelectedCandidatePairChange(func(local, remote pion.Candidate) {
		log.Info().
			Str("peer", shortKey(peerKey)).
			Str("local", fmt.Sprintf("%s %s:%d", local.Type(), local.Address(), local.Port())).
			Str("remote", fmt.Sprintf("%s %s:%d", remote.Type(), remote.Address(), remote.Port())).
			Msg("ICE: selected pair")
	}); err != nil {
		return
	}

	// Gather ALL candidates before signaling (vanilla ICE, not trickle).
	var localCandidates []string
	gatherDone := make(chan struct{})
	if err := agent.OnCandidate(func(c pion.Candidate) {
		if c == nil {
			close(gatherDone)
			return
		}
		localCandidates = append(localCandidates, c.Marshal())
		log.Debug().
			Str("peer", shortKey(peerKey)).
			Str("type", c.Type().String()).
			Str("addr", fmt.Sprintf("%s:%d", c.Address(), c.Port())).
			Msg("ICE: gathered")
	}); err != nil {
		return
	}

	if err := agent.GatherCandidates(); err != nil {
		log.Error().Err(err).Msg("ICE: gather failed")
		return
	}

	// Wait for gathering to complete (includes relay candidates).
	select {
	case <-ctx.Done():
		return
	case <-gatherDone:
	case <-time.After(10 * time.Second):
		log.Warn().Str("peer", shortKey(peerKey)).Msg("ICE: gather timeout, proceeding with available candidates")
	}

	localUfrag, localPwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return
	}

	log.Info().
		Str("peer", shortKey(peerKey)).
		Int("candidates", len(localCandidates)).
		Bool("controller", isController).
		Msg("ICE: gathering complete, starting signaling")

	ctx, cancel := context.WithTimeout(ctx, iceTimeout)
	defer cancel()

	var conn net.Conn
	var remoteUfrag, remotePwd string
	var remoteCandidates []string

	if isController {
		// Send OFFER with all candidates.
		payload, _ := json.Marshal(iceExchange{
			Ufrag:      localUfrag,
			Pwd:        localPwd,
			Candidates: localCandidates,
		})
		m.signal.Send(peerKey, &signalv1.Body{
			Type:    signalv1.Body_OFFER,
			Payload: string(payload),
		})

		// Wait for ANSWER with all remote candidates.
		select {
		case <-ctx.Done():
			return
		case answer := <-pc.answerCh:
			remoteUfrag = answer.Ufrag
			remotePwd = answer.Pwd
			remoteCandidates = answer.Candidates
		}

		log.Info().
			Str("peer", shortKey(peerKey)).
			Int("remote_candidates", len(remoteCandidates)).
			Msg("ICE: got ANSWER, adding remote candidates")

	} else {
		// Wait for OFFER with all remote candidates.
		select {
		case <-ctx.Done():
			return
		case offer := <-pc.offerCh:
			remoteUfrag = offer.Ufrag
			remotePwd = offer.Pwd
			remoteCandidates = offer.Candidates
		}

		// Send ANSWER with all candidates.
		payload, _ := json.Marshal(iceExchange{
			Ufrag:      localUfrag,
			Pwd:        localPwd,
			Candidates: localCandidates,
		})
		m.signal.Send(peerKey, &signalv1.Body{
			Type:    signalv1.Body_ANSWER,
			Payload: string(payload),
		})

		log.Info().
			Str("peer", shortKey(peerKey)).
			Int("remote_candidates", len(remoteCandidates)).
			Msg("ICE: got OFFER, sent ANSWER, adding remote candidates")
	}

	// Add ALL remote candidates before starting Dial/Accept.
	for _, raw := range remoteCandidates {
		c, err := pion.UnmarshalCandidate(raw)
		if err != nil {
			continue
		}
		log.Debug().
			Str("peer", shortKey(peerKey)).
			Str("type", c.Type().String()).
			Str("addr", fmt.Sprintf("%s:%d", c.Address(), c.Port())).
			Msg("ICE: remote candidate")
		agent.AddRemoteCandidate(c)
	}

	// Now start Dial/Accept — all candidates are in place.
	if isController {
		log.Info().Str("peer", shortKey(peerKey)).Msg("ICE: starting Dial")
		conn, err = agent.Dial(ctx, remoteUfrag, remotePwd)
	} else {
		log.Info().Str("peer", shortKey(peerKey)).Msg("ICE: starting Accept")
		conn, err = agent.Accept(ctx, remoteUfrag, remotePwd)
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
		u, _ := stun.ParseURI("stun:stun.l.google.com:19302")
		urls = append(urls, u)
	}
	return urls
}

func durationPtr(d time.Duration) *time.Duration { return &d }

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}
