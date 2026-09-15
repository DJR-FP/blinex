package server

import (
	"io"
	"sync"
	"time"

	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/blinex/signal/internal/auth"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// peerStream is one registered peer's stream plus the lock that serialises
// writes to it.
//
// The lock is not optional. gRPC allows only one goroutine in SendMsg on a
// given stream at a time, and every peer's Send handler runs in its own
// goroutine while routing into *other* peers' streams — so on a mesh of N
// peers, N-1 goroutines can call Send on the same target concurrently. This
// is not a rare interleaving either: WireGuard data is relayed through these
// same streams (type=RELAY), so the hot path races on every packet.
//
// Concurrent SendMsg corrupts HTTP/2 framing rather than returning an error,
// which matches what was seen live — messages the server logged as
// successfully relayed never arrived at a peer that was otherwise healthy.
type peerStream struct {
	stream signalv1.SignalService_SendServer
	mu     sync.Mutex
}

func (p *peerStream) send(msg *signalv1.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stream.Send(msg)
}

// Server implements SignalService. It routes messages between peers using their
// WireGuard public keys as addresses — no persistence, pure in-process routing.
type Server struct {
	signalv1.UnimplementedSignalServiceServer

	mu      sync.RWMutex
	streams map[string]*peerStream   // wgPubKey → stream
	pending map[string]*pendingQueue // wgPubKey → signaling held for a peer mid-reconnect
	dropLog map[string]time.Time     // wgPubKey → last "dropped relay" warning
}

func New() *Server {
	return &Server{
		streams: make(map[string]*peerStream),
		pending: make(map[string]*pendingQueue),
		dropLog: make(map[string]time.Time),
	}
}

// Signaling for a peer that is not currently registered is held briefly rather
// than discarded.
//
// A peer is absent for a few seconds whenever its agent restarts or its stream
// reconnects, and anything addressed to it in that window used to vanish with
// only a debug line. For ICE that means a lost OFFER/ANSWER/CANDIDATE and a
// negotiation that stalls until something retries — the sender never learns,
// because the relay reports nothing back.
//
// WireGuard data (Body_RELAY) is deliberately NOT held. It has UDP semantics
// and WireGuard retransmits on its own, so queueing it would add latency,
// deliver stale packets after a reconnect, and let a busy link grow the queue
// without bound. Data is dropped as before — just no longer silently.
const (
	pendingTTL     = 15 * time.Second
	pendingPerPeer = 32
	dropLogEvery   = 30 * time.Second
)

type pendingQueue struct {
	msgs []*signalv1.Message
	at   time.Time // when the newest message was queued, for expiry
}

func (s *Server) Send(stream signalv1.SignalService_SendServer) error {
	var peerKey string
	self := &peerStream{stream: stream}

	// When JWT auth is enabled the interceptor puts the caller's verified
	// wg_pub_key in the context. A peer may only register under that key,
	// preventing it from hijacking another peer's signaling stream.
	authKey, authenticated := auth.KeyFromContext(stream.Context())

	defer func() {
		if peerKey != "" {
			s.mu.Lock()
			// Only remove our own registration; a reconnect may have already
			// replaced this key with a newer stream.
			if s.streams[peerKey] == self {
				delete(s.streams, peerKey)
			}
			s.mu.Unlock()
			log.Info().Str("peer", peerKey[:min(8, len(peerKey))]).Msg("signal peer disconnected")
		}
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "recv error: %v", err)
		}

		// Register the sender on first message.
		if peerKey == "" {
			if msg.Key == "" {
				return status.Error(codes.InvalidArgument, "first message must set key")
			}
			if authenticated && msg.Key != authKey {
				return status.Error(codes.PermissionDenied, "key does not match authenticated identity")
			}
			peerKey = msg.Key
			s.mu.Lock()
			s.streams[peerKey] = self
			queued := s.takePendingLocked(peerKey)
			s.mu.Unlock()
			log.Info().Str("peer", peerKey[:min(8, len(peerKey))]).Msg("signal peer connected")

			// Deliver anything that arrived while this peer was reconnecting.
			for _, q := range queued {
				if err := self.send(q); err != nil {
					log.Warn().Err(err).Str("peer", peerKey[:min(8, len(peerKey))]).
						Msg("failed to deliver signaling held during reconnect")
					break
				}
			}
			if len(queued) > 0 {
				log.Info().Str("peer", peerKey[:min(8, len(peerKey))]).Int("messages", len(queued)).
					Msg("delivered signaling held during reconnect")
			}
		} else if msg.Key != peerKey {
			// A peer must not change its identity mid-stream.
			return status.Error(codes.PermissionDenied, "key changed mid-stream")
		}

		if msg.RemoteKey == "" {
			continue
		}

		// Route to the target peer.
		s.mu.RLock()
		target, ok := s.streams[msg.RemoteKey]
		s.mu.RUnlock()

		if !ok {
			s.handleAbsentTarget(msg)
			continue
		}

		if err := target.send(msg); err != nil {
			log.Warn().Err(err).Str("remote", msg.RemoteKey[:min(8, len(msg.RemoteKey))]).Msg("failed to forward signal message")
		} else {
			log.Debug().
				Str("from", msg.Key[:min(8, len(msg.Key))]).
				Str("to", msg.RemoteKey[:min(8, len(msg.RemoteKey))]).
				Str("type", msg.Body.GetType().String()).
				Msg("signal message relayed")
		}
	}
}

// handleAbsentTarget queues signaling for a peer that is not currently
// registered, and reports dropped data traffic.
func (s *Server) handleAbsentTarget(msg *signalv1.Message) {
	short := msg.RemoteKey[:min(8, len(msg.RemoteKey))]

	if msg.Body.GetType() == signalv1.Body_RELAY {
		// Data: drop, but say so. Silent drops here are what made a
		// one-directional outage undiagnosable from the server side.
		s.mu.Lock()
		last, seen := s.dropLog[msg.RemoteKey]
		now := time.Now()
		shouldLog := !seen || now.Sub(last) >= dropLogEvery
		if shouldLog {
			s.dropLog[msg.RemoteKey] = now
		}
		s.mu.Unlock()
		if shouldLog {
			log.Warn().Str("remote", short).
				Msg("dropping relayed data: target peer not connected")
		}
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expirePendingLocked()

	q := s.pending[msg.RemoteKey]
	if q == nil {
		q = &pendingQueue{}
		s.pending[msg.RemoteKey] = q
	}
	if len(q.msgs) >= pendingPerPeer {
		// Keep the newest: a stale OFFER is worthless next to the one that
		// followed it, and an unbounded queue for a peer that never returns
		// is a leak.
		q.msgs = q.msgs[1:]
	}
	q.msgs = append(q.msgs, msg)
	q.at = time.Now()
	log.Debug().Str("remote", short).Int("queued", len(q.msgs)).
		Msg("holding signaling for a peer that is not connected")
}

// takePendingLocked returns and clears anything held for peerKey. Caller holds s.mu.
func (s *Server) takePendingLocked(peerKey string) []*signalv1.Message {
	q := s.pending[peerKey]
	if q == nil {
		return nil
	}
	delete(s.pending, peerKey)
	if time.Since(q.at) > pendingTTL {
		return nil // too old to be useful; ICE will have moved on
	}
	return q.msgs
}

// expirePendingLocked drops queues for peers that never came back. Caller holds s.mu.
func (s *Server) expirePendingLocked() {
	for k, q := range s.pending {
		if time.Since(q.at) > pendingTTL {
			delete(s.pending, k)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
