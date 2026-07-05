package server

import (
	"io"
	"sync"

	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/blinex/signal/internal/auth"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements SignalService. It routes messages between peers using their
// WireGuard public keys as addresses — no persistence, pure in-process routing.
type Server struct {
	signalv1.UnimplementedSignalServiceServer

	mu      sync.RWMutex
	streams map[string]signalv1.SignalService_SendServer // wgPubKey → stream
}

func New() *Server {
	return &Server{streams: make(map[string]signalv1.SignalService_SendServer)}
}

func (s *Server) Send(stream signalv1.SignalService_SendServer) error {
	var peerKey string

	// When JWT auth is enabled the interceptor puts the caller's verified
	// wg_pub_key in the context. A peer may only register under that key,
	// preventing it from hijacking another peer's signaling stream.
	authKey, authenticated := auth.KeyFromContext(stream.Context())

	defer func() {
		if peerKey != "" {
			s.mu.Lock()
			// Only remove our own registration; a reconnect may have already
			// replaced this key with a newer stream.
			if s.streams[peerKey] == stream {
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
			s.streams[peerKey] = stream
			s.mu.Unlock()
			log.Info().Str("peer", peerKey[:min(8, len(peerKey))]).Msg("signal peer connected")
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
			// Target is not yet connected — the client will retry via ICE restarts.
			log.Debug().Str("remote", msg.RemoteKey[:min(8, len(msg.RemoteKey))]).Msg("target peer not connected")
			continue
		}

		if err := target.Send(msg); err != nil {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
