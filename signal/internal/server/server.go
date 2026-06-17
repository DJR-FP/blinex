package server

import (
	"io"
	"sync"

	signalv1 "github.com/meshnet/gen/signal/v1"
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

	defer func() {
		if peerKey != "" {
			s.mu.Lock()
			delete(s.streams, peerKey)
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
			peerKey = msg.Key
			s.mu.Lock()
			s.streams[peerKey] = stream
			s.mu.Unlock()
			log.Info().Str("peer", peerKey[:min(8, len(peerKey))]).Msg("signal peer connected")
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
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
