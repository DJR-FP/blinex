// Package controlapi exposes the running agent's live state over a local Unix
// socket, and provides a client used by the `blinex-agent status|peers|routes`
// subcommands. Modeled on the Netbird/Tailscale CLI status pattern.
package controlapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// DefaultSocket is where the daemon listens and the CLI connects by default.
const DefaultSocket = "/var/run/blinex-agent.sock"

// Status is the full snapshot returned by the daemon.
type Status struct {
	Version   string      `json:"version"`
	Hostname  string      `json:"hostname"`
	SelfIP    string      `json:"self_ip"`
	Interface string      `json:"interface"`
	Mode      string      `json:"mode"` // "kernel" or "netstack"
	DNSSuffix string      `json:"dns_suffix"`
	Peers     []PeerInfo  `json:"peers"`
	Routes    []RouteInfo `json:"routes"`
}

// PeerInfo describes one remote peer.
type PeerInfo struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	DNSName  string `json:"dns_name"`
	Path     string `json:"path"` // "direct" or "relay"
}

// RouteInfo describes an advertised subnet / exit-node route.
type RouteInfo struct {
	Network string `json:"network"`
	Via     string `json:"via"`     // gateway hostname, or "this device"
	Self    bool   `json:"self"`    // advertised by this device
	Enabled bool   `json:"enabled"`
}

// Serve starts the control socket. The provider is called on each request to
// build a fresh snapshot. Returns a closer that stops the server and removes
// the socket file.
func Serve(socketPath string, provider func() Status) (func(), error) {
	if socketPath == "" {
		socketPath = DefaultSocket
	}
	_ = os.Remove(socketPath) // clear a stale socket from a previous run
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	_ = os.Chmod(socketPath, 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(provider())
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.Remove(socketPath)
	}, nil
}

// Query connects to the daemon's control socket and returns its status.
func Query(socketPath string) (Status, error) {
	if socketPath == "" {
		socketPath = DefaultSocket
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	resp, err := client.Get("http://unix/status")
	if err != nil {
		return Status{}, fmt.Errorf("agent not reachable on %s (is it running?): %w", socketPath, err)
	}
	defer resp.Body.Close()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return Status{}, fmt.Errorf("decoding status: %w", err)
	}
	return st, nil
}
