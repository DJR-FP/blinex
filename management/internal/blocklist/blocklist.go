// Package blocklist fetches and compiles the malicious-domain feed that
// agents poll via ManagementService.GetBlocklist. It supports the two feed
// formats in common use: a hosts file ("0.0.0.0 bad.example" per line, as
// abuse.ch URLhaus publishes) and a plain domain-per-line list. Comments
// (#) and blank lines are ignored.
package blocklist

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Store holds the currently compiled domain list, safe for concurrent reads
// from many gRPC handlers while a background fetch swaps in a new version.
type Store struct {
	mu      sync.RWMutex
	domains []string
	version string
}

// NewStore returns an empty, disabled-by-default store — Run populates it.
func NewStore() *Store {
	return &Store{}
}

// Snapshot returns the current domain list and its version hash.
func (s *Store) Snapshot() (domains []string, version string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domains, s.version
}

// Run fetches the feed immediately, then re-fetches every interval until ctx
// is cancelled. A fetch failure logs a warning and keeps serving the last
// good list rather than blanking it out. feedURL == "" disables filtering
// entirely — Run returns immediately and the store stays empty forever.
func (s *Store) Run(ctx context.Context, feedURL string, interval time.Duration) {
	if feedURL == "" {
		log.Info().Msg("blocklist: no feed URL configured, domain filtering disabled")
		return
	}
	s.refresh(ctx, feedURL)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh(ctx, feedURL)
		}
	}
}

func (s *Store) refresh(ctx context.Context, feedURL string) {
	domains, err := fetch(ctx, feedURL)
	if err != nil {
		log.Warn().Err(err).Str("url", feedURL).Msg("blocklist: fetch failed, keeping previous list")
		return
	}
	version := hashDomains(domains)

	s.mu.Lock()
	changed := version != s.version
	s.domains = domains
	s.version = version
	s.mu.Unlock()

	if changed {
		log.Info().Int("domains", len(domains)).Str("version", version[:12]).Msg("blocklist: feed updated")
	}
}

func fetch(ctx context.Context, feedURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned status %d", resp.StatusCode)
	}
	return parse(resp.Body)
}

// parse accepts a hosts-file ("0.0.0.0 domain.example") or plain
// domain-per-line feed and returns the deduplicated, lowercased domain list.
func parse(r io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		domain := fields[0]
		if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
			domain = fields[1]
		}
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if domain == "" || domain == "localhost" {
			continue
		}
		seen[domain] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading feed: %w", err)
	}
	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	return domains, nil
}

func hashDomains(domains []string) string {
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, d := range sorted {
		h.Write([]byte(d))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
