package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseHostsFileFormat(t *testing.T) {
	body := "# comment\n0.0.0.0 evil.example\n0.0.0.0 c2.example\n\n127.0.0.1 also-bad.example\n"
	domains, err := parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"evil.example": true, "c2.example": true, "also-bad.example": true}
	if len(domains) != len(want) {
		t.Fatalf("got %d domains, want %d: %v", len(domains), len(want), domains)
	}
	for _, d := range domains {
		if !want[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
}

func TestParsePlainDomainList(t *testing.T) {
	body := "evil.example\nc2.example\n"
	domains, err := parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2: %v", len(domains), domains)
	}
}

func TestParseDeduplicatesAndLowercases(t *testing.T) {
	body := "Evil.Example\nevil.example\nEVIL.EXAMPLE\n"
	domains, err := parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0] != "evil.example" {
		t.Fatalf("expected exactly one lowercased domain, got %v", domains)
	}
}

func TestParseSkipsLocalhost(t *testing.T) {
	body := "0.0.0.0 localhost\n0.0.0.0 evil.example\n"
	domains, err := parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0] != "evil.example" {
		t.Fatalf("expected localhost to be filtered out, got %v", domains)
	}
}

func TestHashDomainsStableAcrossOrder(t *testing.T) {
	a := hashDomains([]string{"b.example", "a.example"})
	b := hashDomains([]string{"a.example", "b.example"})
	if a != b {
		t.Fatal("hash must not depend on input order")
	}
}

func TestHashDomainsChangesWithContent(t *testing.T) {
	a := hashDomains([]string{"a.example"})
	b := hashDomains([]string{"a.example", "b.example"})
	if a == b {
		t.Fatal("hash should differ when content differs")
	}
}

func TestStoreRunFetchesAndUpdatesVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 evil.example\n"))
	}))
	defer srv.Close()

	s := NewStore()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Run blocks on its ticker loop; a single synchronous refresh is enough
	// to test the fetch-and-store path, so call it directly instead of Run.
	s.refresh(ctx, srv.URL)

	domains, version := s.Snapshot()
	if len(domains) != 1 || domains[0] != "evil.example" {
		t.Fatalf("expected [evil.example], got %v", domains)
	}
	if version == "" {
		t.Fatal("expected a non-empty version after a successful fetch")
	}
}

func TestStoreKeepsPreviousListOnFetchFailure(t *testing.T) {
	s := NewStore()
	ctx := context.Background()
	// Prime the store via a successful fetch, then point at a dead URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("evil.example\n"))
	}))
	s.refresh(ctx, srv.URL)
	srv.Close() // now unreachable

	s.refresh(ctx, srv.URL)

	domains, _ := s.Snapshot()
	if len(domains) != 1 || domains[0] != "evil.example" {
		t.Fatalf("expected previous list to survive a failed fetch, got %v", domains)
	}
}

func TestRunWithEmptyURLDisablesFiltering(t *testing.T) {
	s := NewStore()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s.Run(ctx, "", time.Hour) // must return immediately, not block until ctx expires

	domains, version := s.Snapshot()
	if len(domains) != 0 || version != "" {
		t.Fatalf("expected an empty store when no feed URL is configured, got domains=%v version=%q", domains, version)
	}
}
