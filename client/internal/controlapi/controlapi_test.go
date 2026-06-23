package controlapi

import (
	"path/filepath"
	"testing"
)

func TestServeAndQuery(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	want := Status{
		Version: "1.2.3", Hostname: "host-a", SelfIP: "100.64.0.1/32",
		Interface: "blinex0", Mode: "kernel", DNSSuffix: "blinex",
		Peers: []PeerInfo{{Hostname: "host-b", IP: "100.64.0.2", DNSName: "host-b.blinex", Path: "direct"}},
		Routes: []RouteInfo{{Network: "192.168.1.0/24", Via: "host-b", Enabled: true}},
	}
	closeFn, err := Serve(sock, func() Status { return want })
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()

	got, err := Query(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || len(got.Peers) != 1 || got.Peers[0].Path != "direct" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if len(got.Routes) != 1 || got.Routes[0].Network != "192.168.1.0/24" {
		t.Fatalf("routes mismatch: %+v", got.Routes)
	}
	t.Logf("status roundtrip OK: v%s, %d peer(s) [%s], %d route(s)", got.Version, len(got.Peers), got.Peers[0].Path, len(got.Routes))
}

func TestQueryNoAgent(t *testing.T) {
	if _, err := Query(filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("expected error when agent not running")
	}
	t.Log("query against missing socket errors as expected")
}
