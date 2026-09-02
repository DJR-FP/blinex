package dns

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func queryA(t *testing.T, addr, name string) *dnsmessage.Message {
	t.Helper()
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(packed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return &resp
}

// startResolver runs a resolver on an ephemeral port. Upstream points at a sink
// that never replies, so only local records resolve within the test.
func startResolver(t *testing.T) *Resolver {
	t.Helper()
	r := New("127.0.0.1:0", "blinex", "127.0.0.1:9") // port 9 (discard) as dead upstream
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.listenAddr = pc.LocalAddr().String()
	_ = pc.Close()
	go func() { _ = r.Serve() }()
	time.Sleep(50 * time.Millisecond)
	return r
}

func TestUpsertAndResolveA(t *testing.T) {
	r := startResolver(t)
	r.Upsert("laptop", "100.64.0.7")
	resp := queryA(t, r.listenAddr, "laptop.blinex.")
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	a, ok := resp.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answers[0].Body)
	}
	if net.IP(a.A[:]).String() != "100.64.0.7" {
		t.Fatalf("wrong IP: %s", net.IP(a.A[:]).String())
	}
}

func TestRemoveRecord(t *testing.T) {
	r := New("x", "blinex", "8.8.8.8:53")
	r.Upsert("host", "100.64.0.1")
	r.Remove("host")
	r.mu.RLock()
	_, ok := r.records["host.blinex."]
	r.mu.RUnlock()
	if ok {
		t.Fatal("record should be removed")
	}
}

// TestMalformedIPDoesNotPanic guards the nil ip.To4() regression: a record with
// an unparseable IP must not crash the handler goroutine.
func TestMalformedIPDoesNotPanic(t *testing.T) {
	r := startResolver(t)
	r.mu.Lock()
	r.records["bad.blinex."] = net.ParseIP("not-an-ip") // nil
	r.mu.Unlock()
	// Must not panic; with a dead upstream the query simply times out server-side.
	conn, _ := net.Dial("udp", r.listenAddr)
	defer conn.Close()
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("bad.blinex."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packed, _ := msg.Pack()
	_, _ = conn.Write(packed)
	// If the server panicked the process would crash; reaching here is success.
	time.Sleep(100 * time.Millisecond)
}

// TestConcurrentQueriesNoCorruption exercises the buffer-copy fix: many
// simultaneous queries must each get their own correct answer.
func TestConcurrentQueriesNoCorruption(t *testing.T) {
	r := startResolver(t)
	r.Upsert("a", "100.64.0.1")
	r.Upsert("b", "100.64.0.2")

	done := make(chan bool, 20)
	for i := 0; i < 10; i++ {
		go func() {
			resp := queryA(t, r.listenAddr, "a.blinex.")
			ok := len(resp.Answers) == 1
			if ok {
				ar := resp.Answers[0].Body.(*dnsmessage.AResource)
				ok = net.IP(ar.A[:]).String() == "100.64.0.1"
			}
			done <- ok
		}()
		go func() {
			resp := queryA(t, r.listenAddr, "b.blinex.")
			ok := len(resp.Answers) == 1
			if ok {
				ar := resp.Answers[0].Body.(*dnsmessage.AResource)
				ok = net.IP(ar.A[:]).String() == "100.64.0.2"
			}
			done <- ok
		}()
	}
	for i := 0; i < 20; i++ {
		if !<-done {
			t.Fatal("concurrent query returned wrong/empty answer (buffer corruption)")
		}
	}
}

func TestBlockedDomainReturnsNXDOMAIN(t *testing.T) {
	r := startResolver(t)
	r.SetBlocklist([]string{"evil.example"})
	resp := queryA(t, r.listenAddr, "evil.example.")
	if resp.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN, got RCode %v", resp.Header.RCode)
	}
	if len(resp.Answers) != 0 {
		t.Fatalf("expected no answers for a blocked domain, got %d", len(resp.Answers))
	}
}

func TestBlockedDomainBlocksSubdomains(t *testing.T) {
	r := startResolver(t)
	r.SetBlocklist([]string{"evil.example"})
	resp := queryA(t, r.listenAddr, "c2.evil.example.")
	if resp.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected subdomain of a blocked domain to be NXDOMAIN, got RCode %v", resp.Header.RCode)
	}
}

func TestBlocklistIsCaseInsensitive(t *testing.T) {
	r := startResolver(t)
	r.SetBlocklist([]string{"Evil.Example"})
	resp := queryA(t, r.listenAddr, "EVIL.EXAMPLE.")
	if resp.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected case-insensitive block, got RCode %v", resp.Header.RCode)
	}
}

// TestBlocklistDoesNotShadowMeshRecords guards the ordering in handle(): a
// mesh record must resolve normally even while an unrelated domain is
// blocked — mesh records are always checked first.
func TestBlocklistDoesNotShadowMeshRecords(t *testing.T) {
	r := startResolver(t)
	r.Upsert("laptop", "100.64.0.7")
	r.SetBlocklist([]string{"evil.example"})
	resp := queryA(t, r.listenAddr, "laptop.blinex.")
	if len(resp.Answers) != 1 {
		t.Fatalf("expected mesh record to resolve normally, got %d answers", len(resp.Answers))
	}
}

// TestSetBlocklistReplacesWholesale mirrors the netstack router's
// SetACLRules contract: each call fully replaces the previous list rather
// than merging into it.
func TestSetBlocklistReplacesWholesale(t *testing.T) {
	r := startResolver(t)
	r.SetBlocklist([]string{"first.example"})
	r.SetBlocklist([]string{"second.example"})

	resp := queryA(t, r.listenAddr, "second.example.")
	if resp.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected second.example to be blocked, got RCode %v", resp.Header.RCode)
	}
	if r.isBlocked("first.example.") {
		t.Fatal("first.example should no longer be blocked after SetBlocklist replaced the list")
	}
}
