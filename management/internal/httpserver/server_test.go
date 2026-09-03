package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinex/management/internal/auth"
	"github.com/blinex/management/internal/domain"
	"github.com/blinex/management/internal/store/memory"
)

const secret = "test-secret-at-least-32-bytes-long!!"

func newTestServer() (*Server, *memory.Store, *auth.Manager) {
	st := memory.New("seed-key")
	authMgr := auth.NewManager(secret)
	released := map[string]bool{}
	s := New(st, authMgr, func(string) {}, func() map[string]bool { return nil },
		func(k string) { released[k] = true }, "test", "admin", "adminpass")
	return s, st, authMgr
}

func do(s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func adminToken(a *auth.Manager) string { t, _ := a.IssueAdminToken("default"); return t }
func peerToken(a *auth.Manager) string  { t, _ := a.IssueToken("p", "k", "default"); return t }

// ---- validation helpers ----

func TestIsValidGroupName(t *testing.T) {
	good := []string{"prod", "web-1", "a_b", "x", "UPPER", "Default"}
	bad := []string{"", "-lead", "has space", "sym!"}
	for _, g := range good {
		if !isValidGroupName(g) {
			t.Errorf("expected %q valid", g)
		}
	}
	for _, b := range bad {
		if isValidGroupName(b) {
			t.Errorf("expected %q invalid", b)
		}
	}
}

func TestValidateRuleFields(t *testing.T) {
	if err := validateRuleFields("*", "group:web", "tcp", 80); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}
	if err := validateRuleFields("10.0.0.0/24", "1.2.3.4", "all", 0); err != nil {
		t.Errorf("valid CIDR/IP rejected: %v", err)
	}
	if err := validateRuleFields("bogus", "*", "tcp", 80); err == nil {
		t.Error("expected invalid src to fail")
	}
	if err := validateRuleFields("*", "*", "ftp", 80); err == nil {
		t.Error("expected invalid protocol to fail")
	}
	if err := validateRuleFields("*", "*", "tcp", 99999); err == nil {
		t.Error("expected out-of-range port to fail")
	}
	if err := validateRuleFields("group:", "*", "tcp", 0); err == nil {
		t.Error("expected empty group name to fail")
	}
}

func TestParseOrigins(t *testing.T) {
	if got := parseOrigins(""); len(got) != 2 {
		t.Fatalf("empty should default to 2 localhost origins, got %v", got)
	}
	got := parseOrigins("https://a.com, https://b.com ,")
	if len(got) != 2 || got[0] != "https://a.com" || got[1] != "https://b.com" {
		t.Fatalf("unexpected parse: %v", got)
	}
}

// ---- auth / authorization ----

func TestUnauthenticatedRejected(t *testing.T) {
	s, _, _ := newTestServer()
	if rec := do(s, "GET", "/api/v1/peers", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestPeerTokenCannotWrite(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1"})
	rec := do(s, "DELETE", "/api/v1/peers/k1", peerToken(a), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for peer-role write, got %d", rec.Code)
	}
}

func TestPeerTokenCanReadPeers(t *testing.T) {
	s, _, a := newTestServer()
	rec := do(s, "GET", "/api/v1/peers", peerToken(a), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestHealthIsPublic(t *testing.T) {
	s, _, _ := newTestServer()
	if rec := do(s, "GET", "/api/v1/health", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 health, got %d", rec.Code)
	}
}

// ---- admin login ----

func TestAdminLoginSuccessAndFailure(t *testing.T) {
	s, _, _ := newTestServer()
	ok := do(s, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "adminpass"})
	if ok.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", ok.Code)
	}
	var body struct{ Token string }
	_ = json.Unmarshal(ok.Body.Bytes(), &body)
	if body.Token == "" {
		t.Fatal("expected token in login response")
	}
	bad := do(s, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "wrong"})
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad password, got %d", bad.Code)
	}
}

func TestAdminLoginDisabledWhenNoPassword(t *testing.T) {
	st := memory.New("seed-key")
	a := auth.NewManager(secret)
	s := New(st, a, func(string) {}, func() map[string]bool { return nil }, func(string) {}, "t", "admin", "")
	rec := do(s, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "x"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when admin login disabled, got %d", rec.Code)
	}
}

// ---- peer operations & IDOR ----

func TestUpdatePeerRejectsCrossAccount(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "other", WGPubKey: "k-other"})
	rec := do(s, "PUT", "/api/v1/peers/k-other", adminToken(a), map[string]any{"groups": []string{"x"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-account update, got %d", rec.Code)
	}
}

func TestUpdatePeerValidatesGroups(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1"})
	rec := do(s, "PUT", "/api/v1/peers/k1", adminToken(a), map[string]any{"groups": []string{"BAD GROUP"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid group, got %d", rec.Code)
	}
}

// A peer can never lose Default membership through this endpoint, even if
// the request omits it — the dashboard (or any other caller) can't remove it.
func TestUpdatePeerAlwaysKeepsDefaultGroup(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1", Groups: []string{domain.DefaultGroupName}})
	rec := do(s, "PUT", "/api/v1/peers/k1", adminToken(a), map[string]any{"groups": []string{"web"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	p, _ := st.GetPeer(nil, "k1")
	found := false
	for _, g := range p.Groups {
		if g == domain.DefaultGroupName {
			found = true
		}
	}
	if !found {
		t.Fatalf("Default must always be present, got %+v", p.Groups)
	}
}

func TestUpdatePeerRenamesHostnameAndSyncsDNSLabel(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{
		ID: "1", AccountID: "default", WGPubKey: "k1",
		Groups: []string{domain.DefaultGroupName}, Hostname: "laptop-42", DNSLabel: "laptop-42",
	})
	rec := do(s, "PUT", "/api/v1/peers/k1", adminToken(a), map[string]any{
		"groups": []string{domain.DefaultGroupName}, "hostname": "Alice's Laptop",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	p, _ := st.GetPeer(nil, "k1")
	if p.Hostname != "Alice's Laptop" {
		t.Fatalf("hostname not updated: got %q", p.Hostname)
	}
	if p.DNSLabel != "alice-s-laptop" {
		t.Fatalf("DNS label not resynced with new name: got %q", p.DNSLabel)
	}
}

// Omitting "hostname" entirely (e.g. a groups-only update from the Groups
// modal) must not touch the name — only an explicit rename request should.
func TestUpdatePeerOmittedHostnameLeavesNameUnchanged(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{
		ID: "1", AccountID: "default", WGPubKey: "k1",
		Groups: []string{domain.DefaultGroupName}, Hostname: "laptop-42", DNSLabel: "laptop-42",
	})
	rec := do(s, "PUT", "/api/v1/peers/k1", adminToken(a), map[string]any{"groups": []string{domain.DefaultGroupName, "web"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	p, _ := st.GetPeer(nil, "k1")
	if p.Hostname != "laptop-42" || p.DNSLabel != "laptop-42" {
		t.Fatalf("name changed on a groups-only update: hostname=%q dns_label=%q", p.Hostname, p.DNSLabel)
	}
}

func TestUpdatePeerRejectsEmptyOrOverlongHostname(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1", Groups: []string{domain.DefaultGroupName}})

	rec := do(s, "PUT", "/api/v1/peers/k1", adminToken(a), map[string]any{"groups": []string{domain.DefaultGroupName}, "hostname": "   "})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for blank hostname, got %d", rec.Code)
	}

	overlong := ""
	for i := 0; i < 64; i++ {
		overlong += "a"
	}
	rec = do(s, "PUT", "/api/v1/peers/k1", adminToken(a), map[string]any{"groups": []string{domain.DefaultGroupName}, "hostname": overlong})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 64-char hostname, got %d", rec.Code)
	}
}

func TestDeletePeerReleasesIP(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1"})
	rec := do(s, "DELETE", "/api/v1/peers/k1", adminToken(a), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

func TestSetPeerRoutesRejectsMeshOverlap(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1"})
	bad := do(s, "PUT", "/api/v1/peers/k1/routes", adminToken(a), map[string]any{"routes": []string{"100.64.0.0/16"}})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mesh-overlapping route, got %d", bad.Code)
	}
	ok := do(s, "PUT", "/api/v1/peers/k1/routes", adminToken(a), map[string]any{"routes": []string{"192.168.1.0/24"}})
	if ok.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid route, got %d (%s)", ok.Code, ok.Body.String())
	}
}

// Regression: the mesh-overlap check must NOT reject the default route, which is
// how an exit node advertises itself (0.0.0.0/0 "contains" the mesh CIDR but is
// handled specially by consumers). Previously this returned 400, making the
// exit-node feature unreachable via the API/dashboard.
func TestSetPeerRoutesAllowsExitNodeDefaultRoute(t *testing.T) {
	s, st, a := newTestServer()
	_ = st.SavePeer(nil, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1"})

	v4 := do(s, "PUT", "/api/v1/peers/k1/routes", adminToken(a), map[string]any{"routes": []string{"0.0.0.0/0"}})
	if v4.Code != http.StatusOK {
		t.Fatalf("expected 200 for exit-node 0.0.0.0/0, got %d (%s)", v4.Code, v4.Body.String())
	}
	v6 := do(s, "PUT", "/api/v1/peers/k1/routes", adminToken(a), map[string]any{"routes": []string{"::/0"}})
	if v6.Code != http.StatusOK {
		t.Fatalf("expected 200 for exit-node ::/0, got %d (%s)", v6.Code, v6.Body.String())
	}
	// A default route combined with a real LAN subnet should still work.
	both := do(s, "PUT", "/api/v1/peers/k1/routes", adminToken(a), map[string]any{"routes": []string{"0.0.0.0/0", "192.168.5.0/24"}})
	if both.Code != http.StatusOK {
		t.Fatalf("expected 200 for exit-node + subnet, got %d (%s)", both.Code, both.Body.String())
	}
}

// ---- rules ----

func TestCreateRuleValidationAndSuccess(t *testing.T) {
	s, _, a := newTestServer()
	bad := do(s, "POST", "/api/v1/rules", adminToken(a), map[string]any{
		"name": "r", "src": "*", "dst": "*", "protocol": "tcp", "action": "maybe",
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad action, got %d", bad.Code)
	}
	ok := do(s, "POST", "/api/v1/rules", adminToken(a), map[string]any{
		"name": "r", "src": "*", "dst": "group:web", "protocol": "tcp", "port": 443, "action": "allow", "enabled": true,
	})
	if ok.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", ok.Code, ok.Body.String())
	}
}

// ---- groups ----

func TestGroupsSeededWithDefault(t *testing.T) {
	s, _, a := newTestServer()
	rec := do(s, "GET", "/api/v1/groups", peerToken(a), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Groups) != 1 || body.Groups[0].Name != domain.DefaultGroupName {
		t.Fatalf("expected only the seeded Default group, got %+v", body.Groups)
	}
}

func TestCreateAndDeleteGroup(t *testing.T) {
	s, _, a := newTestServer()
	create := do(s, "POST", "/api/v1/groups", adminToken(a), map[string]any{"name": "web"})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", create.Code, create.Body.String())
	}
	var body struct {
		Group domain.Group `json:"group"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &body)
	if body.Group.ID == "" {
		t.Fatal("no id returned")
	}
	// Duplicate name rejected.
	dup := do(s, "POST", "/api/v1/groups", adminToken(a), map[string]any{"name": "web"})
	if dup.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate group name, got %d", dup.Code)
	}
	del := do(s, "DELETE", "/api/v1/groups/"+body.Group.ID, adminToken(a), nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", del.Code)
	}
}

func TestDeleteDefaultGroupRejected(t *testing.T) {
	s, st, a := newTestServer()
	groups, _ := st.GetGroupsByAccount(nil, "default")
	var defaultID string
	for _, g := range groups {
		if g.Name == domain.DefaultGroupName {
			defaultID = g.ID
		}
	}
	if defaultID == "" {
		t.Fatal("seeded Default group not found")
	}
	rec := do(s, "DELETE", "/api/v1/groups/"+defaultID, adminToken(a), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting deletion of Default, got %d", rec.Code)
	}
}

func TestCreateSetupKeyWithAutoGroups(t *testing.T) {
	s, _, a := newTestServer()
	create := do(s, "POST", "/api/v1/setup-keys", adminToken(a), map[string]any{
		"name": "eng", "auto_groups": []string{"web", "prod"},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", create.Code, create.Body.String())
	}
	var body struct {
		SetupKey domain.SetupKey `json:"setup_key"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &body)
	if len(body.SetupKey.AutoGroups) != 2 {
		t.Fatalf("expected 2 auto_groups, got %+v", body.SetupKey.AutoGroups)
	}
	bad := do(s, "POST", "/api/v1/setup-keys", adminToken(a), map[string]any{
		"name": "eng2", "auto_groups": []string{"has space"},
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid auto_group name, got %d", bad.Code)
	}
}

func TestSetupKeyLifecycle(t *testing.T) {
	s, _, a := newTestServer()
	create := do(s, "POST", "/api/v1/setup-keys", adminToken(a), map[string]any{"name": "ci", "expires_in_days": 30})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", create.Code)
	}
	var body struct {
		SetupKey domain.SetupKey `json:"setup_key"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &body)
	if body.SetupKey.ID == "" {
		t.Fatal("no id returned")
	}
	del := do(s, "DELETE", "/api/v1/setup-keys/"+body.SetupKey.ID, adminToken(a), nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", del.Code)
	}
}
