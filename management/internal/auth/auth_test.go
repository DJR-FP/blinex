package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-at-least-32-bytes-long!!"

func TestIssueAndValidatePeerToken(t *testing.T) {
	m := NewManager(testSecret)
	tok, err := m.IssueToken("peer-1", "wgkey-abc", "acct-1")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	claims, err := m.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.PeerID != "peer-1" || claims.WGPubKey != "wgkey-abc" || claims.AccountID != "acct-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.Role != "peer" {
		t.Fatalf("expected peer role, got %q", claims.Role)
	}
}

func TestIssueAndValidateAdminToken(t *testing.T) {
	m := NewManager(testSecret)
	tok, err := m.IssueAdminToken("acct-1")
	if err != nil {
		t.Fatalf("IssueAdminToken: %v", err)
	}
	claims, err := m.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected admin role, got %q", claims.Role)
	}
}

func TestValidateRejectsWrongSecret(t *testing.T) {
	m1 := NewManager(testSecret)
	m2 := NewManager("another-secret-at-least-32-bytes-xx!")
	tok, _ := m1.IssueToken("p", "k", "a")
	if _, err := m2.ValidateToken(tok); err == nil {
		t.Fatal("expected validation to fail with wrong secret")
	}
}

func TestValidateRejectsNoneAlg(t *testing.T) {
	m := NewManager(testSecret)
	// Forge a token with alg=none.
	claims := Claims{WGPubKey: "k", RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := m.ValidateToken(s); err == nil {
		t.Fatal("expected alg=none token to be rejected")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	m := NewManager(testSecret)
	claims := Claims{WGPubKey: "k", RegisteredClaims: jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := tok.SignedString([]byte(testSecret))
	if _, err := m.ValidateToken(s); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestRevocationRejectsOldToken(t *testing.T) {
	m := NewManager(testSecret)
	tok, _ := m.IssueToken("p", "wgkey-x", "a")

	// Token valid before revocation.
	if _, err := m.ValidateToken(tok); err != nil {
		t.Fatalf("token should be valid before revocation: %v", err)
	}

	// Revoke slightly in the future to guarantee IssuedAt is not After.
	m.RevokeByWGKey("wgkey-x")
	// Advance revocation time past the token's IssuedAt (issued "now", second precision).
	m.mu.Lock()
	m.revoked["wgkey-x"] = time.Now().Add(time.Second)
	m.mu.Unlock()

	if _, err := m.ValidateToken(tok); err == nil {
		t.Fatal("expected revoked token to be rejected")
	}
}

func TestRevocationDoesNotAffectOtherKeys(t *testing.T) {
	m := NewManager(testSecret)
	tok, _ := m.IssueToken("p", "wgkey-keep", "a")
	m.RevokeByWGKey("wgkey-other")
	if _, err := m.ValidateToken(tok); err != nil {
		t.Fatalf("unrelated revocation should not affect this token: %v", err)
	}
}

func TestNewTokenAfterRevocationIsValid(t *testing.T) {
	m := NewManager(testSecret)
	m.RevokeByWGKey("wgkey-y")
	time.Sleep(1100 * time.Millisecond) // ensure new token IssuedAt > revokedAt (second precision)
	tok, _ := m.IssueToken("p", "wgkey-y", "a")
	if _, err := m.ValidateToken(tok); err != nil {
		t.Fatalf("token issued after revocation should be valid: %v", err)
	}
}
