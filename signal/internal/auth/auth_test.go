package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

const secret = "signal-secret-at-least-32-bytes-xx!!"

// makeToken builds an HS256 JWT the way ValidateHS256 expects.
func makeToken(t *testing.T, key string, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]any{"wg_pub_key": key}
	if exp != 0 {
		claims["exp"] = exp
	}
	cb, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

func TestValidateHS256Valid(t *testing.T) {
	tok := makeToken(t, "peerkey", time.Now().Add(time.Hour).Unix())
	key, err := ValidateHS256(tok, secret)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if key != "peerkey" {
		t.Fatalf("wrong key: %s", key)
	}
}

func TestValidateHS256BadSignature(t *testing.T) {
	tok := makeToken(t, "peerkey", time.Now().Add(time.Hour).Unix())
	if _, err := ValidateHS256(tok, "wrong-secret-wrong-secret-wrong-x!!"); err == nil {
		t.Fatal("expected signature mismatch to fail")
	}
}

func TestValidateHS256Expired(t *testing.T) {
	tok := makeToken(t, "peerkey", time.Now().Add(-time.Hour).Unix())
	if _, err := ValidateHS256(tok, secret); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestValidateHS256MissingKey(t *testing.T) {
	tok := makeToken(t, "", time.Now().Add(time.Hour).Unix())
	if _, err := ValidateHS256(tok, secret); err == nil {
		t.Fatal("expected missing wg_pub_key to fail")
	}
}

func TestValidateHS256Malformed(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a.b.c.d", "not-a-jwt"} {
		if _, err := ValidateHS256(bad, secret); err == nil {
			t.Fatalf("expected malformed token %q to fail", bad)
		}
	}
}
