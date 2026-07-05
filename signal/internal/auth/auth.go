package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type keyCtx struct{}

// KeyFromContext returns the authenticated wg_pub_key set by StreamInterceptor.
// The bool is false when no interceptor ran (auth disabled).
func KeyFromContext(ctx context.Context) (string, bool) {
	k, ok := ctx.Value(keyCtx{}).(string)
	return k, ok
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// ValidateHS256 validates a HS256-signed JWT and returns the wg_pub_key claim.
func ValidateHS256(tokenStr, secret string) (string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid JWT signature")
	}
	if !hmac.Equal(mac.Sum(nil), sig) {
		return "", fmt.Errorf("JWT signature invalid")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT claims")
	}
	var claims struct {
		WGPubKey  string `json:"wg_pub_key"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", fmt.Errorf("parsing JWT claims: %w", err)
	}
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return "", fmt.Errorf("JWT expired")
	}
	if claims.WGPubKey == "" {
		return "", fmt.Errorf("missing wg_pub_key claim")
	}
	return claims.WGPubKey, nil
}

// StreamInterceptor returns a gRPC stream interceptor that validates HS256 JWTs.
func StreamInterceptor(secret string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata")
		}
		vals := md.Get("authorization")
		if len(vals) == 0 {
			return status.Error(codes.Unauthenticated, "authorization required")
		}
		tok := vals[0]
		if len(tok) > 7 && strings.EqualFold(tok[:7], "bearer ") {
			tok = tok[7:]
		}
		key, err := ValidateHS256(tok, secret)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid token")
		}
		ctx := context.WithValue(ss.Context(), keyCtx{}, key)
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}
