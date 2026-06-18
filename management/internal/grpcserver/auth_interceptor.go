package grpcserver

import (
	"context"
	"strings"

	"github.com/meshnet/management/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type claimsKey struct{}

// Methods that do not require a JWT — Login and GetServerKey are pre-auth.
var publicMethods = map[string]bool{
	"/management.v1.ManagementService/Login":        true,
	"/management.v1.ManagementService/GetServerKey": true,
}

// AuthStreamInterceptor validates JWT from gRPC metadata for all streaming RPCs
// except those in publicMethods. The validated claims are injected into the
// stream context and retrievable via claimsFromContext.
func AuthStreamInterceptor(authMgr *auth.Manager) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}
		claims, err := extractClaims(ss.Context(), authMgr)
		if err != nil {
			return err
		}
		ctx := context.WithValue(ss.Context(), claimsKey{}, claims)
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

// AuthUnaryInterceptor validates JWT from gRPC metadata for all unary RPCs
// except those in publicMethods.
func AuthUnaryInterceptor(authMgr *auth.Manager) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		claims, err := extractClaims(ctx, authMgr)
		if err != nil {
			return nil, err
		}
		return handler(context.WithValue(ctx, claimsKey{}, claims), req)
	}
}

func extractClaims(ctx context.Context, authMgr *auth.Manager) (*auth.Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}
	token := strings.TrimPrefix(vals[0], "Bearer ")
	claims, err := authMgr.ValidateToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	return claims, nil
}

func claimsFromContext(ctx context.Context) *auth.Claims {
	v, _ := ctx.Value(claimsKey{}).(*auth.Claims)
	return v
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }
