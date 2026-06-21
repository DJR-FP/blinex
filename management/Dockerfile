FROM golang:1.25-alpine AS builder
ARG VERSION=dev
WORKDIR /src

# Copy only the modules needed for this binary
COPY gen/go.mod gen/go.sum ./gen/
COPY management/go.mod management/go.sum ./management/

# Create a minimal workspace that includes only gen + management
RUN printf 'go 1.25\n\nuse (\n\t./gen\n\t./management\n)\n' > go.work && \
    go work sync && \
    cd management && go mod download

# Copy source and build
COPY gen/ ./gen/
COPY management/ ./management/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=v${VERSION}" \
    -o /management \
    ./management/cmd/server

# ── Runtime image ────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S blinex && adduser -S blinex -G blinex

COPY --from=builder /management /usr/local/bin/management

USER blinex

EXPOSE 50051 8080

ENTRYPOINT ["/usr/local/bin/management"]
