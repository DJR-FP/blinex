FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY relay/go.mod relay/go.sum ./relay/

RUN printf 'go 1.25\n\nuse (\n\t./relay\n)\n' > go.work && \
    go work sync && \
    cd relay && go mod download

COPY relay/ ./relay/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /relay \
    ./relay/cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S meshnet && adduser -S meshnet -G meshnet

COPY --from=builder /relay /usr/local/bin/relay

USER meshnet

EXPOSE 3478/udp

ENTRYPOINT ["/usr/local/bin/relay"]
