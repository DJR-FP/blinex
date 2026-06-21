FROM golang:1.25-alpine AS builder
ARG VERSION=dev
WORKDIR /src

COPY relay/go.mod relay/go.sum ./relay/

RUN printf 'go 1.25\n\nuse (\n\t./relay\n)\n' > go.work && \
    go work sync && \
    cd relay && go mod download

COPY relay/ ./relay/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=v${VERSION}" \
    -o /relay \
    ./relay/cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S blinex && adduser -S blinex -G blinex

COPY --from=builder /relay /usr/local/bin/relay

USER blinex

EXPOSE 3478/udp

ENTRYPOINT ["/usr/local/bin/relay"]
