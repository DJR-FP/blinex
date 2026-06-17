FROM golang:1.25-alpine AS builder
ARG VERSION=dev
WORKDIR /src

COPY gen/go.mod gen/go.sum ./gen/
COPY signal/go.mod signal/go.sum ./signal/

RUN printf 'go 1.25\n\nuse (\n\t./gen\n\t./signal\n)\n' > go.work && \
    go work sync && \
    cd signal && go mod download

COPY gen/ ./gen/
COPY signal/ ./signal/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=v${VERSION}" \
    -o /signal \
    ./signal/cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S meshnet && adduser -S meshnet -G meshnet

COPY --from=builder /signal /usr/local/bin/signal

USER meshnet

EXPOSE 10000

ENTRYPOINT ["/usr/local/bin/signal"]
