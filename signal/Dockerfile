FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.work go.work.sum* ./
COPY gen/ ./gen/
COPY signal/ ./signal/
RUN go build -ldflags="-s -w" -o /signal ./signal/cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /signal /signal
ENTRYPOINT ["/signal"]
