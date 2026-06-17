FROM golang:1.23-alpine AS builder
WORKDIR /src

# Copy workspace and all modules
COPY go.work go.work.sum* ./
COPY gen/ ./gen/
COPY management/ ./management/

RUN go build -ldflags="-s -w" -o /management ./management/cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /management /management
ENTRYPOINT ["/management"]
