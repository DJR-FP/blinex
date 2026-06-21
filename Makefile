GOROOT   := $(HOME)/go/go
GOPATH   := $(HOME)/gopath
GO       := $(GOROOT)/bin/go
BUF      := $(GOPATH)/bin/buf
BIN      := bin
VERSION  := $(shell cat VERSION 2>/dev/null | tr -d '[:space:]' || echo dev)
LDFLAGS  := -ldflags "-s -w -X main.version=v$(VERSION)"

export PATH := $(GOROOT)/bin:$(GOPATH)/bin:$(PATH)

.PHONY: all proto build test clean run-management run-signal run-relay run-agent dashboard

all: proto build

## ─── Proto ─────────────────────────────────────────────────────────────────────

proto:
	$(BUF) generate
	@echo "✓ proto generated"

## ─── Build ──────────────────────────────────────────────────────────────────────

build: build-management build-signal build-relay build-agent

build-management:
	$(GO) build $(LDFLAGS) -o $(BIN)/management ./management/cmd/server
	@echo "✓ management v$(VERSION) built"

build-signal:
	$(GO) build $(LDFLAGS) -o $(BIN)/signal ./signal/cmd/server
	@echo "✓ signal v$(VERSION) built"

build-relay:
	$(GO) build $(LDFLAGS) -o $(BIN)/relay ./relay/cmd/server
	@echo "✓ relay v$(VERSION) built"

build-agent:
	$(GO) build $(LDFLAGS) -o $(BIN)/agent ./client/cmd/agent
	@echo "✓ agent v$(VERSION) built"

## ─── Test ───────────────────────────────────────────────────────────────────────

test:
	$(GO) test ./management/... ./signal/... ./relay/... ./client/...

## ─── Run (dev) ──────────────────────────────────────────────────────────────────

run-management:
	$(GO) run ./management/cmd/server

run-signal:
	$(GO) run ./signal/cmd/server

run-relay:
	RELAY_PUBLIC_IP=127.0.0.1 $(GO) run ./relay/cmd/server

run-agent:
	BLINEX_SETUP_KEY=BLINEX-DEFAULT-KEY $(GO) run ./client/cmd/agent

## ─── Dashboard ───────────────────────────────────────────────────────────────────

dashboard:
	cd dashboard && npm run dev

dashboard-install:
	cd dashboard && npm install

dashboard-build:
	cd dashboard && npm run build

## ─── Tidy ───────────────────────────────────────────────────────────────────────

tidy:
	$(GO) work sync
	$(GO) -C gen mod tidy
	$(GO) -C management mod tidy
	$(GO) -C signal mod tidy
	$(GO) -C relay mod tidy
	$(GO) -C client mod tidy

## ─── Release ─────────────────────────────────────────────────────────────────────

# Create and push a version tag. Usage: make tag  (reads VERSION file)
tag:
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	@echo "✓ tagged v$(VERSION) and pushed"

## ─── Clean ───────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BIN)
	rm -rf dashboard/.next dashboard/node_modules
