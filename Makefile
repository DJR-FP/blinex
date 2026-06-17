GOROOT   := $(HOME)/go/go
GOPATH   := $(HOME)/gopath
GO       := $(GOROOT)/bin/go
BUF      := $(GOPATH)/bin/buf
BIN      := bin

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
	$(GO) build -o $(BIN)/management ./management/cmd/server
	@echo "✓ management built"

build-signal:
	$(GO) build -o $(BIN)/signal ./signal/cmd/server
	@echo "✓ signal built"

build-relay:
	$(GO) build -o $(BIN)/relay ./relay/cmd/server
	@echo "✓ relay built"

build-agent:
	$(GO) build -o $(BIN)/agent ./client/cmd/agent
	@echo "✓ agent built"

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
	MESHNET_SETUP_KEY=MESHNET-DEFAULT-KEY $(GO) run ./client/cmd/agent

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

## ─── Clean ───────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BIN)
	rm -rf dashboard/.next dashboard/node_modules
