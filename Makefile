SHELL := /bin/sh

MODULE  := github.com/yqjwxz/beacon
BIN     := bin/beacon
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# proxy.golang.org is unreachable from mainland China; keep the mirror opt-out.
export GOPROXY ?= https://goproxy.cn,direct

.PHONY: all build test vet fmt check once clean

all: build

build: build-agent build-server

build-agent:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/beacon

build-server:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/beacon-server ./cmd/beacon-server

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet test

once: build
	./$(BIN) agent run --once

clean:
	rm -rf bin
