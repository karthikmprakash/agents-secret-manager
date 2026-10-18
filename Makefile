SHELL := /bin/bash
BINARY ?= $(HOME)/.local/bin/sm
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test test-race test-ui test-landing screenshots vet fmt check ui app clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/sm

test:
	go test ./...

test-race:
	go test -race ./...

test-ui:
	python3 scripts/test-ui.py

test-landing:
	python3 scripts/test-landing.py

screenshots:
	python3 scripts/capture-docs.py

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

check: fmt vet test-race

ui: build
	$(BINARY) ui

app:
	./scripts/build-mac-app.sh

clean:
	rm -rf dist
