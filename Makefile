GO      ?= go
GOLANGCI_LINT ?= $(shell test -x ./bin/golangci-lint && echo ./bin/golangci-lint || echo golangci-lint)
LDFLAGS := -s -w -X github.com/knumchoke/secure-pastebin/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: tools build test test-integration lint vuln ui check run compose-up compose-down

build: ui
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/pastebin ./cmd/pastebin

test:
	$(GO) test -race -count=1 ./...

test-integration:
	PASTEBIN_INTEGRATION=1 $(GO) test -race -count=1 -run 'Integration' ./...

lint:
	$(GOLANGCI_LINT) run ./...

tools:
	GOBIN=$(CURDIR)/bin $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	GOBIN=$(CURDIR)/bin $(GO) install golang.org/x/vuln/cmd/govulncheck@latest

vuln:
	$(shell test -x ./bin/govulncheck && echo ./bin/govulncheck || echo govulncheck) ./...

ui:
	cd ui && npm ci && npm run build

check: lint test
	cd ui && npm test --if-present

run:
	$(GO) run ./cmd/pastebin serve

compose-up:
	docker compose -f deploy/docker-compose.yml up --build -d

compose-down:
	docker compose -f deploy/docker-compose.yml down -v
