# exporter_proxy build entry point. Run `make` or `make help` to list targets.

APP      := exporter_proxy
PKG      := ./cmd/$(APP)
BIN_DIR  := bin
BINARY   := $(BIN_DIR)/$(APP)

GO       ?= go
# Use a golangci-lint dropped into bin/ if present, otherwise the one in PATH.
GOLANGCI_LINT ?= $(if $(wildcard $(BIN_DIR)/golangci-lint),./$(BIN_DIR)/golangci-lint,golangci-lint)

# Version information, overridable by the packaging process
# (e.g. `make build VERSION=1.0.0`).
VERSION    ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
REVISION   ?= $(shell git rev-parse HEAD 2>/dev/null)
BRANCH     ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
# Commit date rather than the current date, so that rebuilding the same
# commit gives the same binary. Format expected by prometheus/common/version.
BUILD_DATE ?= $(shell TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y%m%d-%H:%M:%S 2>/dev/null)

VERSION_PKG := github.com/prometheus/common/version
LDFLAGS := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).Revision=$(REVISION) \
	-X $(VERSION_PKG).Branch=$(BRANCH) \
	-X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.DEFAULT_GOAL := help

.PHONY: help build test lint clean

help: ## List available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build a static binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

test: ## Run unit tests
	$(GO) test -count=1 ./...

lint: ## Check formatting, run go vet and golangci-lint
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "$(GOLANGCI_LINT) not found, see README (Development)"; exit 1; }
	$(GOLANGCI_LINT) run ./...

clean: ## Remove build and test artifacts (keeps tools stored in bin/)
	rm -f $(BINARY) coverage.out coverage.html
