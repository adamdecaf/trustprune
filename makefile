SHELL := /bin/bash
GOARCH ?= $(shell go env GOARCH)

.PHONY: build check test dist linux osx win lint coverage-floor

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -o bin/trustprune-linux-$(GOARCH) github.com/adamdecaf/trustprune
linux_amd64:
	$(MAKE) linux GOARCH=amd64

osx:
	CGO_ENABLED=0 GOOS=darwin GOARCH=$(GOARCH) go build -trimpath -o bin/trustprune-osx-$(GOARCH) github.com/adamdecaf/trustprune
osx_amd64:
	$(MAKE) osx GOARCH=amd64

win:
	CGO_ENABLED=0 GOOS=windows GOARCH=$(GOARCH) go build -trimpath -o bin/trustprune-$(GOARCH).exe github.com/adamdecaf/trustprune
win_64:
	$(MAKE) win GOARCH=amd64

dist: linux osx win


.PHONY: check
check:
	go vet ./...
	go test -count=1 -timeout 3m $(GOTEST_FLAGS) ./pkg/... .

# coverage-floor enforces pkg/store >= 40% and pkg/cmd >= 35% (issue #234).
coverage-floor:
	./scripts/check-coverage.sh


GOLANGCI_LINT_VERSION ?= v2.15.0
GOLANGCI_LINT_BIN := $(CURDIR)/bin/golangci-lint-$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT_BIN)
	$(GOLANGCI_LINT_BIN) run ./...

$(GOLANGCI_LINT_BIN):
	@mkdir -p $(dir $@)
	@set -eu; \
	os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported arch: $$arch" >&2; exit 1 ;; esac; \
	ver=$(GOLANGCI_LINT_VERSION:v%=%); \
	url="https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)/golangci-lint-$$ver-$$os-$$arch.tar.gz"; \
	tmp=$$(mktemp -d); \
	curl -fsSL "$$url" -o "$$tmp/gli.tar.gz"; \
	tar -xzf "$$tmp/gli.tar.gz" -C "$$tmp"; \
	cp "$$tmp"/golangci-lint-*/golangci-lint "$@"; \
	chmod +x "$@"; \
	rm -rf "$$tmp"

.PHONY: generate
generate:
	CGO_ENABLED=0 go run pkg/allowlist/blocklist_gen.go

test: check
	$(MAKE) linux
	go test -count=1 -timeout 5m $(GOTEST_FLAGS) ./test/

build: check
	go build -trimpath -o trustprune github.com/adamdecaf/trustprune
	@chmod +x trustprune
	@ln -sfn trustprune cert-manage

