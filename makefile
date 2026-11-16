SHELL := /bin/bash
GOARCH ?= $(shell go env GOARCH)

.PHONY: build check test dist linux osx win lint coverage-floor leaks leaks-git

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

# Betterleaks v1.10.0 (not latest, and not the v2 RC). Release archives use
# x64, not amd64. Pass --config explicitly: v1.10.0 does not auto-load
# .betterleaks.toml. leaks-git opts into local git config because v1.10.0
# isolates it unless this trusted repository says otherwise.
BETTERLEAKS_VERSION ?= v1.10.0
BETTERLEAKS_BIN := $(CURDIR)/bin/betterleaks-$(BETTERLEAKS_VERSION)

leaks: $(BETTERLEAKS_BIN)
	$(BETTERLEAKS_BIN) dir . --config .betterleaks.toml --no-banner

leaks-git: $(BETTERLEAKS_BIN)
	$(BETTERLEAKS_BIN) git . --config .betterleaks.toml --no-banner --trust-local-git-config

$(BETTERLEAKS_BIN):
	@mkdir -p $(dir $@)
	@set -euo pipefail; \
	os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in \
		x86_64|amd64) arch=x64 ;; \
		aarch64|arm64) arch=arm64 ;; \
		*) echo "unsupported arch: $$arch" >&2; exit 1 ;; \
	esac; \
	case "$$os" in \
		linux|darwin) ;; \
		*) echo "unsupported os: $$os" >&2; exit 1 ;; \
	esac; \
	case "$${os}_$${arch}" in \
		linux_x64) sum=9d9ad503cd5d80d18a939352266c3fcca52f10da9b83cd5cfe646989b13940fe ;; \
		linux_arm64) sum=3d7585cbe4f947aef6e31662f65beb5b43b104381a691b6b81b157ebfbb0c02d ;; \
		darwin_x64) sum=71b3f30602856e622008c248b1b47b2ba15b227f4a033e8bfdfa05a21ec7d531 ;; \
		darwin_arm64) sum=91eaea97709d3308c7712574a56260539c65fbd0672711537aa68d566ea630b3 ;; \
		*) echo "no checksum for $${os}/$${arch}" >&2; exit 1 ;; \
	esac; \
	ver=$(BETTERLEAKS_VERSION:v%=%); \
	archive="betterleaks_$${ver}_$${os}_$${arch}.tar.gz"; \
	url="https://github.com/betterleaks/betterleaks/releases/download/$(BETTERLEAKS_VERSION)/$$archive"; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	curl -fsSL "$$url" -o "$$tmp/$$archive"; \
	if command -v sha256sum >/dev/null 2>&1; then \
		got=$$(sha256sum "$$tmp/$$archive" | awk '{print $$1}'); \
	elif command -v shasum >/dev/null 2>&1; then \
		got=$$(shasum -a 256 "$$tmp/$$archive" | awk '{print $$1}'); \
	else \
		echo "sha256sum or shasum is required to verify $$archive" >&2; \
		exit 1; \
	fi; \
	if [ "$$got" != "$$sum" ]; then \
		echo "checksum mismatch for $$archive" >&2; \
		echo "got:  $$got" >&2; \
		echo "want: $$sum" >&2; \
		exit 1; \
	fi; \
	tar -xzf "$$tmp/$$archive" -C "$$tmp" betterleaks; \
	cp "$$tmp/betterleaks" "$@"; \
	chmod +x "$@"

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

