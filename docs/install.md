---
layout: default
title: Install
nav_order: 2
---

# Install

Module version on `master` is `0.1.1-dev`. Tagged releases start at `0.1.0`. Building requires **Go 1.27**.


## Renamed from cert-manage

The CLI is now `trustprune`. A `cert-manage` alias remains through 0.2.x. Release and local builds also publish `cert-manage-*` / a `cert-manage` symlink for compatibility. See the [README](https://github.com/adamdecaf/trustprune#renamed-from-cert-manage) for backup-path details.

## Release binaries

Download a pre-built binary from the [latest release](https://github.com/adamdecaf/trustprune/releases).

Tagged **0.1.0** still ships `cert-manage` binaries and predates commands such as `allowlist`, `apps`, and `--dry-run`. For those, [build from source](#build-from-source) or `go install` from `master` until a renamed release is published.

Cross-compile locally with Make (outputs under `bin/`):

```bash
make linux    # bin/trustprune-linux-$(GOARCH)
make osx      # bin/trustprune-osx-$(GOARCH)
make win      # bin/trustprune-$(GOARCH).exe
make dist     # all three
```

## go install

```bash
go install github.com/adamdecaf/trustprune@master
```

Use `@master` for the current command set (`allowlist`, `apps`, `--dry-run`, …). `go install …@latest` resolves to tagged **0.1.0**, which still ships `cert-manage` only. That installs a binary named `trustprune` (Go uses the last path element). `make build` also creates a local `cert-manage` symlink alias.

## Build from source

```bash
git clone https://github.com/adamdecaf/trustprune.git
cd trustprune
make build          # vet + unit tests + ./trustprune (+ cert-manage symlink)
```

Useful test targets:

```bash
make check                 # vet + unit tests under ./pkg and .
make test                  # check + Docker-backed integration when available
MOCKED=true make test      # skip Docker-backed tests
```

[← Home](index.md)
