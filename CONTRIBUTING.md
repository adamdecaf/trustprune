# Contributing

Help with docs, bugfixes, tests, and new or deeper store support is welcome. One focused pull request at a time works best.

This project follows the [Google Code of Conduct](https://opensource.google.com/conduct/).

## Requirements

Go 1.27 (`go.mod`).

## Local gates

```bash
make lint
CGO_ENABLED=0 make check
CGO_ENABLED=1 go test -count=1 -timeout 3m -race ./pkg/... .
make coverage-floor
```

- `make lint` installs and runs golangci-lint v2.15.0, pinned in the makefile.
- `CGO_ENABLED=0 make check` runs `go vet` and `go test -count=1 -timeout 3m ./pkg/... .`.
- The race command covers the same packages with `CGO_ENABLED=1`.
- `make coverage-floor` requires `pkg/store` >= 40% and `pkg/cmd` >= 35%.

Also:

```bash
make build
make test              # full suite; uses Docker when available
MOCKED=true make test  # skip Docker-backed tests
```

Tests must use temp directories or container stores. Never point destructive tests at a real system CA directory.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on pull requests and on pushes to `master`:

- lint
- coverage-floor
- cross-compile (`linux` / `darwin` / `windows`, `amd64` / `arm64`)
- test matrix: Ubuntu, macOS, and Windows, including arm64, plus FreeBSD via `vmactions/freebsd-vm` under an empty `HOME`
- Docker distro suites (Alpine, Debian, Ubuntu, Rocky, Fedora, Arch, Gentoo, Firefox, and Chrome)

Docs-only pull requests skip those Go jobs through a paths-filter. Workflow and Go-source edits keep the full matrix.

## Secret scanning

[`.github/workflows/betterleaks.yml`](.github/workflows/betterleaks.yml) runs on every pull request and on pushes to `master`. It is a separate workflow, so docs-only pull requests are still scanned.

The job uses Betterleaks CLI v1.10.0 via `dortort/betterleaks-action` v0.1.0 (SHA-pinned). Auto mode scans git history on push and the working tree on pull requests. The job fails when leaks are found. Do not pin `latest` or a Betterleaks v2 release candidate.

Locally:

```bash
make leaks      # working tree
make leaks-git  # git history of this repository
```

Or run the v1.10.0 binary with `--config .betterleaks.toml`. The config is not auto-loaded. These targets are not part of `make check` or `make test`.

## False positives

Add a narrow path/value `filter` or `prefilter` in [`.betterleaks.toml`](.betterleaks.toml). Keep those keys above `[extend]`; if they follow `[extend]`, TOML treats them as `extend` fields and they do not apply. Then re-run `make leaks` and `make leaks-git`.

Inline `betterleaks:allow` comments (or legacy `gitleaks:allow`) also work.

Do not broaden `testdata/` so public certificates are skipped. Only private-key fixtures (`.pfx` / `.p12`) are prefiltered.
