# AGENTS.md

Guidance for anyone, human or automated, contributing to cert-manage.

## Build and test

- Go version: see `go.mod`.
- Build: `go build ./...`
- Unit tests: `go test ./...`
- Coverage floors: `make coverage-floor` (or `./scripts/check-coverage.sh`) requires at least 40% statement coverage for `pkg/store` and 35% for `pkg/cmd`. CI runs the same check on Ubuntu.
- Platform suites run in docker in CI (`.github/workflows/ci.yml`). Run the matching suite locally before touching a platform's store code.

## Safety rules

- Certificates removed from a trust store can be hard to get back. Tests only use temp directories or containers, never a real system, Java, or browser store.
- Restore and allowlist changes must keep the existing safety: back up first, stage in a temp dir, swap, and roll back on failure.
- New destructive behavior must support `--dry-run`.

## Pull requests

- Keep PRs small and focused on one change. CI must be green before merge.
- Any change to behavior, flags, or supported platforms or apps updates `docs/` and the README in the same PR.
- Write PR titles as user-facing release notes ("Restore honors --backup for NSS"), since GitHub release notes are generated from them by GoReleaser. There is no CHANGELOG file.
- Don't name automated agents or bots in commits, PRs, issues, or comments.
