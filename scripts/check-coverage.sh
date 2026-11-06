#!/usr/bin/env bash
# Enforce pkg/store and pkg/cmd statement coverage floors (issue #234).
set -euo pipefail

STORE_MIN="${STORE_COVERAGE_MIN:-40}"
CMD_MIN="${CMD_COVERAGE_MIN:-35}"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

tmpdir="$(mktemp -d)"
empty_home="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir" "$empty_home" 2>/dev/null || true
}
trap cleanup EXIT

# Never point tests at a real HOME while measuring coverage.
export HOME="$empty_home"
export USERPROFILE="$empty_home"

echo "Measuring coverage with empty HOME=$HOME"
go test -count=1 -timeout 5m -coverprofile="$tmpdir/store.out" ./pkg/store/
go test -count=1 -timeout 5m -coverprofile="$tmpdir/cmd.out" ./pkg/cmd/

pct() {
  go tool cover -func="$1" | awk '/^total:/{ gsub(/%/,"",$NF); print $NF; exit }'
}

store_pct="$(pct "$tmpdir/store.out")"
cmd_pct="$(pct "$tmpdir/cmd.out")"

printf 'store coverage: %s%% (floor %s%%)\n' "$store_pct" "$STORE_MIN"
printf 'cmd coverage:   %s%% (floor %s%%)\n' "$cmd_pct" "$CMD_MIN"

awk -v got="$store_pct" -v min="$STORE_MIN" 'BEGIN{ if ((got+0) < (min+0)) { printf "store coverage %.1f%% is below floor %s%%\n", got, min; exit 1 } }'
awk -v got="$cmd_pct" -v min="$CMD_MIN" 'BEGIN{ if ((got+0) < (min+0)) { printf "cmd coverage %.1f%% is below floor %s%%\n", got, min; exit 1 } }'

echo "Coverage floors satisfied."
