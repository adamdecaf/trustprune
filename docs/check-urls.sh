#!/usr/bin/env bash
# Verify every published doc URL resolves.
# Usage:
#   ./docs/check-urls.sh              # check _site after a local Jekyll build
#   BASE_URL=https://trustprune.com ./docs/check-urls.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
base="${BASE_URL:-}"
site="${root}/docs/_site"

paths=(
  /
  /index.html
  /install /install.html
  /basics /basics.html
  /usage /usage.html
  /allowlists /allowlists.html
  /backup-restore /backup-restore.html
  /platforms /platforms.html
  /why /why.html
  /blog /blog.html
  /whitelists /whitelists.html
  /2026/10/28/apple-pem-hand-edit-emudhra.html
  /2026/11/11/limited-pem-bundle-few-hostnames.html
)

fail=0
for path in "${paths[@]}"; do
  if [[ -n "$base" ]]; then
    code=$(curl -sS --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "${base}${path}" || echo err)
    if [[ "$code" != "200" ]]; then
      echo "FAIL $code ${base}${path}"
      fail=1
    else
      echo "OK   $code ${base}${path}"
    fi
  else
    # Map URL path to a file under _site.
    if [[ "$path" == "/" ]]; then
      file="${site}/index.html"
    elif [[ "$path" == *.html ]]; then
      file="${site}${path}"
    else
      # extensionless: accept either path.html or path/index.html
      if [[ -f "${site}${path}.html" ]]; then
        file="${site}${path}.html"
      else
        file="${site}${path}/index.html"
      fi
    fi
    if [[ -f "$file" ]]; then
      echo "OK   file $file"
    else
      echo "FAIL missing $file (for $path)"
      fail=1
    fi
  fi
done

# Redirect stub must meta-refresh to allowlists.html
stub="${site}/whitelists.html"
check_refresh() {
  local body="$1" label="$2"
  # Require the meta refresh target, not just the word "allowlists".
  if ! grep -Fqi 'url=allowlists.html' <<<"$body"; then
    echo "FAIL $label missing meta refresh to allowlists.html"
    return 1
  fi
  if ! grep -Fqi 'http-equiv="refresh"' <<<"$body" && ! grep -Fqi "http-equiv='refresh'" <<<"$body" && ! grep -Fqi 'http-equiv=refresh' <<<"$body"; then
    echo "FAIL $label missing http-equiv=refresh"
    return 1
  fi
  echo "OK   $label meta refresh → allowlists.html"
  return 0
}
if [[ -n "$base" ]]; then
  body=$(curl -sS --connect-timeout 10 --max-time 30 "${base}/whitelists.html" || true)
  check_refresh "$body" "whitelists stub" || fail=1
elif [[ -f "$stub" ]]; then
  check_refresh "$(cat "$stub")" "$stub" || fail=1
else
  echo "FAIL missing $stub"
  fail=1
fi

exit "$fail"
