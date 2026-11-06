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
)

fail=0
for path in "${paths[@]}"; do
  if [[ -n "$base" ]]; then
    code=$(curl -sS -o /dev/null -w '%{http_code}' "${base}${path}" || echo err)
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

# Redirect stub must mention allowlists
stub="${site}/whitelists.html"
if [[ -n "$base" ]]; then
  body=$(curl -sS "${base}/whitelists.html" || true)
  if ! grep -qi 'allowlists' <<<"$body"; then
    echo "FAIL whitelists stub missing allowlists reference"
    fail=1
  else
    echo "OK   whitelists redirect stub references allowlists"
  fi
elif [[ -f "$stub" ]]; then
  if ! grep -qi 'allowlists' "$stub"; then
    echo "FAIL $stub missing allowlists reference"
    fail=1
  else
    echo "OK   whitelists redirect stub references allowlists"
  fi
fi

exit "$fail"
