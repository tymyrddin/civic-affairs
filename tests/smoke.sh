#!/usr/bin/env bash
# Smoke test: verifies the pipeline is up and each service is healthy.
# Run after ./ctl up.
# Exits non-zero if any check fails.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass=0
fail=0

ok()   { echo "  ok   $1"; pass=$((pass + 1)); }
fail() { echo "  FAIL $1"; fail=$((fail  + 1)); }

check_http() {
  local label="$1"
  local url="$2"
  local extra="${3:-}"
  if curl -sf $extra "$url" > /dev/null 2>&1; then
    ok "$label"
  else
    fail "$label ($url)"
  fi
}

# Like check_http but accepts any HTTP response — use for services that require auth.
check_http_up() {
  local label="$1"
  local url="$2"
  local extra="${3:-}"
  if curl -s $extra "$url" -o /dev/null -w '%{http_code}' 2>/dev/null | grep -qE '^[0-9]'; then
    ok "$label"
  else
    fail "$label ($url)"
  fi
}

# Container health
# Flags containers in an explicit failure state: (unhealthy), Restarting, Exited, Error.
# Containers that are Up without a healthcheck are considered acceptable.
echo ""
echo "Container health"
for project in misp shuffle quiet-room long-table receiving-desk receiving-desk/globaleaks; do
  file="$REPO/$project/compose.yml"
  failing=$(docker compose -f "$file" ps --format '{{.Name}} {{.Status}}' 2>/dev/null \
    | grep -vE "\(healthy\)" \
    | grep -E "(unhealthy|Restarting|Exited|Error)" \
    | grep -v "^$" || true)
  if [ -z "$failing" ]; then
    ok "$project"
  else
    fail "$project"
    echo "$failing" | sed 's/^/         /'
  fi
done

# Endpoint reachability
echo ""
echo "Endpoints"
check_http    "MISP"         "http://localhost:8080/users/login"
check_http    "Shuffle"      "http://localhost:3001/"
check_http_up "OpenCTI"      "http://localhost:8888/health"
check_http_up "Wazuh API"    "https://localhost:55000/" "-k"
check_http    "security.txt" "http://localhost:8080/.well-known/security.txt"
check_http_up "GlobaLeaks"  "https://localhost:8082" "-k"

echo ""
echo "$pass passed, $fail failed."
[ "$fail" -eq 0 ]
