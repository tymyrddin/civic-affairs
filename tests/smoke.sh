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

# Container health
# Health checks are defined per-service in each compose file. Docker reports the
# result here; a service with no healthcheck shows as running but not (healthy).
echo ""
echo "Container health"
for project in misp shuffle quiet-room long-table receiving-desk; do
  file="$REPO/$project/compose.yml"
  not_healthy=$(docker compose -f "$file" ps --format '{{.Name}} {{.Status}}' 2>/dev/null \
    | grep -v "(healthy)" | grep -v "^$" || true)
  if [ -z "$not_healthy" ]; then
    ok "$project"
  else
    fail "$project"
    echo "$not_healthy" | sed 's/^/         /'
  fi
done

# Endpoint reachability
echo ""
echo "Endpoints"
check_http "MISP"         "http://localhost:8080/users/login"
check_http "Shuffle"      "http://localhost:3001/"
check_http "OpenCTI"      "http://localhost:8888/health"
check_http "Wazuh API"    "https://localhost:55000/" "-k"
check_http "security.txt" "http://localhost:80/.well-known/security.txt"

echo ""
echo "$pass passed, $fail failed."
[ "$fail" -eq 0 ]
