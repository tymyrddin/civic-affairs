#!/usr/bin/env bash
# Tracer test: asserts data actually flows through the pipeline, not just that
# containers are up. Complements smoke.sh, which only checks presence and reachability.
#
# It injects a synthetic Suricata alert into eve.json and follows it downstream:
#
#   default       alert -> eve.json -> classifier -> MISP        (fast, ~45s)
#   --deep  adds  ... -> opencti-misp connector -> OpenCTI       (slow, up to ~150s)
#   --clean       purge leftover TRACER-* objects from OpenCTI    (no injection)
#
# The synthetic alert uses reserved documentation IP ranges (TEST-NET-2/3) and a
# unique per-run marker, so it never collides with real traffic or the dedup window.
# The MISP tracer event is deleted after the run. A --deep run leaves its report and
# observables in OpenCTI (no cheap delete-by-value), which is why this lives outside
# smoke.sh; run --clean to purge them, or rely on a down --volumes cycle.
#
# Run after ./ctl up. Exits non-zero if the trace does not complete.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEEP=0
CLEAN=0
case "${1:-}" in
  --deep)  DEEP=1 ;;
  --clean) CLEAN=1 ;;
  "")      ;;
  *)       echo "usage: $(basename "$0") [--deep|--clean]"; exit 2 ;;
esac

MISP_HOST="${MISP_HOST:-https://127.0.0.1:8443}"
OPENCTI_HOST="${OPENCTI_HOST:-http://127.0.0.1:8888}"
MISP_TIMEOUT="${MISP_TIMEOUT:-45}"
OPENCTI_TIMEOUT="${OPENCTI_TIMEOUT:-150}"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required for JSON parsing"; exit 2; }

# Read a single VAR=value from an env file without sourcing it (avoids executing the file).
read_env() {
  local file="$1" key="$2" line
  line=$(grep -E "^${key}=" "$file" 2>/dev/null | tail -1) || true
  printf '%s' "${line#*=}"
}

# --clean: purge tracer leftovers from OpenCTI, then exit. The tracer reports are named
# "Suricata IDS Alert: TRACER-..." and the observables are in TEST-NET-2/3, which nothing
# but this script creates, so matching on those is safe.
if [ "$CLEAN" = 1 ]; then
  TOKEN="$(read_env "$REPO/long-table/.env" OPENCTI_ADMIN_TOKEN)"
  [ -n "$TOKEN" ] || { echo "OPENCTI_ADMIN_TOKEN not found in long-table/.env"; exit 2; }
  echo ""
  echo "Cleaning TRACER-* objects from OpenCTI"
  OPENCTI_HOST="$OPENCTI_HOST" TOKEN="$TOKEN" python3 -u - <<'PY'
import os, json, sys, urllib.request, urllib.error
host=os.environ["OPENCTI_HOST"]; tok=os.environ["TOKEN"]
def gql(q, v=None):
    req=urllib.request.Request(host+"/graphql",
        data=json.dumps({"query":q,"variables":v or {}}).encode(),
        headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(req, timeout=30))

try:
    gql("{about{version}}")
except (urllib.error.URLError, OSError) as e:
    print(f"  OpenCTI not reachable at {host} ({e}). Is the stack up?")
    sys.exit(1)

deleted=0
# Tracer reports
d=gql("query($s:String){reports(search:$s,first:200){edges{node{id name}}}}", {"s":"TRACER-"})
for e in d.get("data",{}).get("reports",{}).get("edges",[]):
    n=e["node"]
    if "TRACER-" in (n.get("name") or ""):
        gql("mutation($id:ID!){reportEdit(id:$id){delete}}", {"id":n["id"]}); deleted+=1
        print("  report   ", n["name"])
# Tracer observables (TEST-NET-2/3)
for pref in ("203.0.113","198.51.100"):
    d=gql("query($s:String){stixCyberObservables(search:$s,first:200){edges{node{id observable_value}}}}", {"s":pref})
    for e in d.get("data",{}).get("stixCyberObservables",{}).get("edges",[]):
        n=e["node"]; val=n.get("observable_value") or ""
        if val.startswith(pref+"."):
            gql("mutation($id:ID!){stixCyberObservableEdit(id:$id){delete}}", {"id":n["id"]}); deleted+=1
            print("  observable", val)
print(f"Removed {deleted} object(s).")
PY
  exit 0
fi

MISP_KEY="$(read_env "$REPO/quiet-room/.env" MISP_API_KEY)"
[ -n "$MISP_KEY" ] || { echo "MISP_API_KEY not found in quiet-room/.env (run ./ctl init?)"; exit 2; }

# Unique per-run marker and reserved-range addresses (RFC 5737 TEST-NET-2/3).
ID="$(date +%s)$$${RANDOM}"
SIG="TRACER-${ID}"
SRC="203.0.113.$(( RANDOM % 254 + 1 ))"
DST="198.51.100.$(( RANDOM % 254 + 1 ))"
SIGID="$(( 9${ID: -7} ))"

echo ""
echo "Tracer ${SIG}  src=${SRC} dst=${DST}"
[ "$DEEP" = 1 ] && echo "Mode: deep (classifier -> MISP -> OpenCTI)" || echo "Mode: fast (classifier -> MISP)"

# 1. Inject the synthetic alert into the live eve.json the classifier tails.
ALERT="$(python3 - "$SRC" "$DST" "$SIG" "$SIGID" <<'PY'
import json, sys, datetime
src, dst, sig, sigid = sys.argv[1:5]
print(json.dumps({
    "timestamp": datetime.datetime.now().astimezone().isoformat(),
    "event_type": "alert",
    "src_ip": src, "dest_ip": dst, "src_port": 40000, "dest_port": 80, "proto": "TCP",
    "alert": {"signature": sig, "category": "Smoke Test Tracer",
              "signature_id": int(sigid), "severity": 3},
}))
PY
)"

echo "  injecting alert into eve.json"
printf '%s\n' "$ALERT" | docker compose -f "$REPO/quiet-room/compose.yml" exec -T suricata \
  sh -c 'cat >> /var/log/suricata/eve.json' \
  || { echo "  FAIL could not write to eve.json (is suricata up?)"; exit 1; }

# 2. Poll MISP for the event the classifier should create from it.
misp_event_id() {
  curl -sk -X POST "$MISP_HOST/events/restSearch" \
    -H "Authorization: $MISP_KEY" -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{\"returnFormat\":\"json\",\"value\":\"$SRC\"}" 2>/dev/null \
  | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for e in d.get("response",[]):
    ev=e.get("Event",{})
    print(ev.get("id","")); break'
}

echo -n "  waiting for MISP event "
EVENT_ID=""
for _ in $(seq 1 "$MISP_TIMEOUT"); do
  EVENT_ID="$(misp_event_id)"
  [ -n "$EVENT_ID" ] && break
  echo -n "."; sleep 1
done
echo ""

cleanup() {
  if [ -n "${EVENT_ID:-}" ]; then
    curl -sk -X POST "$MISP_HOST/events/delete/$EVENT_ID" \
      -H "Authorization: $MISP_KEY" -H "Accept: application/json" >/dev/null 2>&1 || true
  fi
}

if [ -z "$EVENT_ID" ]; then
  echo "  FAIL classifier did not create a MISP event within ${MISP_TIMEOUT}s"
  echo "       (classifier stuck, MISP unreachable, or alert not tailed)"
  exit 1
fi
echo "  ok   classifier -> MISP (event $EVENT_ID)"

# 3. Deep tier: follow into OpenCTI via the misp connector.
if [ "$DEEP" = 1 ]; then
  TOKEN="$(read_env "$REPO/long-table/.env" OPENCTI_ADMIN_TOKEN)"
  if [ -z "$TOKEN" ]; then
    cleanup
    echo "  FAIL OPENCTI_ADMIN_TOKEN not found in long-table/.env"
    exit 2
  fi

  opencti_has_observable() {
    curl -s -X POST "$OPENCTI_HOST/graphql" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "{\"query\":\"query(\$s:String){stixCyberObservables(search:\$s){edges{node{observable_value}}}}\",\"variables\":{\"s\":\"$SRC\"}}" 2>/dev/null \
    | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
edges=(d.get("data") or {}).get("stixCyberObservables",{}).get("edges",[])
sys.exit(0 if edges else 1)'
  }

  echo -n "  waiting for OpenCTI observable (connector interval ~60s) "
  FOUND=0
  for _ in $(seq 1 "$OPENCTI_TIMEOUT"); do
    if opencti_has_observable; then FOUND=1; break; fi
    echo -n "."; sleep 1
  done
  echo ""

  if [ "$FOUND" = 1 ]; then
    echo "  ok   MISP -> connector -> OpenCTI ($SRC)"
  else
    cleanup
    echo "  FAIL tracer did not reach OpenCTI within ${OPENCTI_TIMEOUT}s"
    echo "       (connector not fetching, or worker ingest stalled)"
    exit 1
  fi
fi

cleanup
echo ""
echo "Tracer passed."
