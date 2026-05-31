#!/usr/bin/env bash
# Walkthrough simulation: reproduces the establishment LT-2026-0007 arc end to end
# against the live pipeline, so the documented case tables emerge from the running
# build rather than being asserted on paper.
#
# What it drives:
#   Seeded into MISP (things the classifier structurally cannot produce):
#     RD-2026-0047-A  Receiving Desk firmware finding, CVE-2026-4471, reliability 4
#     QR-2026-0031    Society notification, 94.23.117.8 -> 10.44.12.0/24, reliability 4
#     RD-2026-0049    anonymous Tor tip, CVE-2026-4471, reliability 2 (ceiling)
#     RD-2026-0048    Siemens S7-1200, CVE-2019-13945, seeded but set aside (no Long-Table)
#   Injected through the live classifier (Suricata eve.json / Zeek dns.log):
#     QR-2026-0032    lone Suricata alert on 94.23.117.8 -> a tlp:white reliability-2 event
#     QR-2026-0033    Suricata + Zeek on a shared host -> a held tlp:amber needs-review
#                     reliability-3 event, which the analyst step then routes (Long-Table)
#   Written directly (the classifier does not ingest feeds):
#     QR-2026-0034    third-party feed claim, reliability 1, drop-log entry, no MISP event
#
# The four converging cases share CVE-2026-4471, 94.23.117.8, and 10.44.12.0/24, so the
# MISP->OpenCTI connector carries the routed (Long-Table / tlp:white) events across and
# LT-2026-0007 resolves in OpenCTI. RD-0048 stays out (no Long-Table), QR-0033 is a
# separate case on its own observables, and QR-0034 never becomes an event.
#
#   default     run the arc and verify convergence in OpenCTI
#   --no-verify run the arc, skip the OpenCTI check (no OpenCTI token needed)
#   --clean     remove the simulation's MISP events, drop-log lines, and OpenCTI objects
#
# Run after ./ctl up. Exits non-zero if a step does not complete.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO/quiet-room/compose.yml"

MODE=run
case "${1:-}" in
  --no-verify) MODE=noverify ;;
  --clean)     MODE=clean ;;
  "")          ;;
  *)           echo "usage: $(basename "$0") [--no-verify|--clean]"; exit 2 ;;
esac

MISP_HOST="${MISP_HOST:-https://127.0.0.1:8443}"
OPENCTI_HOST="${OPENCTI_HOST:-http://127.0.0.1:8888}"
EVENT_TIMEOUT="${EVENT_TIMEOUT:-60}"
OPENCTI_TIMEOUT="${OPENCTI_TIMEOUT:-180}"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required for JSON handling"; exit 2; }

# Convergence observables, taken from the walkthrough case tables.
MARKER="SIM-LT-2026-0007"
C2_IP="94.23.117.8"
SUBNET="10.44.12.0/24"
QR32_DST="10.44.12.7"          # a host inside the targeted subnet
CVE="CVE-2026-4471"
HOLD_HOST="198.51.100.23"      # QR-0033 internal host (separate case)
HOLD_EXT="203.0.113.45"        # QR-0033 external low-reputation range
HOLD_DOMAIN="city-payroll-portal.example"
ASIDE_IP="185.44.23.107"       # RD-0048 Siemens S7-1200, set aside
ASIDE_CVE="CVE-2019-13945"
FEED_IP="203.0.113.77"         # QR-0034 feed claim, dropped

# Read a single VAR=value from an env file without sourcing it.
read_env() {
  local file="$1" key="$2" line
  line=$(grep -E "^${key}=" "$file" 2>/dev/null | tail -1) || true
  printf '%s' "${line#*=}"
}

MISP_KEY="$(read_env "$REPO/quiet-room/.env" MISP_API_KEY)"
[ -n "$MISP_KEY" ] || { echo "MISP_API_KEY not found in quiet-room/.env (run ./ctl init?)"; exit 2; }

# ---------------------------------------------------------------------- MISP helpers

# misp_add INFO TAGS DIST THREAT ATTR...   (ATTR = "category|type|value|comment")
# Prints "<event_id> <event_uuid>".
misp_add() {
  local info="$1" tags="$2" dist="$3" threat="$4"; shift 4
  local json
  json="$(python3 - "$info" "$tags" "$dist" "$threat" "$@" <<'PY'
import json, sys
info, tags, dist, threat = sys.argv[1:5]
attrs = []
for a in sys.argv[5:]:
    parts = a.split("|", 3)
    while len(parts) < 4:
        parts.append("")
    cat, typ, val, com = parts
    attrs.append({"category": cat, "type": typ, "value": val, "comment": com, "to_ids": False})
print(json.dumps({"Event": {
    "info": info, "distribution": dist, "threat_level_id": threat, "analysis": "0",
    "Tag": [{"name": t} for t in tags.split(",") if t],
    "Attribute": attrs,
}}))
PY
)"
  curl -sk -X POST "$MISP_HOST/events/add" \
    -H "Authorization: $MISP_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
    --data "$json" 2>/dev/null \
  | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
e=d.get("Event",{}); print(e.get("id",""), e.get("uuid",""))'
}

# misp_search VALUE [TAG]   prints "<id> <uuid>" of the first matching event, or nothing.
misp_search() {
  local value="$1" tag="${2:-}" query
  query="$(python3 - "$value" "$tag" <<'PY'
import json, sys
value, tag = sys.argv[1], sys.argv[2]
q = {"returnFormat": "json", "value": value}
if tag:
    q["tags"] = [tag]
print(json.dumps(q))
PY
)"
  curl -sk -X POST "$MISP_HOST/events/restSearch" \
    -H "Authorization: $MISP_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
    --data "$query" 2>/dev/null \
  | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for e in d.get("response",[]):
    ev=e.get("Event",{}); print(ev.get("id",""), ev.get("uuid","")); break'
}

misp_attach_tag() {
  curl -sk -X POST "$MISP_HOST/tags/attachTagToObject" \
    -H "Authorization: $MISP_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
    --data "{\"uuid\":\"$1\",\"tag\":\"$2\"}" >/dev/null 2>&1
}

misp_delete() {
  curl -sk -X POST "$MISP_HOST/events/delete/$1" \
    -H "Authorization: $MISP_KEY" -H "Accept: application/json" >/dev/null 2>&1 || true
}

# wait_for_event VALUE [TAG] LABEL   polls until the event exists; prints "<id> <uuid>".
wait_for_event() {
  local value="$1" tag="$2" label="$3" found=""
  # Progress goes to stderr; stdout carries only the result, which the caller captures.
  echo -n "  waiting for $label " >&2
  for _ in $(seq 1 "$EVENT_TIMEOUT"); do
    found="$(misp_search "$value" "$tag")"
    [ -n "$found" ] && break
    echo -n "." >&2; sleep 1
  done
  echo "" >&2
  # Terminate with a newline so a caller's `read` does not see EOF mid-line and
  # return non-zero (which would trip set -e). Command substitution strips it.
  printf '%s\n' "$found"
}

# ---------------------------------------------------------------------- injection helpers

inject_suricata() {
  local src="$1" dst="$2" sig="$3" sigid="$4" sev="${5:-2}" sport="${6:-44000}" dport="${7:-8443}"
  python3 - "$src" "$dst" "$sig" "$sigid" "$sev" "$sport" "$dport" <<'PY' \
    | docker compose -f "$COMPOSE" exec -T suricata sh -c 'cat >> /var/log/suricata/eve.json'
import json, sys, datetime
src, dst, sig, sigid, sev, sport, dport = sys.argv[1:8]
print(json.dumps({
    "timestamp": datetime.datetime.now().astimezone().isoformat(),
    "event_type": "alert", "src_ip": src, "dest_ip": dst,
    "src_port": int(sport), "dest_port": int(dport), "proto": "TCP",
    "alert": {"signature": sig, "category": "Simulation",
              "signature_id": int(sigid), "severity": int(sev)},
}))
PY
}

inject_zeek_dns() {
  local orig="$1" resp="$2" query="$3"
  python3 - "$orig" "$resp" "$query" <<'PY' \
    | docker compose -f "$COMPOSE" exec -T zeek sh -c 'cat >> /opt/zeek/logs/dns.log'
import json, sys, datetime
orig, resp, query = sys.argv[1:4]
print(json.dumps({
    "ts": datetime.datetime.now().timestamp(), "uid": "Csim",
    "id.orig_h": orig, "id.orig_p": 51000, "id.resp_h": resp, "id.resp_p": 53,
    "proto": "udp", "query": query, "qtype_name": "A", "rcode_name": "NOERROR", "answers": [resp],
}))
PY
}

write_drop() {
  local indicator="$1" source="$2" reliability="$3" reason="$4"
  python3 - "$indicator" "$source" "$reliability" "$reason" <<'PY' \
    | docker compose -f "$COMPOSE" exec -T classifier sh -c 'cat >> /state/drops.log'
import json, sys, datetime
ind, src, rel, reason = sys.argv[1:5]
print(json.dumps({
    "ts": datetime.datetime.now().timestamp(),
    "iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "indicator": ind, "source": src, "reliability": int(rel), "reason": reason,
}))
PY
}

# ---------------------------------------------------------------------- OpenCTI helpers

octi_gql() {
  curl -s -X POST "$OPENCTI_HOST/graphql" \
    -H "Authorization: Bearer $OCTI_TOKEN" -H "Content-Type: application/json" \
    --data "$1" 2>/dev/null
}

octi_has_observable() {
  octi_gql "{\"query\":\"query(\$s:String){stixCyberObservables(search:\$s){edges{node{observable_value}}}}\",\"variables\":{\"s\":\"$1\"}}" \
  | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
edges=(d.get("data") or {}).get("stixCyberObservables",{}).get("edges",[])
sys.exit(0 if edges else 1)'
}

# ---------------------------------------------------------------------- clean mode

if [ "$MODE" = clean ]; then
  echo ""
  echo "Cleaning simulation artefacts"
  # MISP: every event carrying the marker, plus the QR-0033 events on the sim-only host.
  for value in "$MARKER" "$HOLD_HOST" "$HOLD_EXT" "$C2_IP" "$QR32_DST" "$ASIDE_IP"; do
    while read -r id _; do
      [ -n "$id" ] || continue
      misp_delete "$id" && echo "  MISP event $id"
    done < <(curl -sk -X POST "$MISP_HOST/events/restSearch" \
              -H "Authorization: $MISP_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
              --data "{\"returnFormat\":\"json\",\"value\":\"$value\"}" 2>/dev/null \
            | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for e in d.get("response",[]):
    print(e.get("Event",{}).get("id",""))')
  done
  # Drop log: remove the simulated feed line.
  docker compose -f "$COMPOSE" exec -T classifier python3 - "$FEED_IP" <<'PY' 2>/dev/null || true
import json, sys, os
feed = sys.argv[1]
p = "/state/drops.log"
if os.path.exists(p):
    kept = []
    for line in open(p, encoding="utf-8", errors="replace"):
        s = line.strip()
        if not s:
            continue
        try:
            if json.loads(s).get("indicator") != feed:
                kept.append(s)
        except json.JSONDecodeError:
            kept.append(s)
    open(p, "w", encoding="utf-8").write("\n".join(kept) + ("\n" if kept else ""))
    print("  drop log cleaned")
PY
  # OpenCTI: marker reports and the sim observables, best effort.
  OCTI_TOKEN="$(read_env "$REPO/long-table/.env" OPENCTI_ADMIN_TOKEN)"
  if [ -n "$OCTI_TOKEN" ]; then
    OPENCTI_HOST="$OPENCTI_HOST" TOKEN="$OCTI_TOKEN" MARKER="$MARKER" \
    C2_IP="$C2_IP" HOLD_HOST="$HOLD_HOST" HOLD_EXT="$HOLD_EXT" QR32_DST="$QR32_DST" \
    SUBNET="$SUBNET" CVE="$CVE" \
    python3 -u - <<'PY' || true
import os, json, urllib.request, urllib.error
host=os.environ["OPENCTI_HOST"]; tok=os.environ["TOKEN"]
def gql(q,v=None):
    req=urllib.request.Request(host+"/graphql",
        data=json.dumps({"query":q,"variables":v or {}}).encode(),
        headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(req,timeout=30))
try:
    gql("{about{version}}")
except (urllib.error.URLError, OSError) as e:
    print(f"  OpenCTI not reachable ({e}); skipping its cleanup"); raise SystemExit(0)
n=0
d=gql("query($s:String){reports(search:$s,first:200){edges{node{id name}}}}",{"s":os.environ["MARKER"]})
for e in d.get("data",{}).get("reports",{}).get("edges",[]):
    node=e["node"]
    if os.environ["MARKER"] in (node.get("name") or ""):
        gql("mutation($id:ID!){reportEdit(id:$id){delete}}",{"id":node["id"]}); n+=1
        print("  OpenCTI report", node["name"])
for val in (os.environ["C2_IP"],os.environ["HOLD_HOST"],os.environ["HOLD_EXT"],os.environ["QR32_DST"],os.environ["SUBNET"]):
    d=gql("query($s:String){stixCyberObservables(search:$s,first:200){edges{node{id observable_value}}}}",{"s":val})
    for e in d.get("data",{}).get("stixCyberObservables",{}).get("edges",[]):
        node=e["node"]
        if (node.get("observable_value") or "")==val:
            gql("mutation($id:ID!){stixCyberObservableEdit(id:$id){delete}}",{"id":node["id"]}); n+=1
            print("  OpenCTI observable", val)
# Case-Incident and Vulnerability built by the assessment step.
d=gql("query($s:String){caseIncidents(search:$s,first:50){edges{node{id name}}}}",{"s":os.environ["MARKER"]})
for e in (d.get("data") or {}).get("caseIncidents",{}).get("edges",[]):
    node=e["node"]
    if os.environ["MARKER"] in (node.get("name") or ""):
        gql("mutation($id:ID!){stixDomainObjectEdit(id:$id){delete}}",{"id":node["id"]}); n+=1
        print("  OpenCTI case-incident", node["name"])
d=gql("query($s:String){vulnerabilities(search:$s,first:50){edges{node{id name}}}}",{"s":os.environ["CVE"]})
for e in (d.get("data") or {}).get("vulnerabilities",{}).get("edges",[]):
    node=e["node"]
    if (node.get("name") or "")==os.environ["CVE"]:
        gql("mutation($id:ID!){stixDomainObjectEdit(id:$id){delete}}",{"id":node["id"]}); n+=1
        print("  OpenCTI vulnerability", node["name"])
print(f"  removed {n} OpenCTI object(s)")
PY
  else
    echo "  OPENCTI_ADMIN_TOKEN not found in long-table/.env; left OpenCTI objects in place"
  fi
  echo ""
  echo "Clean complete."
  exit 0
fi

# ---------------------------------------------------------------------- run

RUN="$(date +%s)$$"
QR32_SIG="${MARKER} QR-0032 Acme Gateway update-service exploit ${RUN}"
QR33_SIG="${MARKER} QR-0033 outbound to flagged scanning range ${RUN}"
SIGID32=$(( 7000000 + (RUN % 900000) ))
SIGID33=$(( 7900000 + (RUN % 90000) ))
# Per-run subdomain on the lookalike payroll domain, so the Zeek dedup key
# (query, src, dst) differs each run and the sim survives rapid re-runs.
QR33_QUERY="q${SIGID33}.${HOLD_DOMAIN}"
MARK_ATTR="Other|text|${MARKER}|sim marker"

echo ""
echo "Walkthrough simulation: LT-2026-0007 arc (run ${RUN})"

# Seed the cases the classifier cannot originate.
echo ""
echo "Seeding Receiving Desk findings and the Society notification"

read -r RD47_ID _ < <(misp_add \
  "${MARKER} RD-2026-0047-A: ${CVE} firmware finding (Acme Industrial Gateway v2.3.1)" \
  'Receiving-Desk,Long-Table,tlp:amber,reliability="4"' 1 2 \
  "External analysis|vulnerability|${CVE}|firmware finding, CVSS 9.1" \
  "Network activity|ip-dst|${SUBNET}|water treatment signalling subnet" \
  "Other|text|Acme Industrial Gateway v2.3.1|affected product" \
  "Other|text|RD-2026-0047-A|internal reference" "$MARK_ATTR")
[ -n "${RD47_ID:-}" ] || { echo "  FAIL could not seed RD-2026-0047-A (is MISP up? key valid?)"; exit 1; }
echo "  ok   RD-2026-0047-A  (event $RD47_ID)"

read -r QR31_ID _ < <(misp_add \
  "${MARKER} QR-2026-0031: Society notification, ${C2_IP} -> ${SUBNET}" \
  'Quiet-Room,Society-notification,tlp:amber,Long-Table,reliability="4"' 1 2 \
  "Network activity|ip-src|${C2_IP}|source of observed traffic" \
  "Network activity|AS|AS16276|OVH SAS, FR" \
  "Network activity|ip-dst|${SUBNET}|water treatment signalling subnet" \
  "Other|datetime|2026-04-28T00:00:00|earliest observed activity" \
  "Other|text|QR-2026-0031|internal reference" \
  "Other|text|RD-2026-0047-A|related Long Table case" "$MARK_ATTR")
[ -n "${QR31_ID:-}" ] || { echo "  FAIL could not seed QR-2026-0031"; exit 1; }
echo "  ok   QR-2026-0031    (event $QR31_ID)"

read -r RD49_ID _ < <(misp_add \
  "${MARKER} RD-2026-0049: anonymous Tor tip, ${CVE} at water treatment sites" \
  'Receiving-Desk,Long-Table,tlp:amber,reliability="2"' 1 2 \
  "External analysis|vulnerability|${CVE}|reported at water treatment sites" \
  "Network activity|ip-dst|${SUBNET}|water treatment signalling subnet" \
  "Other|text|anonymous submission, reliability ceiling 2|source note" \
  "Other|text|RD-2026-0049|internal reference" "$MARK_ATTR")
[ -n "${RD49_ID:-}" ] || { echo "  FAIL could not seed RD-2026-0049"; exit 1; }
echo "  ok   RD-2026-0049    (event $RD49_ID)"

read -r RD48_ID _ < <(misp_add \
  "${MARKER} RD-2026-0048: Siemens S7-1200 ${ASIDE_CVE} (set aside, non-correlating)" \
  'Receiving-Desk,tlp:amber,reliability="2"' 0 1 \
  "External analysis|vulnerability|${ASIDE_CVE}|Siemens S7-1200" \
  "Network activity|ip-dst|${ASIDE_IP}|exposed S7-1200 host" \
  "Other|text|Siemens S7-1200 firmware v4.1|affected product" \
  "Other|text|RD-2026-0048|internal reference" "$MARK_ATTR")
[ -n "${RD48_ID:-}" ] || { echo "  FAIL could not seed RD-2026-0048"; exit 1; }
echo "  ok   RD-2026-0048    (event $RD48_ID, no Long-Table: stays out of OpenCTI)"

# QR-0032: a lone Suricata alert through the live classifier -> a tlp:white floor event.
echo ""
echo "Injecting QR-2026-0032 (automated sensor, lone Suricata alert)"
inject_suricata "$C2_IP" "$QR32_DST" "$QR32_SIG" "$SIGID32" \
  || { echo "  FAIL could not write to eve.json (is suricata up?)"; exit 1; }
QR32_FOUND="$(wait_for_event "$QR32_SIG" "" "the classifier's QR-0032 event")"
[ -n "$QR32_FOUND" ] || { echo "  FAIL classifier did not create the QR-0032 event in ${EVENT_TIMEOUT}s"; exit 1; }
echo "  ok   classifier created QR-0032 (event ${QR32_FOUND%% *}, tlp:white reliability 2)"

# QR-0033: Suricata then Zeek on a shared host -> a held correlated event; analyst routes it.
echo ""
echo "Injecting QR-2026-0033 (correlation hold, Suricata + Zeek)"
inject_suricata "$HOLD_HOST" "$HOLD_EXT" "$QR33_SIG" "$SIGID33" 2 51000 443 \
  || { echo "  FAIL could not write to eve.json"; exit 1; }
sleep 3   # let the classifier record and buffer the alert before the DNS log arrives
inject_zeek_dns "$HOLD_HOST" "$HOLD_EXT" "$QR33_QUERY" \
  || { echo "  FAIL could not write to dns.log (is zeek up?)"; exit 1; }
read -r HOLD_ID HOLD_UUID < <(wait_for_event "$HOLD_HOST" "needs-review" "the held correlated event")
[ -n "${HOLD_ID:-}" ] || { echo "  FAIL classifier did not create the held QR-0033 event in ${EVENT_TIMEOUT}s"; exit 1; }
echo "  ok   classifier held QR-0033 (event $HOLD_ID, tlp:amber needs-review reliability 3)"

# Optional manual-capture pause: hold here, before the analyst gate, so the
# needs-review state can be inspected or screenshotted. Set PAUSE_AT_HOLD=1 and
# touch the continue file (default /tmp/sim-hold-continue) to resume.
if [ -n "${PAUSE_AT_HOLD:-}" ]; then
  CONT="${HOLD_CONTINUE:-/tmp/sim-hold-continue}"
  rm -f "$CONT"
  echo ""
  echo "  PAUSE_AT_HOLD: QR-0033 is held (needs-review, no Long-Table yet)"
  echo "  capture it at ${MISP_HOST}/events/view/${HOLD_ID}"
  echo "  waiting for ${CONT} before the analyst gate (touch it to continue) ..."
  while [ ! -e "$CONT" ]; do sleep 2; done
  rm -f "$CONT"
  echo "  resuming"
fi

echo "  analyst gate: approving QR-0033 (adding Long-Table)"
misp_attach_tag "$HOLD_UUID" "Long-Table"
echo "  ok   QR-0033 routed to the Long Table"

# QR-0034: a feed claim, dropped. No MISP event; the drop log is the only record.
echo ""
echo "Recording QR-2026-0034 (third-party feed, dropped)"
write_drop "$FEED_IP" "third-party-feed" 1 "below threshold, no local correlation" \
  || { echo "  FAIL could not write the drop-log entry"; exit 1; }
if [ -n "$(misp_search "$FEED_IP" "")" ]; then
  echo "  FAIL a MISP event exists for the dropped feed indicator $FEED_IP (should be none)"; exit 1
fi
echo "  ok   $FEED_IP dropped, logged, no MISP event"

# Verify convergence in OpenCTI.
if [ "$MODE" = noverify ]; then
  echo ""
  echo "Skipping OpenCTI verification (--no-verify)."
  echo ""
  echo "Simulation complete."
  exit 0
fi

OCTI_TOKEN="$(read_env "$REPO/long-table/.env" OPENCTI_ADMIN_TOKEN)"
[ -n "$OCTI_TOKEN" ] || { echo ""; echo "OPENCTI_ADMIN_TOKEN not found in long-table/.env; run with --no-verify to skip"; exit 2; }

echo ""
echo "Verifying convergence in OpenCTI (connector interval ~60s)"
echo -n "  waiting for ${C2_IP} to cross the connector "
FOUND=0
for _ in $(seq 1 "$OPENCTI_TIMEOUT"); do
  if octi_has_observable "$C2_IP"; then FOUND=1; break; fi
  echo -n "."; sleep 1
done
echo ""
if [ "$FOUND" != 1 ]; then
  echo "  FAIL ${C2_IP} did not reach OpenCTI within ${OPENCTI_TIMEOUT}s"
  echo "       (connector not fetching, or worker ingest stalled)"
  exit 1
fi
echo "  ok   ${C2_IP} present in OpenCTI (QR-0031 + QR-0032 converge)"

if octi_has_observable "$ASIDE_IP"; then
  echo "  note ${ASIDE_IP} is in OpenCTI; RD-0048 was expected to stay out (no Long-Table)"
else
  echo "  ok   ${ASIDE_IP} absent (RD-0048 set aside, did not converge)"
fi
if octi_has_observable "$FEED_IP"; then
  echo "  note ${FEED_IP} is in OpenCTI; the dropped feed claim should not have crossed"
else
  echo "  ok   ${FEED_IP} absent (QR-0034 dropped, never an event)"
fi

# The Long Table analyst consolidates the inputs into one assessment. The connector
# imports each event as an isolated report and builds no cross-event links, so this
# step is what produces the LT-2026-0007 picture: a Vulnerability entity, the IP and
# subnet observables, the relationships between them, and a Case-Incident that gathers
# the CVE, the observables and the four input reports. RD-0048 is deliberately left out.
echo ""
echo "Building the Long-Table consolidated assessment LT-2026-0007 in OpenCTI"
OPENCTI_HOST="$OPENCTI_HOST" TOKEN="$OCTI_TOKEN" MARKER="$MARKER" \
CVE="$CVE" C2_IP="$C2_IP" SUBNET="$SUBNET" \
python3 -u - <<'PY' || { echo "  FAIL could not build the LT-2026-0007 assessment"; exit 1; }
import os, json, urllib.request

host=os.environ["OPENCTI_HOST"]; tok=os.environ["TOKEN"]; marker=os.environ["MARKER"]
CVE=os.environ["CVE"]; IP=os.environ["C2_IP"]; SUBNET=os.environ["SUBNET"]
lit=json.dumps   # a value as a GraphQL/JSON string literal

def gql(q):
    req=urllib.request.Request(host+"/graphql", data=json.dumps({"query":q}).encode(),
        headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    r=json.load(urllib.request.urlopen(req,timeout=30))
    if r.get("errors"):
        raise SystemExit("  GraphQL error: "+json.dumps(r["errors"])[:400])
    return r["data"]

# The four inputs (RD-0048 excluded by omission). Poll until the connector has
# imported all four; match each ref as a substring of the report name (one marker
# search, robust to how OpenCTI tokenises the reference strings).
import time
want={"RD-2026-0047-A":None,"QR-2026-0031":None,"RD-2026-0049":None,"QR-0032":None}
deadline=time.time()+90
while time.time()<deadline:
    d=gql("{reports(search:%s,first:200){edges{node{id name}}}}" % lit(marker))
    for e in d["reports"]["edges"]:
        nm=e["node"]["name"] or ""
        if marker not in nm:
            continue
        for ref in want:
            if want[ref] is None and ref in nm:
                want[ref]=e["node"]["id"]
    if all(v is not None for v in want.values()):
        break
    time.sleep(5)
report_ids=[v for v in want.values() if v]
print("  linked %d of 4 input report(s)" % len(report_ids))

# Vulnerability.
d=gql("{vulnerabilities(search:%s,first:10){edges{node{id name}}}}" % lit(CVE))
vid=next((e["node"]["id"] for e in d["vulnerabilities"]["edges"] if e["node"]["name"]==CVE),None)
if not vid:
    desc=("%s: unauthenticated command execution in the Acme Industrial Gateway update "
          "service. CVSS 9.1; vendor notified 2026-04-14; ninety-day window closing "
          "2026-07-13." % marker)
    d=gql("mutation{vulnerabilityAdd(input:{name:%s,description:%s,x_opencti_cvss_base_score:9.1}){id}}"
          % (lit(CVE), lit(desc)))
    vid=d["vulnerabilityAdd"]["id"]; print("  created Vulnerability %s" % CVE)
else:
    print("  Vulnerability %s present" % CVE)

# Observables (the connector usually already has the IP; create what is missing).
def ensure_obs(value):
    d=gql("{stixCyberObservables(search:%s,first:20){edges{node{id observable_value}}}}" % lit(value))
    for e in d["stixCyberObservables"]["edges"]:
        if e["node"]["observable_value"]==value:
            return e["node"]["id"]
    d=gql('mutation{stixCyberObservableAdd(type:"IPv4-Addr",IPv4Addr:{value:%s}){id}}' % lit(value))
    print("  created observable %s" % value)
    return d["stixCyberObservableAdd"]["id"]
ip_id=ensure_obs(IP); net_id=ensure_obs(SUBNET)

# Relationships: related-to is the catch-all OpenCTI accepts between these types.
for a,b in ((ip_id,vid),(net_id,vid),(ip_id,net_id)):
    gql("mutation{stixCoreRelationshipAdd(input:{fromId:%s,toId:%s,relationship_type:\"related-to\"}){id}}"
        % (lit(a), lit(b)))
print("  related the IP and subnet to the CVE")

# Case-Incident: the consolidated assessment that gathers the lot.
name="%s LT-2026-0007" % marker
d=gql("{caseIncidents(search:%s,first:10){edges{node{id name}}}}" % lit(name))
cid=next((e["node"]["id"] for e in d["caseIncidents"]["edges"] if e["node"]["name"]==name),None)
if not cid:
    desc=("Consolidated assessment: CVE-2026-4471 exploited from 94.23.117.8 (AS16276) "
          "against 10.44.12.0/24 (water treatment signalling) from approximately "
          "2026-04-28. Inputs: RD-2026-0047-A, QR-2026-0031, RD-2026-0049, QR-2026-0032. "
          "RD-2026-0048 set aside. Determination: escalate.")
    objs="[%s]" % ",".join(lit(i) for i in ([vid, ip_id, net_id] + report_ids))
    d=gql("mutation{caseIncidentAdd(input:{name:%s,description:%s,confidence:80,objects:%s}){id}}"
          % (lit(name), lit(desc), objs))
    cid=d["caseIncidentAdd"]["id"]; print("  created Case-Incident %s" % name)
else:
    print("  Case-Incident %s present" % name)
print("  ok   LT-2026-0007 assessment built (Case-Incident id %s)" % cid)
PY

echo ""
echo "Simulation complete. LT-2026-0007 is consolidated in OpenCTI."
echo "Inspect the Case-Incident there, or run '$(basename "$0") --clean' to remove the artefacts."
