"""
Quiet Room classifier: tails Suricata EVE JSON, creates MISP events for IDS alerts.

Reads /var/log/suricata/eve.json, filters event_type == "alert", and posts each alert
to MISP via its REST API. Tracks file offset across restarts. Deduplicates by
(signature_id, src_ip, dest_ip) within a 5-minute window to suppress alert storms.

Environment:
  MISP_URL          container-to-container MISP address  (default: https://misp:443)
  MISP_VERIFYCERT   "true"/"false" for TLS verification  (default: false)
  MISP_API_KEY      MISP automation key (required)
"""

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

from pymisp import MISPEvent, MISPAttribute, PyMISP

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("classifier")

EVE_PATH = Path("/var/log/suricata/eve.json")
STATE_PATH = Path("/state/offset")
POLL_INTERVAL = 1.0          # seconds between tail polls
DEDUP_WINDOW = 300           # seconds — suppress repeat (sig, src, dst) tuples
BACKOFF_BASE = 1.0
BACKOFF_MAX = 60.0


def misp_connect() -> PyMISP:
    url = os.environ.get("MISP_URL", "https://misp:443")
    key = os.environ["MISP_API_KEY"]
    verify = os.environ.get("MISP_VERIFYCERT", "false").lower() == "true"
    return PyMISP(url, key, ssl=verify)


def severity_to_threat_level(suricata_severity: int) -> int:
    """Map Suricata alert severity (1=high, 2=med, 3=low) to MISP threat level id."""
    return {1: 1, 2: 2, 3: 3}.get(suricata_severity, 2)


def make_event(alert: dict) -> MISPEvent:
    sig = alert.get("alert", {})
    event = MISPEvent()
    event.info = f"Suricata IDS Alert: {sig.get('signature', 'unknown')}"
    event.threat_level_id = severity_to_threat_level(sig.get("severity", 2))
    event.analysis = 0       # initial
    event.distribution = 0  # organisation-only

    event.add_tag("Quiet-Room")
    event.add_tag("tlp:white")

    def attr(category: str, type_: str, value: str, comment: str = "") -> None:
        if value:
            a = MISPAttribute()
            a.category = category
            a.type = type_
            a.value = str(value)
            if comment:
                a.comment = comment
            a.to_ids = False
            event.attributes.append(a)

    attr("Network activity", "ip-src",  alert.get("src_ip", ""))
    attr("Network activity", "ip-dst",  alert.get("dest_ip", ""))
    attr("Network activity", "port",    str(alert.get("src_port", "")),  "src port")
    attr("Network activity", "port",    str(alert.get("dest_port", "")), "dst port")
    attr("Network activity", "text",    alert.get("proto", ""))
    attr("Network activity", "text",    sig.get("signature", ""),        "signature")
    attr("Network activity", "text",    sig.get("category", ""),         "category")
    attr("Network activity", "text",    str(sig.get("signature_id", "")), "signature_id")

    return event


def read_offset() -> int:
    try:
        return int(STATE_PATH.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def write_offset(offset: int) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(str(offset))


def tail_alerts(misp: PyMISP) -> None:
    dedup: dict[tuple, float] = {}
    backoff = BACKOFF_BASE

    offset = read_offset()
    last_inode: Optional[int] = None

    log.info("starting tail from offset %d", offset)

    while True:
        try:
            stat = EVE_PATH.stat()
        except FileNotFoundError:
            log.info("eve.json not found, waiting")
            time.sleep(POLL_INTERVAL)
            continue

        if last_inode is not None and stat.st_ino != last_inode:
            log.info("file rotated (inode changed), resetting offset")
            offset = 0
            write_offset(0)

        last_inode = stat.st_ino

        if stat.st_size < offset:
            log.info("file truncated, resetting offset")
            offset = 0

        if stat.st_size == offset:
            time.sleep(POLL_INTERVAL)
            continue

        with EVE_PATH.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for raw in f:
                offset += len(raw.encode("utf-8", errors="replace"))
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") != "alert":
                    continue

                sig_id = event.get("alert", {}).get("signature_id", "")
                src = event.get("src_ip", "")
                dst = event.get("dest_ip", "")
                key = (sig_id, src, dst)
                now = time.monotonic()

                # expire stale dedup entries
                dedup = {k: v for k, v in dedup.items() if now - v < DEDUP_WINDOW}

                if key in dedup:
                    log.info("dedup skip  sig=%s %s->%s", sig_id, src, dst)
                    continue

                misp_event = make_event(event)
                attempt = 0
                while True:
                    try:
                        result = misp.add_event(misp_event)
                        uuid = result.get("Event", {}).get("uuid", "?")
                        log.info("created     event=%s sig=%s %s->%s", uuid, sig_id, src, dst)
                        dedup[key] = now
                        backoff = BACKOFF_BASE
                        break
                    except Exception as exc:
                        attempt += 1
                        log.warning("MISP error (attempt %d): %s", attempt, exc)
                        time.sleep(min(backoff * (2 ** (attempt - 1)), BACKOFF_MAX))
                write_offset(offset)

        write_offset(offset)
        time.sleep(POLL_INTERVAL)


def main() -> None:
    if "MISP_API_KEY" not in os.environ:
        log.error("MISP_API_KEY is not set")
        sys.exit(1)

    misp: Optional[PyMISP] = None
    backoff = BACKOFF_BASE
    attempt = 0
    while misp is None:
        try:
            misp = misp_connect()
            log.info("connected to MISP at %s", os.environ.get("MISP_URL", "https://misp:443"))
            backoff = BACKOFF_BASE
        except Exception as exc:
            attempt += 1
            wait = min(backoff * (2 ** (attempt - 1)), BACKOFF_MAX)
            log.warning("MISP connection failed (attempt %d): %s — retrying in %.0fs", attempt, exc, wait)
            time.sleep(wait)

    tail_alerts(misp)


if __name__ == "__main__":
    main()
