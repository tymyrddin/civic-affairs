"""
Quiet Room classifier: the automated sensor path.

Tails Suricata EVE JSON and Zeek logs, and turns each sensor signal into a MISP
event. The Quiet Room characterises; it does not interpret.

Behaviour follows the establishment walkthroughs:

  Floor (walkthrough-automated-sensor): every sensor signal becomes a MISP event,
  tagged Quiet-Room, tlp:white, reliability 2. Below the routing threshold of 3 it
  is recorded but not routed; the MISP->OpenCTI connector still carries tlp:white
  events on to the Long Table. Reliability decides whether it routes, not whether
  it is recorded.

  Correlation hold (walkthrough-correlation-hold): when a new signal shares a
  host IP with a recent signal from the other sensor (Suricata + Zeek)
  within a window, two independent sensors on the same infrastructure clear the
  threshold where neither did alone. The classifier posts a second, correlated
  event at reliability 3, tagged Quiet-Room, tlp:amber, needs-review, distribution
  1. It is held, not routed: an analyst promotes it by adding the Long-Table tag.

The drop log (walkthrough-drop) is not produced here: it is for material that
fails validation before becoming an event (malformed, duplicate, or a discredited
source such as a low-reliability third-party feed). The classifier does not ingest
feeds, so those entries are written externally; this process only prunes the log
to its retention window. A drop entry is one JSON object per line:
{ts, iso, indicator, source, reliability, reason}.

Offsets persist per file. The Suricata offset stays at /state/offset for the
compose healthcheck; Zeek offsets live in /state/zeek-offsets.json.

Environment:
  MISP_URL              container-to-container MISP address  (default: https://misp:443)
  MISP_VERIFYCERT       "true"/"false" for TLS verification  (default: false)
  MISP_API_KEY          MISP automation key (required)
  ZEEK_LOG_DIR          directory of the mounted Zeek logs   (default: /opt/zeek/logs)
  ZEEK_LOGS             comma-separated Zeek logs to tail     (default: dns.log)
  QR_CORRELATION_WINDOW seconds for the cross-sensor hold     (default: 600)
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from pymisp import MISPAttribute, MISPEvent, PyMISP

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("classifier")

EVE_PATH = Path("/var/log/suricata/eve.json")
STATE_DIR = Path("/state")
EVE_OFFSET_PATH = STATE_DIR / "offset"            # kept here for the compose healthcheck
ZEEK_OFFSET_PATH = STATE_DIR / "zeek-offsets.json"
DROP_LOG_PATH = STATE_DIR / "drops.log"

ZEEK_LOG_DIR = Path(os.environ.get("ZEEK_LOG_DIR", "/opt/zeek/logs"))
ZEEK_LOGS = [n.strip() for n in os.environ.get("ZEEK_LOGS", "dns.log").split(",") if n.strip()]

POLL_INTERVAL = 1.0          # seconds between tail polls
DEDUP_WINDOW = 300           # seconds — suppress repeat (signal) tuples
CORRELATION_WINDOW = int(os.environ.get("QR_CORRELATION_WINDOW", "600"))
ROUTING_THRESHOLD = 3
SENSOR_RELIABILITY = 2       # a single sensor signal, uncorroborated
CORRELATED_RELIABILITY = 3   # two independent sensors on the same infrastructure
DROP_RETENTION_DAYS = 90
BACKOFF_BASE = 1.0
BACKOFF_MAX = 60.0


# --------------------------------------------------------------------------- MISP

def misp_connect() -> PyMISP:
    url = os.environ.get("MISP_URL", "https://misp:443")
    key = os.environ["MISP_API_KEY"]
    verify = os.environ.get("MISP_VERIFYCERT", "false").lower() == "true"
    return PyMISP(url, key, ssl=verify)


def add_event_with_retry(misp: PyMISP, event: MISPEvent) -> Optional[str]:
    """Post an event, retrying with capped backoff. Returns its UUID."""
    backoff = BACKOFF_BASE
    attempt = 0
    while True:
        try:
            result = misp.add_event(event)
            return result.get("Event", {}).get("uuid", "?")
        except Exception as exc:
            attempt += 1
            log.warning("MISP add_event error (attempt %d): %s", attempt, exc)
            time.sleep(min(backoff * (2 ** (attempt - 1)), BACKOFF_MAX))


# --------------------------------------------------------------------------- events

def severity_to_threat_level(suricata_severity: int) -> int:
    """Map Suricata alert severity (1=high, 2=med, 3=low) to MISP threat level id."""
    return {1: 1, 2: 2, 3: 3}.get(suricata_severity, 2)


def _add_attrs(event: MISPEvent, attrs: list) -> None:
    for category, type_, value, comment in attrs:
        if not value:
            continue
        a = MISPAttribute()
        a.category = category
        a.type = type_
        a.value = str(value)
        if comment:
            a.comment = comment
        a.to_ids = False     # characterisation, not detection: do not feed back as rules
        event.attributes.append(a)


def _new_event(info: str, threat_level: int, distribution: int, tags: list) -> MISPEvent:
    event = MISPEvent()
    event.info = info
    event.threat_level_id = threat_level
    event.analysis = 0       # initial
    event.distribution = distribution
    for tag in tags:
        event.add_tag(tag)
    return event


def build_base_event(se: dict) -> MISPEvent:
    """The floor: every sensor signal becomes a tlp:white event at reliability 2."""
    event = _new_event(
        se["summary"], se.get("threat_level", 2), distribution=0,
        tags=["Quiet-Room", "tlp:white", f'reliability="{SENSOR_RELIABILITY}"'],
    )
    _add_attrs(event, se["attrs"])
    return event


def build_correlated_event(a: dict, b: dict) -> MISPEvent:
    """The hold: a cross-sensor match on shared infrastructure, reliability 3, needs-review."""
    shared = sorted(set(a["hosts"]) & set(b["hosts"]))
    host = shared[0] if shared else (a.get("dest") or b.get("dest") or "?")
    event = _new_event(
        f"Correlated: shared infrastructure {host}", threat_level=2, distribution=1,
        tags=["Quiet-Room", "tlp:amber", "needs-review", f'reliability="{CORRELATED_RELIABILITY}"'],
    )
    merged: list = []
    seen: set = set()
    for attrs in (a["attrs"], b["attrs"]):
        for cat, type_, value, comment in attrs:
            k = (type_, str(value))
            if value and k not in seen:
                seen.add(k)
                merged.append((cat, type_, value, comment))
    merged.append(("Other", "comment",
                   f"two independent sensors on {', '.join(shared) or host} within "
                   f"{CORRELATION_WINDOW}s (Suricata + Zeek); held for analyst review",
                   "correlation hold"))
    _add_attrs(event, merged)
    return event


# --------------------------------------------------------------------------- parsing

def parse_suricata(raw: str) -> Optional[dict]:
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if event.get("event_type") != "alert":
        return None
    sig = event.get("alert", {})
    src, dst = event.get("src_ip", ""), event.get("dest_ip", "")
    sig_id = sig.get("signature_id", "")
    return {
        "sensor": "suricata",
        "dest": dst,
        "hosts": [h for h in (src, dst) if h],
        "summary": f"Suricata IDS Alert: {sig.get('signature', 'unknown')}",
        "threat_level": severity_to_threat_level(sig.get("severity", 2)),
        "dedup_key": ("suricata", sig_id, src, dst),
        "attrs": [
            ("Network activity", "ip-src", src, ""),
            ("Network activity", "ip-dst", dst, ""),
            ("Network activity", "port", event.get("src_port", ""), "src port"),
            ("Network activity", "port", event.get("dest_port", ""), "dst port"),
            ("Network activity", "text", event.get("proto", ""), ""),
            ("Network activity", "text", sig.get("signature", ""), "signature"),
            ("Network activity", "text", sig.get("category", ""), "category"),
            ("Network activity", "text", sig_id, "signature_id"),
        ],
    }


def parse_zeek(logname: str, raw: str) -> Optional[dict]:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    # Zeek JSON uses flat dotted keys: "id.orig_h", "id.resp_h".
    src = obj.get("id.orig_h", "")
    dst = obj.get("id.resp_h", "")
    proto = obj.get("proto", "")
    attrs = [
        ("Network activity", "ip-src", src, "zeek orig"),
        ("Network activity", "ip-dst", dst, "zeek resp"),
        ("Network activity", "text", proto, "proto"),
    ]
    if logname == "dns.log":
        query = obj.get("query", "")
        summary = f"Zeek DNS: {query or '(no query)'}"
        dedup = ("zeek-dns", query, src, dst)
        if query:
            attrs.append(("Network activity", "domain", query, "queried name"))
    else:
        service = obj.get("service", "") or logname.removesuffix(".log")
        summary = f"Zeek {logname}: {service}"
        dedup = ("zeek", logname, src, dst)
        if service:
            attrs.append(("Network activity", "text", service, "service"))
    return {
        "sensor": "zeek",
        "dest": dst,
        "hosts": [h for h in (src, dst) if h],
        "summary": summary,
        "threat_level": 2,
        "dedup_key": dedup,
        "attrs": attrs,
    }


# --------------------------------------------------------------------------- drop log

def prune_drop_log() -> None:
    """Keep the externally-written drop log to its retention window."""
    if not DROP_LOG_PATH.exists():
        return
    cutoff = time.time() - DROP_RETENTION_DAYS * 86400
    kept = []
    with DROP_LOG_PATH.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                if json.loads(line).get("ts", 0) >= cutoff:
                    kept.append(line)
            except json.JSONDecodeError:
                continue
    tmp = DROP_LOG_PATH.with_suffix(".tmp")
    tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    tmp.replace(DROP_LOG_PATH)


# --------------------------------------------------------------------------- tailing

class Tailer:
    """Tails one append-only file, persisting its byte offset across restarts."""

    def __init__(self, path: Path, name: str,
                 load_offset: Callable[[], int], save_offset: Callable[[int], None]):
        self.path = path
        self.name = name
        self._load = load_offset
        self._save = save_offset
        self.last_inode: Optional[int] = None

    def consume(self, handler: Callable[[str], None]) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return
        offset = self._load()
        if offset is None:
            # No stored offset. Files present at startup were primed to EOF
            # (prime_to_eof), so reaching here means the file appeared after
            # startup: all of its content is new, read it from the beginning.
            offset = 0
        if self.last_inode is not None and stat.st_ino != self.last_inode:
            log.info("%s rotated (inode changed), resetting offset", self.name)
            offset = 0
            self._save(0)
        self.last_inode = stat.st_ino
        if stat.st_size < offset:
            log.info("%s truncated, resetting offset", self.name)
            offset = 0
        if stat.st_size == offset:
            return
        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for raw in f:
                offset += len(raw.encode("utf-8", errors="replace"))
                if raw.strip():
                    handler(raw)
                self._save(offset)

    def prime_to_eof(self) -> None:
        """If the file exists at startup and has no stored offset, start at its end
        so a restart does not replay pre-existing history. A file that does not exist
        yet is left unprimed and read from the beginning when it later appears."""
        if self._load() is not None:
            return
        try:
            self._save(self.path.stat().st_size)
        except FileNotFoundError:
            pass


def eve_offset_io():
    def load() -> Optional[int]:
        # None means "no stored offset": the tailer then starts at end-of-file
        # rather than replaying the whole log on first sight or after a wipe.
        try:
            return int(EVE_OFFSET_PATH.read_text().strip())
        except (FileNotFoundError, ValueError):
            return None

    def save(offset: int) -> None:
        EVE_OFFSET_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVE_OFFSET_PATH.write_text(str(offset))

    return load, save


class ZeekOffsets:
    """Per-file Zeek offsets, persisted together as one JSON map."""

    def __init__(self) -> None:
        try:
            self._data = json.loads(ZEEK_OFFSET_PATH.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            self._data = {}

    def io(self, name: str):
        def load() -> Optional[int]:
            if name not in self._data:
                return None
            try:
                return int(self._data[name])
            except (TypeError, ValueError):
                return None

        def save(offset: int) -> None:
            self._data[name] = offset
            ZEEK_OFFSET_PATH.parent.mkdir(parents=True, exist_ok=True)
            ZEEK_OFFSET_PATH.write_text(json.dumps(self._data))

        return load, save


# --------------------------------------------------------------------------- pipeline

class Classifier:
    def __init__(self, misp: PyMISP) -> None:
        self.misp = misp
        self.dedup: dict = {}     # signal key -> monotonic time last seen
        self.recent: list = []    # buffered signals awaiting a cross-sensor partner

    def _find_partner(self, se: dict, now: float) -> Optional[dict]:
        """A buffered signal from the other sensor sharing any host IP, within the window."""
        hosts = set(se["hosts"])
        if not hosts:
            return None
        for entry in self.recent:
            if entry["sensor"] == se["sensor"]:
                continue
            if now - entry["_t"] > CORRELATION_WINDOW:
                continue
            if hosts & set(entry["hosts"]):
                return entry
        return None

    def process(self, se: dict) -> None:
        now = time.monotonic()
        self.dedup = {k: v for k, v in self.dedup.items() if now - v < DEDUP_WINDOW}
        self.recent = [e for e in self.recent if now - e["_t"] < CORRELATION_WINDOW]

        key = se["dedup_key"]
        if key in self.dedup:
            log.info("dedup skip  %s", se["summary"])
            return
        self.dedup[key] = now

        # Floor: every signal becomes a tlp:white event, routed or not.
        base = add_event_with_retry(self.misp, build_base_event(se))
        log.info("recorded    event=%s rel=2 %s", base, se["summary"])

        # Correlation hold: a cross-sensor match on the destination IP clears threshold.
        partner = self._find_partner(se, now)
        if partner:
            held = add_event_with_retry(self.misp, build_correlated_event(partner, se))
            log.info("held        event=%s rel=3 needs-review %s + %s",
                     held, partner["summary"], se["summary"])
            self.recent.remove(partner)
            return

        se["_t"] = now
        self.recent.append(se)


# --------------------------------------------------------------------------- main

def main() -> None:
    if "MISP_API_KEY" not in os.environ:
        log.error("MISP_API_KEY is not set")
        sys.exit(1)

    prune_drop_log()
    last_prune = time.monotonic()

    misp: Optional[PyMISP] = None
    backoff = BACKOFF_BASE
    attempt = 0
    while misp is None:
        try:
            misp = misp_connect()
            log.info("connected to MISP at %s", os.environ.get("MISP_URL", "https://misp:443"))
        except Exception as exc:
            attempt += 1
            wait = min(backoff * (2 ** (attempt - 1)), BACKOFF_MAX)
            log.warning("MISP connection failed (attempt %d): %s — retrying in %.0fs", attempt, exc, wait)
            time.sleep(wait)

    classifier = Classifier(misp)

    def handle(parse: Callable[[str], Optional[dict]]) -> Callable[[str], None]:
        def handler(raw: str) -> None:
            se = parse(raw)
            if se:
                classifier.process(se)
        return handler

    eve_load, eve_save = eve_offset_io()
    pairs = [(Tailer(EVE_PATH, "eve.json", eve_load, eve_save), handle(parse_suricata))]

    zeek_offsets = ZeekOffsets()
    for name in ZEEK_LOGS:
        load, save = zeek_offsets.io(name)
        tailer = Tailer(ZEEK_LOG_DIR / name, name, load, save)
        pairs.append((tailer, handle(lambda raw, ln=name: parse_zeek(ln, raw))))

    log.info("tailing eve.json and Zeek logs %s from %s", ZEEK_LOGS, ZEEK_LOG_DIR)

    # Skip pre-existing history for files present now; files that appear later are
    # read from the start (their content is all new).
    for tailer, _ in pairs:
        tailer.prime_to_eof()

    while True:
        for tailer, handler in pairs:
            tailer.consume(handler)
        if time.monotonic() - last_prune > 3600:
            prune_drop_log()
            last_prune = time.monotonic()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
