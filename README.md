# Civic affairs

Signal intake, threat correlation, hardware analysis, and coordinated disclosure intake for the
Civic Defence Establishment.

Four operational divisions with distinct data domains and tool stacks. Divisional boundaries
reflect organisational structure, not data flow; this repository covers the full pipeline.

## Pipeline

```
Suricata ──┐
Zeek       ├──► Quiet Room ──► MISP (reliability 3+) ──► Long Table ──► Assessment
Wazuh      ┘    filter           store, route              correlate
                normalise                                   interpret
                classify                                    escalate

Receiving Desk ──► Quiet Room │ Long Table │ Repair Shop
```

The Quiet Room filters, normalises, and classifies incoming signals. Classified material is
written to MISP; MISP stores it and routes it to the Long Table. The Long Table correlates,
interprets, and escalates. Wazuh supplies selective host telemetry; selection is a deployment
decision, not an analysis-time filter. Automation assists prioritisation. Adjudication remains
with analysts. Provenance records track acquisition path, not truth ancestry.

The Receiving Desk handles disclosure intake and routes each case to the appropriate division.
The Repair Shop handles devices that require physical access.

## Quiet Room

Signal intake, normalisation, and classification. Suricata and Zeek run on network perimeter
sensors and are complementary: Suricata triggers on rule signatures; Zeek captures full connection
metadata regardless of whether a signature fires. Wazuh provides host-level telemetry on a
selective basis, assigned by group at deployment, not filtered at analysis time.

Incoming material is classified on two axes: source taxonomy (Society notification, Office
advisory, or Other) and reliability (1–5). Scores are auto-assigned on intake from source taxonomy
defaults. Analyst review is required before material is escalated or routed above the reliability
threshold. Manual override is available at any stage. The automation handles volume; the analyst
handles adjudication.

Material at reliability 3 or above with clear source attribution is written to MISP and routed to
the Long Table. Material below threshold is dropped and logged. The drop log is retained for 90
days for retrospective analysis.

The Quiet Room characterises. It does not interpret or investigate.

Stack: Suricata, Zeek, Wazuh, MISP, Shuffle.

## Long Table

Correlation, interpretation, and escalation. Receives classified signals from the Quiet Room as
MISP events — IP addresses, domains, certificates, file hashes, network behaviour patterns — and
correlates them across time and source. Enrichment draws on RIPE NCC (prefix and ASN data), CIRCL
passive DNS (domain history), and crt.sh (certificate transparency).

An analyst reviews the correlated picture and produces a consolidated assessment: attributed
infrastructure, campaign patterns, confidence levels, and a routing determination. The Long Table
produces one view; it does not append alternatives.

The Long Table's domain is the threat actor. Firmware vulnerability findings and CVE enrichment
belong to the Watch Tower, which runs on the Office's infrastructure. The two domains are adjacent:
a vulnerability being actively exploited produces both a Watch Tower finding and a Quiet Room
signal. Whether the two instances share events, and under what rules, is an open architectural
question.

MISP galaxies and event correlation may be sufficient for actor attribution and campaign tracking
at expected event volume. OpenCTI (Filigran, France) provides relationship graph and actor mapping
that MISP does not handle as natively, at the cost of a VC-backed dependency. The choice between
MISP alone and MISP + OpenCTI is unresolved.

Stack: MISP, Shuffle, RIPE NCC API, CIRCL passive DNS, crt.sh. OpenCTI: under evaluation.

## Repair Shop

Active hardware and firmware analysis. Works with devices in hand under conditions that do not
permit engagement through normal channels. JTAG and SWD debug interfaces, physical teardown,
direct flash storage access, and offline binary analysis.

Covers three classes of work: devices that cannot be assessed through network-layer approaches,
supply chain material requiring verification before deployment, and hardware submitted through the
Receiving Desk whose provenance or contents warrant examination before the material is trusted.

Analysis runs in offline, isolated environments. Output is reviewed before anything leaves.

## Receiving Desk

Coordinated vulnerability disclosure intake. Three channels: security.txt for standard
submissions, PGP-encrypted email for sensitive identified submissions, and a Tor onion service for
anonymous material whose provenance is not recorded.

Every submission produces a case record. Triage routes each case to the appropriate division:
signals-layer findings to the Quiet Room, intelligence-layer findings to the Long Table, hardware
or firmware submissions to the Repair Shop. Submissions spanning categories are split and routed
separately.

Identified submitters receive acknowledgement within two working days, triage determination within
ten, and escalation status within thirty. Anonymous submissions receive their case reference
through the same Tor onion service used to submit.

## Infrastructure

Per-division Docker Compose files. One control script.

```
./ctl up             start the full pipeline
./ctl down           stop; volumes preserved
./ctl down --volumes stop; destroy all data (confirmation required)
./ctl purge          remove everything including built images
```

`misp/` starts first and creates `pipeline-net`. `shuffle/` and `long-table/` join it as
external and will not start without it.

Each division has an `env.example`. Copy to `.env` and set values before first start.

The Receiving Desk requires a TLS certificate before Nginx starts. Run
`receiving-desk/init-certs.sh <domain>` to seed a temporary self-signed cert into the Certbot
volume, then obtain a real Let's Encrypt certificate once the stack is running.