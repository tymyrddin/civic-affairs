# Organisational divisions

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

## Receiving Desk

Coordinated vulnerability disclosure intake. Three channels: security.txt for standard
submissions, PGP-encrypted email for sensitive identified submissions, and a Tor onion service for
anonymous material whose provenance is not recorded.

Every submission produces a case record. Triage routes each case to the appropriate division:
signals-layer findings to the Quiet Room, intelligence-layer findings to the Long Table.
Submissions spanning categories are split and routed separately.

Identified submitters receive acknowledgement within two working days, triage determination within
ten, and escalation status within thirty. Anonymous submissions receive their case reference
through the same Tor onion service used to submit.
