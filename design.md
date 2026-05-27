# Design choices

Decisions made during infrastructure setup, with the reasoning behind each. Recorded for
accountability and to make future changes deliberate rather than accidental.

## Repository structure

Per-division Docker Compose files rather than a single root compose file. Matches the
organisational structure of the pipeline and allows divisions to be brought up, updated, or
torn down independently. The trade-off is that cross-division communication requires explicit
named networks and a defined startup order.

## Network topology

`pipeline-net` is a named bridge network created by `misp/compose.yml` and referenced as
external by `shuffle/compose.yml` and `long-table/compose.yml`. MISP starts first; the other
compose projects fail without it. Internal communication within each division uses a separate
`internal: true` bridge network, isolating division components from the pipeline network.

Alternatives considered: a single shared network for everything (simpler but no isolation), or
per-division networks with explicit peering (more granular but adds operational complexity for
no clear benefit at this stage).

## MISP as shared infrastructure

MISP sits in its own directory rather than inside `quiet-room/` or `long-table/`. It is the
store-and-route layer for the whole pipeline; giving it to a single division would misrepresent
its role and create an awkward dependency from the other division.

## Shuffle as shared infrastructure

One Shuffle instance serves both the Quiet Room (intake automation, MISP ingestion) and the
Long Table (enrichment workflows). A per-division approach would mean two OpenSearch deployments
for no operational gain. Division-specific workflows are separated by configuration within the
single instance.

## OpenCTI: live services in long-table/

The choice between MISP alone and MISP + OpenCTI is unresolved, but including OpenCTI as live
service definitions in `long-table/compose.yml` means the stack is ready to activate rather than
requiring a separate implementation step when the decision lands. The services can be commented
out or left stopped until then.

## Wazuh: manager only

The Wazuh indexer and dashboard are excluded. Agents are deployed separately on pipeline hosts
via group assignment. The manager handles agent communication (port 1514) and exposes a REST API
on port 55000 (localhost only).

## Suricata and Zeek: network_mode host

Packet capture requires `NET_ADMIN` and `NET_RAW` capabilities with access to the host network
interface. `network_mode: host` is the cleanest approach for sensor containers; the alternative
(bridge network with capabilities) adds complexity without meaningful isolation benefit for
sensors that are explicitly intended to see all traffic. These containers do not join
`pipeline-net`; log forwarding to Shuffle is a separate configuration step.

## Capability model

`cap_drop: ALL` on every service, with capabilities added back individually. `no-new-privileges:
true` on every service. `read_only: true` with tmpfs mounts where the image allows it (Redis,
Nginx, Tor, Certbot). Services that genuinely require write access to their filesystem (MISP,
MariaDB, Wazuh, OpenSearch, OpenCTI, Shuffle) are not run read-only.

## Port binding

Internal-only services (MISP web UI, Wazuh REST API, Shuffle frontend, OpenCTI platform) bind
to `127.0.0.1` on the host. Only externally intended ports (Wazuh agent listener on 1514,
Nginx on 80 and 443) bind to `0.0.0.0`. This is a defence-in-depth measure; firewall rules
should still restrict 1514 to authorised agent addresses.

## TLS certificates: Certbot with HTTP-01

Let's Encrypt via Certbot. The HTTP-01 challenge requires port 80 to be externally accessible,
which freed the former Tor listener from port 80. The Tor hidden service listener moved to port
8080 internally; `torrc` maps the hidden service port 80 to `nginx:8080`. A Certbot renewal
loop runs every 12 hours inside the container; Nginx requires a manual reload after renewal
(`docker compose exec nginx nginx -s reload`). `init-certs.sh` seeds a temporary self-signed
cert into the Certbot volume on first run so Nginx can start before a real certificate exists.

Alternatives considered: DNS-01 challenge (avoids exposing port 80 but requires DNS provider
API credentials and per-provider integration), self-signed only (not appropriate for a
public-facing disclosure endpoint).

## Control script

`up.sh`, `down.sh`, and `purge.sh` were consolidated into a single `ctl` script with subcommands
(`./ctl up`, `./ctl down`, `./ctl purge`). Three separate scripts with overlapping structure
offered no benefit over one entry point.

`./ctl down` preserves volumes by default. Volumes contain persistent operational data: the MISP
database, all analyst-created events, OpenCTI threat intelligence, Wazuh history, Shuffle
workflow definitions, Certbot certificates, and the Tor hidden service private key. A default
that destroyed this data on any stop would be operationally hazardous. `--volumes` is an
explicit flag requiring confirmation. `purge` is a separate subcommand requiring confirmation
and also removes locally built images.

## Image pinning

All images use explicit version tags rather than `:latest`. Digest pinning (immutable) is noted
as the production-grade step but not implemented in the compose files, as digest values change
on every image rebuild and are impractical to maintain in version control without tooling.
The compose file headers note where to verify current tags.

## Tor hidden service keys

Stored in the `tor-data` Docker named volume, not as a bind mount into the repository directory.
Named volumes are not accessible from the repository tree and require explicit Docker commands
to inspect or copy, reducing the risk of accidental exposure. The volume survives `./ctl down`
but is destroyed by `./ctl down --volumes` and `./ctl purge`. Both operations carry a prominent
warning about key loss.
