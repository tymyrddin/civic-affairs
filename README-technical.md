# Civic affairs: operational manual

How to stand up the Civic Defence Establishment toolchain and how a signal moves through it. For
what the Establishment is and why it is shaped this way, see [README.md](README.md).

Three operational divisions with distinct data domains and tool stacks. Divisional boundaries
reflect [organisational structure](docs/divisions.md), not data flow; this repository covers the
full pipeline.

## Pipeline

```
Suricata ──┐
Zeek       ├──► Quiet Room ──► MISP ──► Long Table ──► Assessment
Wazuh      ┘    characterise    store, route   correlate
                correlate                       interpret
                hold or route                   escalate

Receiving Desk (static)    ──► Quiet Room │ Long Table
GlobaLeaks     (intake)    ──► operator review ──► manual routing
```

The Quiet Room characterises and classifies incoming signals. Every sensor signal becomes a MISP
event; signals that a second sensor corroborates on shared infrastructure are held for analyst
review before they route. MISP stores the events and the OpenCTI connector carries the routed ones
to the Long Table, which correlates, interprets, and escalates. Wazuh supplies selective host
telemetry; selection is a deployment decision, not an analysis-time filter. Automation assists
prioritisation. Adjudication remains with analysts. Provenance records track acquisition path, not
truth ancestry.

The Receiving Desk serves static discovery material (security.txt, PGP key) over clearnet and a
static onion. GlobaLeaks provides the anonymous submission form on a separate onion, with ClamAV
scanning and metadata stripping built in. Routing from GlobaLeaks to the appropriate division is
manual.

## Requirements

- Docker Engine 24 or later with the Compose plugin (v2). The `docker compose` command, not legacy `docker-compose`.
- Linux host. Suricata and Zeek use `network_mode: host` for packet capture and do not work on macOS or Windows Docker
  Desktop without reworking those services.
- 16 GB RAM available to Docker is a comfortable baseline. OpenSearch runs two separate instances (Shuffle and OpenCTI),
  alongside MISP and Wazuh, each holding significant heap.
- A monitored network interface. Run `ip link show` to identify it; the Quiet Room startup check will list available
  interfaces if the value in `quiet-room/.env` is missing or wrong.
- For the Receiving Desk: a public domain name with port 80 reachable from the internet for Let's Encrypt HTTP-01
  challenge validation.

## Quickstart

Generate secrets and prepare the environment:

```
./ctl init
```

Open `quiet-room/.env` and set the monitored network interface:

```
SENSOR_INTERFACE=enp34s0
```

`./ctl init` lists available interfaces if the value is missing. Use the interface carrying the traffic to monitor.

Bring the pipeline up:

```
./ctl up
```

On first boot, MISP generates DH parameters and imports the database schema. Allow three to five minutes before the
MISP container reports healthy. `./ctl up` rebuilds the Quiet Room classifier image, so a change to `classifier.py`
reaches the running container on the next `up`.

## Infrastructure

Per-division Docker Compose files. One control script.

```
./ctl init           generate secrets and prepare .env files
./ctl up             start the full pipeline
./ctl down           stop; volumes preserved
./ctl down --volumes stop; destroy all data (confirmation required)
./ctl purge          remove everything including built images
./ctl wazuh-token [/path]  acquire a Wazuh API JWT; with a path, make the request
./clean-env          remove all .env files to start from scratch
```

`misp/` starts first and creates `pipeline-net`. `shuffle/` and `long-table/` join it as
external and will not start without it. `receiving-desk/globaleaks/` runs on its own isolated
bridge network and starts independently.

Each division has an `env.example` showing available variables. `./ctl init` copies these to `.env` files, fills in
generated secrets, and seeds a bootstrap TLS certificate for the Receiving Desk. Manual copying is not needed.

## Usage

Credentials for all services are written to `.env` files by `./ctl init`. Read them there; nothing is printed to the
terminal.

URLs below are for local testing. For a remote deployment, replace `127.0.0.1` with the server's hostname or IP
throughout.

### MISP

Available at https://127.0.0.1:8443. The browser will warn about a self-signed certificate; accept it to proceed.

Log in with `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `misp/.env`. On first login MISP asks you to confirm the
organisation name and change the password; work through those prompts before doing anything else.

The MISP connector in OpenCTI only imports MISP events tagged `Long-Table`, `tlp:white`, or `tlp:green`. Events without
one of those tags do not cross to OpenCTI.

### OpenCTI (Long Table)

Available at http://127.0.0.1:8888.

Log in with `OPENCTI_ADMIN_EMAIL` and `OPENCTI_ADMIN_PASSWORD` from `long-table/.env`.

### Shuffle

Available at http://127.0.0.1:3001.

Shuffle has no pre-set admin account. On the first visit it prompts you to create one. Do that before attempting to use
workflows.

### Wazuh

The Wazuh API runs at https://127.0.0.1:55000. It does not serve a browser interface. It uses JWT authentication.

Make an authenticated request directly:

```
./ctl wazuh-token /agents
```

Or acquire a token for use in your own requests:

```
./ctl wazuh-token
```

Tokens expire after 15 minutes. Wazuh agents are installed separately on the hosts to be monitored. The manager listens
on 1514/tcp and 1514/udp for agent connections.

### Quiet Room signal path

The classifier service tails Suricata's EVE JSON alerts and the Zeek logs named in `ZEEK_LOGS` (default `dns.log`), and
turns each sensor signal into a MISP event.

Every signal becomes a floor event tagged `Quiet-Room`, `tlp:white`, and `reliability="2"`. The `tlp:white` tag is what
the OpenCTI connector imports, so floor events reach the Long Table on their own standing. Repeated identical signals
from the same source within a five-minute window collapse into a single event rather than a flood.

When a signal shares a host with a recent signal from the other sensor within the correlation window
(`QR_CORRELATION_WINDOW`, default 600 seconds), the classifier posts a second, correlated event at `reliability="3"`,
tagged `tlp:amber` and `needs-review`. Two independent sensors on the same infrastructure clear a bar that neither
clears alone. This correlated event is held rather than routed: an analyst promotes it by adding the `Long-Table` tag.

The classifier does not ingest third-party feeds. A feed claim that fails validation is written to the drop log
(`/state/drops.log`, retained ninety days), not turned into an event.

On startup the classifier begins tailing each log at its current end, so a restart does not replay history. A log that
appears later is read from the start. The Zeek logs also accumulate in the `zeek-logs` volume for direct analyst access.

Wazuh host telemetry follows a separate path and is not yet wired into the classifier; it works once agents are
enrolled.

### Walkthrough simulation

`sim/walkthrough.sh` drives the documented LT-2026-0007 case end to end against a running stack, so the case tables
emerge from the live build rather than being asserted on paper. It seeds the Receiving Desk findings and the Society
notification into MISP, injects the Suricata and Zeek alerts the classifier turns into QR-2026-0032 and QR-2026-0033,
plays the analyst gate that routes the held correlation, records the dropped feed claim, and checks that the shared
observables cross into OpenCTI. It then assembles the consolidated LT-2026-0007 assessment in OpenCTI as a Case-Incident
linking the vulnerability, the observables, and the four contributing reports.

Run it after `./ctl up`:

```
./sim/walkthrough.sh              run the case and verify convergence in OpenCTI
./sim/walkthrough.sh --no-verify  run the case, skip the OpenCTI check
./sim/walkthrough.sh --clean      remove the simulation's MISP events, drop-log line, and OpenCTI objects
```

Set `PAUSE_AT_HOLD=1` to pause before the analyst gate, leaving QR-2026-0033 in its held `needs-review` state for
inspection; create `/tmp/sim-hold-continue` to resume.

### Receiving Desk

`./ctl init` sets `DOMAIN=bootstrap.invalid` in `receiving-desk/.env` and seeds a 1-day self-signed certificate under
that name. The `.invalid` TLD is reserved and non-resolvable; the cert is clearly transitional and expires quickly.

For production:

1. Set `DOMAIN=yourdomain.tld` in `receiving-desk/.env`.
2. Obtain a real Let's Encrypt certificate once the stack is up and port 80 is reachable from the internet:

```
docker compose -f receiving-desk/compose.yml run --rm certbot \
  certonly --webroot -w /var/www/certbot -d yourdomain.tld
```

3. Restart nginx to pick up the new cert path:

```
docker compose -f receiving-desk/compose.yml up -d nginx
```

Also replace `receiving-desk/nginx/security.txt` with real contact details and the correct encryption key fingerprint,
and replace `receiving-desk/nginx/pgp-key.asc` with the actual public key. The Tor hidden service address is generated
on first start and stored in the `tor-data` volume. Back up the hostname and private key files from that volume; losing
the private key means losing the `.onion` address permanently.

### GlobaLeaks

Available at https://127.0.0.1:8082. The browser will warn about a self-signed certificate; accept it to proceed.

The first visit runs the setup wizard, which configures the node name, administrator account, and notification
settings. Submissions are not available until the wizard completes.

GlobaLeaks manages its own Tor hidden service internally. The `.onion` address appears in the admin panel once setup
is complete. The private key lives in the `globaleaks_globaleaks-data` volume; backing it up is worth doing once the address has
been published, for the same reason as the Receiving Desk's Tor key.

Routing from GlobaLeaks to the appropriate division is manual. Submissions appear in the operator interface at
https://127.0.0.1:8082; the analyst reviews and routes each one.

## Production gaps

The pipeline runs end-to-end locally after `./ctl init` and `./ctl up`. The following are not yet configured and are
worth addressing before a production deployment.

- Receiving Desk: set `DOMAIN=yourdomain.tld` in `receiving-desk/.env` before deploying, then follow the cert
  acquisition steps in the Receiving Desk section above. Replace `security.txt` with real contact details and a PGP
  fingerprint, and replace `pgp-key.asc` with the actual public key.

- Base URLs: `BASE_URL` in `misp/.env` and `OPENCTI_BASE_URL` and `MISP_BASEURL` in `long-table/.env` default to
  `127.0.0.1`. Update to the server's actual hostname; links and redirects in both tools derive from these values.

- Admin account details: `ADMIN_EMAIL` in `misp/.env` and `OPENCTI_ADMIN_EMAIL` in `long-table/.env` default to
  `admin@example.internal`. Change to real addresses before going live.

- Wazuh agents: no agents are enrolled. The Wazuh agent needs to be installed on each host to be monitored and pointed
  at the manager on port 1514.

- Shuffle OpenSearch: the security plugin is disabled (`DISABLE_SECURITY_PLUGIN: "true"`). OpenSearch sits on an
  internal Docker network and is not reachable from outside, but enabling the security plugin and TLS is worth doing for
  a hardened deployment.

- Tor hidden service key: Tor generates a unique `.onion` address the first time the `tor` container starts. Read it
  with:

  ```
  docker exec receiving-desk-tor-1 cat /var/lib/tor/hidden_service/hostname
  ```

  The private key lives in the `tor-data` Docker volume alongside that hostname file. Back up both files to offline
  storage once the address has been published, in `security.txt`, on the organisation's website, or anywhere else.
  Losing the key after publication means the published address stops working and every reference to it needs updating.

- GlobaLeaks setup: the setup wizard runs on first visit to https://127.0.0.1:8082. It sets the node name, admin
  credentials, and notification settings; the platform is not operational until it completes.

- GlobaLeaks .onion key: GlobaLeaks manages its own Tor hidden service in the `globaleaks_globaleaks-data` volume. The `.onion`
  address appears in the admin panel once setup is complete. The private key from that volume is worth backing up
  before publishing the address anywhere; losing it means the published address stops working.

- Firewall: Wazuh agent ports (1514/tcp and 1514/udp) are bound to `0.0.0.0`; all other service ports bind to
  `127.0.0.1`. Restrict inbound access at the host firewall to match what actually needs to be reachable from outside.

- Volume backups: no off-host backup is configured for the named Docker volumes holding live data (MISP database,
  OpenCTI store, Wazuh state). A fresh `./ctl up` does not restore them.

- External volumes: `certbot-letsencrypt` and `globaleaks_globaleaks-data` are declared external and survive
  `./ctl down --volumes`. `./ctl purge` removes both. To remove them by hand:
  `docker volume rm certbot-letsencrypt globaleaks_globaleaks-data`.

## Licence

[Unlicence](LICENCE)
