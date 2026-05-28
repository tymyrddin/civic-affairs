# Civic affairs

Signal intake, threat correlation, hardware analysis, and coordinated disclosure intake for the
Civic Defence Establishment.

Four operational divisions with distinct data domains and tool stacks. Divisional boundaries
reflect [organisational structure](docs/divisions.md), not data flow; this repository covers the full pipeline.

## Pipeline

```
Suricata ──┐
Zeek       ├──► Quiet Room ──► MISP (reliability 3+) ──► Long Table ──► Assessment
Wazuh      ┘    filter           store, route              correlate
                normalise                                   interpret
                classify                                    escalate

Receiving Desk (static)    ──► Quiet Room │ Long Table │ Repair Shop
GlobaLeaks     (intake)    ──► operator review ──► manual routing
```

The Quiet Room filters, normalises, and classifies incoming signals. Classified material is
written to MISP; MISP stores it and routes it to the Long Table. The Long Table correlates,
interprets, and escalates. Wazuh supplies selective host telemetry; selection is a deployment
decision, not an analysis-time filter. Automation assists prioritisation. Adjudication remains
with analysts. Provenance records track acquisition path, not truth ancestry.

The Receiving Desk serves static discovery material (security.txt, PGP key) over clearnet and a
static onion. GlobaLeaks provides the anonymous submission form on a separate onion, with ClamAV
scanning and metadata stripping built in. Routing from GlobaLeaks to the appropriate division is
manual. The Repair Shop handles devices that require physical access.

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
MISP container reports healthy.

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

The classifier service tails Suricata's EVE JSON log and creates a MISP event for each IDS alert (`event_type: alert`).
Alerts are tagged `Quiet-Room` and `tlp:white`; the `tlp:white` tag means the OpenCTI connector picks them up
automatically. Repeated alerts from the same (signature, source IP, destination IP) tuple within a 5-minute window
produce one event, not a flood.

Zeek logs accumulate in the `zeek-logs` volume for direct analyst access. Zeek does not generate MISP events
automatically.

Wazuh host telemetry follows a separate path and works once agents are enrolled.

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