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

Receiving Desk ──► Quiet Room │ Long Table │ Repair Shop
```

The Quiet Room filters, normalises, and classifies incoming signals. Classified material is
written to MISP; MISP stores it and routes it to the Long Table. The Long Table correlates,
interprets, and escalates. Wazuh supplies selective host telemetry; selection is a deployment
decision, not an analysis-time filter. Automation assists prioritisation. Adjudication remains
with analysts. Provenance records track acquisition path, not truth ancestry.

The Receiving Desk handles disclosure intake and routes each case to the appropriate division.
The Repair Shop handles devices that require physical access.

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
./ctl up             start the full pipeline
./ctl down           stop; volumes preserved
./ctl down --volumes stop; destroy all data (confirmation required)
./ctl purge          remove everything including built images
```

`misp/` starts first and creates `pipeline-net`. `shuffle/` and `long-table/` join it as
external and will not start without it.

Each division has an `env.example` showing available variables. `./ctl init` copies these to `.env` files and fills in generated secrets; manual copying is not needed.

The Receiving Desk requires a TLS certificate before Nginx starts. Run
`receiving-desk/init-certs.sh <domain>` to seed a temporary self-signed cert into the Certbot
volume, then obtain a real Let's Encrypt certificate once the stack is running.

## Usage

Credentials for all services are written to `.env` files by `./ctl init`. Read them there; nothing is printed to the terminal.

URLs below are for local testing. For a remote deployment, replace `127.0.0.1` with the server's hostname or IP throughout.

### MISP

Available at https://127.0.0.1:8443. The browser will warn about a self-signed certificate; accept it to proceed.

Log in with `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `misp/.env`. On first login MISP asks you to confirm the organisation name and change the password; work through those prompts before doing anything else.

The MISP connector in OpenCTI only imports MISP events tagged `Long-Table`, `tlp:white`, or `tlp:green`. Events without one of those tags do not cross to OpenCTI.

### OpenCTI (Long Table)

Available at http://127.0.0.1:8888.

Log in with `OPENCTI_ADMIN_EMAIL` and `OPENCTI_ADMIN_PASSWORD` from `long-table/.env`.

### Shuffle

Available at http://127.0.0.1:3001.

Shuffle has no pre-set admin account. On the first visit it prompts you to create one. Do that before attempting to use workflows.

### Wazuh

The Wazuh API runs at https://127.0.0.1:55000. It does not serve a browser interface and returns a 401 on direct access. It uses JWT authentication.

Get a token (replace `<API_PASSWORD>` with the value of `API_PASSWORD` from `quiet-room/.env`):

```
curl -k -u wazuh-wui:<API_PASSWORD> \
  -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"
```

The command prints a token string. Tokens expire after 15 minutes. Use it in subsequent requests:

```
curl -k -H "Authorization: Bearer <token>" https://127.0.0.1:55000/
```

Wazuh agents are installed separately on the hosts to be monitored. The manager listens on 1514/tcp and 1514/udp for agent connections.

### Quiet Room signal path

Suricata and Zeek write logs to named Docker volumes (`suricata-logs`, `zeek-logs`). Nothing reads those volumes at present. The pipeline diagram shows Quiet Room feeding MISP, but the log-forwarding step is not yet configured. Signal capture runs and logs accumulate, but no MISP events are generated from network traffic until a log forwarder (Filebeat or similar) is wired into those volumes.

Wazuh host telemetry follows a separate path and works once agents are enrolled.

### Receiving Desk

For local testing, `./ctl init` seeds a self-signed certificate; the Receiving Desk starts with that.

For production, obtain a real certificate once the stack is up and port 80 is reachable from the internet:

```
docker compose -f receiving-desk/compose.yml run --rm certbot \
  certonly --webroot -w /var/www/certbot -d yourdomain.tld
```

Then reload Nginx:

```
docker compose -f receiving-desk/compose.yml exec nginx nginx -s reload
```

Also replace `receiving-desk/nginx/security.txt` with real contact details and the correct encryption key fingerprint,
and update the domain in `receiving-desk/nginx/nginx.conf`. The Tor hidden service address is generated on first start
and stored in the `tor-data` volume. Back up the hostname and private key files from that volume; losing the private key
means losing the `.onion` address permanently.