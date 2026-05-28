#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

trap 'echo ""; echo "Interrupted. Any containers already started are still running. Use ./ctl down to stop them."; exit 130' INT

step() { echo ""; echo "==> $*"; }

usage() {
  echo "Usage: $0 <command> [options]"
  echo ""
  echo "Commands:"
  echo "  init             Generate secrets and prepare .env files for first run."
  echo "  up               Start the full pipeline in dependency order."
  echo "  down             Stop and remove containers and networks. Volumes are preserved."
  echo "  down --volumes   Also remove all data volumes (requires confirmation)."
  echo "  purge            Remove everything: containers, volumes, networks, and locally"
  echo "                   built images. Requires confirmation."
  echo "  wazuh-token [/path]  Acquire a Wazuh API JWT. With a path, make the full request."
}

# ── env file helpers ─────────────────────────────────────────────────────────

_stage_envs() {
  # Copy env.example → .env for any division missing a .env file.
  # Prints the paths of files created so the caller can clean them up.
  for dir in misp shuffle quiet-room long-table receiving-desk; do
    if [ ! -f "${REPO}/${dir}/.env" ] && [ -f "${REPO}/${dir}/env.example" ]; then
      cp "${REPO}/${dir}/env.example" "${REPO}/${dir}/.env"
      echo "${REPO}/${dir}/.env"
    fi
  done
}

_unstage_envs() {
  # Remove the temporary .env files created by _stage_envs.
  local f
  for f in "$@"; do rm -f "$f"; done
}

_env_get() {
  # _env_get KEY FILE  →  prints current value (empty string if unset)
  grep -E "^${1}=" "${2}" 2>/dev/null | cut -d= -f2-
}

_env_set() {
  # _env_set KEY VALUE FILE  →  updates existing line or appends
  if grep -qE "^${1}=" "${3}" 2>/dev/null; then
    sed -i "s|^${1}=.*|${1}=${2}|" "${3}"
  else
    printf '%s=%s\n' "${1}" "${2}" >> "${3}"
  fi
}

_env_del() {
  # _env_del KEY FILE  →  removes the line entirely
  sed -i "/^${1}=/d" "${2}"
}

_is_placeholder() {
  # Returns 0 (true) if the value has not been set to something real.
  case "${1}" in
    changeme-*|""|"00000000-0000-0000-0000-"*) return 0 ;;
    *) return 1 ;;
  esac
}

_fill() {
  # _fill KEY VALUE FILE  →  sets KEY=VALUE only if current value is a placeholder
  local cur
  cur=$(_env_get "${1}" "${3}")
  if _is_placeholder "${cur}"; then
    _env_set "${1}" "${2}" "${3}"
    printf '    %-36s %s\n' "${1}" "${3#"$REPO"/}"
  fi
}

_rename() {
  # _rename OLD NEW FILE  →  renames a variable, preserving its value
  # No-op if OLD does not exist; no-op if NEW is already present.
  if grep -qE "^${1}=" "${3}" 2>/dev/null; then
    local val
    val=$(_env_get "${1}" "${3}")
    _env_del "${1}" "${3}"
    if ! grep -qE "^${2}=" "${3}" 2>/dev/null; then
      printf '%s=%s\n' "${2}" "${val}" >> "${3}"
    fi
    printf '    renamed %-28s -> %s  (%s)\n' "${1}" "${2}" "${3#"$REPO"/}"
  fi
}

# ── commands ─────────────────────────────────────────────────────────────────

cmd_init() {
  # Copy env.examples to .env files if they do not exist yet.
  step "Copying templates"
  local copied=0
  for dir in misp shuffle quiet-room long-table receiving-desk; do
    if [ ! -f "${REPO}/${dir}/.env" ]; then
      cp "${REPO}/${dir}/env.example" "${REPO}/${dir}/.env"
      echo "    created ${dir}/.env"
      copied=1
    else
      echo "    exists  ${dir}/.env"
    fi
  done

  # Migrate any variables that were renamed between versions.
  step "Migrating renamed variables"
  _rename MISP_ADMIN_EMAIL     ADMIN_EMAIL     "${REPO}/misp/.env"
  _rename MISP_ADMIN_PASSPHRASE ADMIN_PASSWORD "${REPO}/misp/.env"
  _rename MISP_ORG             ADMIN_ORG       "${REPO}/misp/.env"
  _rename MISP_BASEURL         BASE_URL        "${REPO}/misp/.env"
  _rename WAZUH_API_USER       API_USERNAME    "${REPO}/quiet-room/.env"
  _rename WAZUH_API_PASSWORD   API_PASSWORD    "${REPO}/quiet-room/.env"
  echo "    done"

  # Generate secrets for any remaining placeholder values.
  step "Generating secrets"

  # misp
  _fill MYSQL_PASSWORD       "$(openssl rand -hex 24)" "${REPO}/misp/.env"
  _fill MYSQL_ROOT_PASSWORD  "$(openssl rand -hex 24)" "${REPO}/misp/.env"
  _fill REDIS_PASSWORD       "$(openssl rand -hex 24)" "${REPO}/misp/.env"
  _fill ADMIN_PASSWORD       "$(openssl rand -hex 16)" "${REPO}/misp/.env"
  _fill GPG_PASSPHRASE       "$(openssl rand -hex 16)" "${REPO}/misp/.env"

  # ADMIN_KEY / MISP_API_KEY are generated together and kept in sync.
  # MISP requires exactly 40 alphanumeric characters.
  local misp_key
  misp_key=$(_env_get ADMIN_KEY "${REPO}/misp/.env")
  if _is_placeholder "${misp_key}"; then
    misp_key="$(openssl rand -base64 40 | tr -dc 'a-zA-Z0-9' | head -c 40)"
    _env_set ADMIN_KEY "${misp_key}" "${REPO}/misp/.env"
    printf '    %-36s %s\n' ADMIN_KEY "misp/.env"
  fi
  _env_set MISP_API_KEY "${misp_key}" "${REPO}/long-table/.env"
  printf '    %-36s %s (synced from ADMIN_KEY)\n' MISP_API_KEY "long-table/.env"
  _env_set MISP_API_KEY "${misp_key}" "${REPO}/quiet-room/.env"
  printf '    %-36s %s (synced from ADMIN_KEY)\n' MISP_API_KEY "quiet-room/.env"

  # If MISP is already running with an existing database, apply the key directly.
  # configure_misp.sh only runs on first database initialisation, not on subsequent starts.
  if docker inspect misp-misp-1 > /dev/null 2>&1; then
    echo "    MISP container running — applying ADMIN_KEY to existing database"
    docker exec misp-misp-1 sudo -u www-data \
      /var/www/MISP/app/Console/cake User change_authkey 1 "${misp_key}" 2>&1 \
      | grep -v "audit message" | sed 's/^/    /'
  fi

  # shuffle
  _fill SHUFFLE_BACKEND_APIKEY "$(openssl rand -hex 24)" "${REPO}/shuffle/.env"

  # quiet-room — Wazuh requires uppercase, lowercase, digit, and special character
  _fill API_PASSWORD "$(openssl rand -base64 20 | tr -dc 'a-zA-Z0-9' | head -c 20)Zz1!" "${REPO}/quiet-room/.env"

  # long-table
  _fill OPENCTI_ADMIN_PASSWORD "$(openssl rand -hex 24)" "${REPO}/long-table/.env"
  _fill OPENCTI_ADMIN_TOKEN    "$(uuidgen | tr '[:upper:]' '[:lower:]')" "${REPO}/long-table/.env"
  _fill CONNECTOR_MISP_ID      "$(uuidgen | tr '[:upper:]' '[:lower:]')" "${REPO}/long-table/.env"
  _fill OPENCTI_REDIS_PASSWORD "$(openssl rand -hex 24)" "${REPO}/long-table/.env"
  _fill MINIO_ROOT_PASSWORD    "$(openssl rand -hex 24)" "${REPO}/long-table/.env"
  _fill RABBITMQ_PASSWORD      "$(openssl rand -hex 24)" "${REPO}/long-table/.env"

  # quiet-room MISP classifier defaults
  _fill MISP_URL       "https://misp:443" "${REPO}/quiet-room/.env"
  _fill MISP_VERIFYCERT "false"           "${REPO}/quiet-room/.env"

  # receiving-desk
  _fill DOMAIN bootstrap.invalid "${REPO}/receiving-desk/.env"

  # Remaining items that require human decisions.
  step "Action required"

  local iface
  iface=$(_env_get SENSOR_INTERFACE "${REPO}/quiet-room/.env")
  if [ -z "${iface}" ]; then
    echo "  Available interfaces:"
    ip -o link show | awk -F': ' '{print "    " $2}'
    if [ -t 0 ]; then
      read -r -p "  Enter SENSOR_INTERFACE: " iface
      if [ -n "${iface}" ]; then
        _env_set SENSOR_INTERFACE "${iface}" "${REPO}/quiet-room/.env"
        echo "  SENSOR_INTERFACE=${iface}  (written to quiet-room/.env)"
      else
        echo "  Skipped. Set SENSOR_INTERFACE in quiet-room/.env before running ./ctl up."
      fi
    else
      echo "  Set SENSOR_INTERFACE in quiet-room/.env (interface carrying monitored traffic)."
    fi
  else
    echo "  SENSOR_INTERFACE=${iface}"
  fi

  # Seed the Receiving Desk TLS certificate if the volume is empty.
  step "Receiving Desk TLS"
  local rd_domain cert_exists
  rd_domain=$(_env_get DOMAIN "${REPO}/receiving-desk/.env")
  rd_domain="${rd_domain:-bootstrap.invalid}"
  # The volume is declared external in compose.yml and must exist before any compose command.
  docker volume create certbot-letsencrypt > /dev/null
  cert_exists=$(docker run --rm \
    -v certbot-letsencrypt:/etc/letsencrypt \
    alpine test -f /etc/letsencrypt/live/${rd_domain}/fullchain.pem && echo yes || echo no)
  if [ "$cert_exists" = "no" ]; then
    bash "${REPO}/receiving-desk/init-certs.sh" "${rd_domain}"
  else
    echo "    certificate already present for ${rd_domain}"
  fi

  echo ""
  echo "  URL defaults are set for local testing. For production, update:"
  echo "    BASE_URL in misp/.env"
  echo "    OPENCTI_BASE_URL and MISP_BASEURL in long-table/.env"
  echo ""
  echo "Secrets written. Run ./ctl up when ready."
}

cmd_up() {
  # misp/ must be first: it creates pipeline-net, which all other compose files
  # reference as external. shuffle/ and long-table/ will fail to start if it is absent.
  step "MISP (creates pipeline-net)"
  docker compose -f "$REPO/misp/compose.yml" up -d --wait

  local misp_key
  misp_key=$(_env_get ADMIN_KEY "${REPO}/misp/.env")
  if [ -n "$misp_key" ]; then
    local attempt=0
    printf "    Applying ADMIN_KEY"
    while [ $attempt -lt 30 ]; do
      result=$(docker exec misp-misp-1 sudo -u www-data \
        /var/www/MISP/app/Console/cake User change_authkey 1 "${misp_key}" 2>&1) || true
      if echo "$result" | grep -qiE "not found|error"; then
        attempt=$((attempt + 1))
        printf "."
        sleep 10
      else
        echo " done"
        echo "$result" | grep -v "audit message" | sed 's/^/    /'
        break
      fi
    done
  fi

  step "Shuffle"
  docker compose -f "$REPO/shuffle/compose.yml" up -d --wait

  step "Quiet Room"
  local sensor_iface
  sensor_iface=$(grep -E '^SENSOR_INTERFACE=' "$REPO/quiet-room/.env" 2>/dev/null | cut -d= -f2)
  if [ -z "$sensor_iface" ]; then
    echo "ERROR: SENSOR_INTERFACE is not set in quiet-room/.env."
    echo "Run 'ip link show' to list interfaces, then set SENSOR_INTERFACE in quiet-room/.env."
    exit 1
  fi
  if ! ip link show "$sensor_iface" > /dev/null 2>&1; then
    echo "ERROR: Interface '${sensor_iface}' not found on this host."
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  " $2}'
    exit 1
  fi
  docker compose -f "$REPO/quiet-room/compose.yml" up -d --wait

  step "Long Table"
  local misp_key lt_profile=""
  misp_key=$(grep -E '^MISP_API_KEY=' "$REPO/long-table/.env" 2>/dev/null | cut -d= -f2)
  if [ -n "$misp_key" ] && [ "$misp_key" != "changeme-misp-api-key" ]; then
    lt_profile="--profile misp"
  else
    echo "  MISP_API_KEY not configured; MISP connector will not start."
    echo "  Run ./ctl init to set it, then re-run ./ctl up."
  fi
  docker compose -f "$REPO/long-table/compose.yml" $lt_profile up -d --wait

  step "Receiving Desk"
  docker compose -f "$REPO/receiving-desk/compose.yml" up -d --wait

  echo ""
  echo "Pipeline is up."
  echo ""
  echo "  MISP       https://127.0.0.1:8443"
  echo "  Shuffle    http://127.0.0.1:3001"
  echo "  OpenCTI    http://127.0.0.1:8888"
  echo "  Wazuh API  https://127.0.0.1:55000  (JWT only — use ./ctl wazuh-token)"
}


cmd_down() {
  local volumes=false

  for arg in "$@"; do
    case $arg in
      --volumes) volumes=true ;;
      *) echo "Unknown option: $arg"; usage; exit 1 ;;
    esac
  done

  local flags="--remove-orphans"

  if [ "$volumes" = true ]; then
    echo ""
    echo "WARNING: --volumes will permanently destroy all data volumes, including the Tor"
    echo "hidden service private key. Loss of that key means loss of the .onion address."
    echo ""
    echo "NOTE: certbot-letsencrypt is declared external and survives this command."
    echo "To remove it as well: docker volume rm certbot-letsencrypt"
    echo ""
    read -r -p "Type YES to continue: " confirm
    [ "$confirm" = "YES" ] || { echo "Aborted."; exit 1; }
    flags="$flags --volumes"
  fi

  local -a _staged
  mapfile -t _staged < <(_stage_envs)

  step "Receiving Desk"
  docker compose -f "$REPO/receiving-desk/compose.yml" down $flags

  step "Long Table"
  docker compose -f "$REPO/long-table/compose.yml" --profile misp down $flags

  step "Quiet Room"
  docker compose -f "$REPO/quiet-room/compose.yml" down $flags

  step "Shuffle"
  docker compose -f "$REPO/shuffle/compose.yml" down $flags

  step "MISP"
  docker compose -f "$REPO/misp/compose.yml" down $flags

  _unstage_envs "${_staged[@]+"${_staged[@]}"}"

  echo ""
  echo "Pipeline is down."
}

cmd_purge() {
  echo "This will permanently destroy all pipeline data, including the Tor hidden service"
  echo "private key. Back up the tor-data volume before continuing if you need to preserve"
  echo "the .onion address."
  echo ""
  read -r -p "Type YES to continue: " confirm
  [ "$confirm" = "YES" ] || { echo "Aborted."; exit 1; }

  local -a _staged
  mapfile -t _staged < <(_stage_envs)

  step "Receiving Desk"
  docker compose -f "$REPO/receiving-desk/compose.yml" down --volumes --remove-orphans --rmi local

  step "Long Table"
  docker compose -f "$REPO/long-table/compose.yml" --profile misp down --volumes --remove-orphans

  step "Quiet Room"
  docker compose -f "$REPO/quiet-room/compose.yml" down --volumes --remove-orphans

  step "Shuffle"
  docker compose -f "$REPO/shuffle/compose.yml" down --volumes --remove-orphans

  step "MISP"
  docker compose -f "$REPO/misp/compose.yml" down --volumes --remove-orphans

  _unstage_envs "${_staged[@]+"${_staged[@]}"}"

  step "External volumes"
  docker volume rm certbot-letsencrypt 2>/dev/null && echo "    removed certbot-letsencrypt" \
    || echo "    certbot-letsencrypt not present (already removed or never created)"

  step "Docker housekeeping"
  docker system prune -f

  echo ""
  echo "All containers, volumes, networks, locally built images, and build cache removed."
  echo "To also remove pulled images: docker image prune -a"
}

cmd_wazuh_token() {
  local pass token path="${1:-}"
  pass=$(_env_get API_PASSWORD "${REPO}/quiet-room/.env")
  if [ -z "$pass" ]; then
    echo "API_PASSWORD not found in quiet-room/.env. Run ./ctl init first."
    exit 1
  fi
  token=$(curl -sk -u "wazuh-wui:${pass}" \
    -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")
  if [ -z "$path" ]; then
    echo "$token"
  else
    curl -sk -H "Authorization: Bearer ${token}" "https://127.0.0.1:55000${path}"
    echo ""
  fi
}

case "${1:-}" in
  init)         shift; cmd_init         "$@" ;;
  up)           shift; cmd_up           "$@" ;;
  down)         shift; cmd_down         "$@" ;;
  purge)        shift; cmd_purge        "$@" ;;
  wazuh-token)  shift; cmd_wazuh_token  "$@" ;;
  *)            usage; exit 1 ;;
esac
