#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step() { echo ""; echo "==> $*"; }

usage() {
  echo "Usage: $0 <command> [options]"
  echo ""
  echo "Commands:"
  echo "  up               Start the full pipeline in dependency order."
  echo "  down             Stop and remove containers and networks. Volumes are preserved."
  echo "  down --volumes   Also remove all data volumes (requires confirmation)."
  echo "  purge            Remove everything: containers, volumes, networks, and locally"
  echo "                   built images. Requires confirmation."
}

cmd_up() {
  # misp/ must be first: it creates pipeline-net, which all other compose files
  # reference as external. shuffle/ and long-table/ will fail to start if it is absent.
  step "MISP (creates pipeline-net)"
  docker compose -f "$REPO/misp/compose.yml" up -d --wait

  step "Shuffle"
  docker compose -f "$REPO/shuffle/compose.yml" up -d --wait

  step "Quiet Room"
  docker compose -f "$REPO/quiet-room/compose.yml" up -d --wait

  step "Long Table"
  docker compose -f "$REPO/long-table/compose.yml" up -d --wait

  step "Receiving Desk"
  docker compose -f "$REPO/receiving-desk/compose.yml" up -d --wait

  echo ""
  echo "Pipeline is up."
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
    read -r -p "Type YES to continue: " confirm
    [ "$confirm" = "YES" ] || { echo "Aborted."; exit 1; }
    flags="$flags --volumes"
  fi

  step "Receiving Desk"
  docker compose -f "$REPO/receiving-desk/compose.yml" down $flags

  step "Long Table"
  docker compose -f "$REPO/long-table/compose.yml" down $flags

  step "Quiet Room"
  docker compose -f "$REPO/quiet-room/compose.yml" down $flags

  step "Shuffle"
  docker compose -f "$REPO/shuffle/compose.yml" down $flags

  step "MISP"
  docker compose -f "$REPO/misp/compose.yml" down $flags

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

  step "Receiving Desk"
  docker compose -f "$REPO/receiving-desk/compose.yml" down --volumes --remove-orphans --rmi local

  step "Long Table"
  docker compose -f "$REPO/long-table/compose.yml" down --volumes --remove-orphans

  step "Quiet Room"
  docker compose -f "$REPO/quiet-room/compose.yml" down --volumes --remove-orphans

  step "Shuffle"
  docker compose -f "$REPO/shuffle/compose.yml" down --volumes --remove-orphans

  step "MISP"
  docker compose -f "$REPO/misp/compose.yml" down --volumes --remove-orphans

  echo ""
  echo "All containers, volumes, networks, and locally built images removed."
  echo "To also remove pulled images: docker image prune -a"
}

case "${1:-}" in
  up)    shift; cmd_up    "$@" ;;
  down)  shift; cmd_down  "$@" ;;
  purge) shift; cmd_purge "$@" ;;
  *)     usage; exit 1 ;;
esac
