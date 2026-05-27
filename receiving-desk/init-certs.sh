#!/usr/bin/env bash
# Seeds a temporary self-signed certificate into the certbot-letsencrypt volume so
# Nginx can start before the real Let's Encrypt certificate exists.
# Run this once before starting the Receiving Desk for the first time.
#
# After Nginx is running, obtain the real certificate:
#   docker compose -f receiving-desk/compose.yml run --rm certbot \
#     certonly --webroot -w /var/www/certbot -d <domain.tld>
#
# Then reload Nginx:
#   docker compose -f receiving-desk/compose.yml exec nginx nginx -s reload
#
# Also update nginx/nginx.conf: replace YOURDOMAIN.TLD with your actual domain.

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain.tld>}"
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose.yml"

docker compose -f "$COMPOSE_FILE" run --rm \
  --entrypoint sh certbot -c "
    mkdir -p /etc/letsencrypt/live/$DOMAIN
    openssl req -x509 -newkey rsa:2048 \
      -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
      -out    /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
      -days 1 -nodes -subj '/CN=$DOMAIN' 2>/dev/null
    cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
       /etc/letsencrypt/live/$DOMAIN/chain.pem
    echo 'Temporary self-signed cert written for $DOMAIN (valid 1 day).'
  "
