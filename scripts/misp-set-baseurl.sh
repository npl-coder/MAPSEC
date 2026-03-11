#!/usr/bin/env bash
# Set MISP base URL so the UI and feed fetch use the correct domain (not localhost).
# Run once after changing MISP_BASEURL, or if feed fetch requests go to https://localhost/...
# Usage: ./scripts/misp-set-baseurl.sh [baseurl]
# Example: ./scripts/misp-set-baseurl.sh https://misp.local

set -e
BASEURL="${1:-https://misp.local}"
COMPOSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$COMPOSE_DIR"
echo "Setting MISP baseurl to: $BASEURL"
docker compose exec misp sudo -u www-data /var/www/MISP/app/Console/cake Baseurl "$BASEURL"
docker compose exec misp sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting external_baseurl "$BASEURL"
echo "Done. Reload MISP in the browser (or hard refresh); feed fetch should now use $BASEURL"
