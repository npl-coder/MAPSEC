#!/usr/bin/env bash
# Count and list MISP events using the nginx vhost URL (https://misp.local).
# Requires misp.local in /etc/hosts, nginx + main stack running, and MISP_API_KEY.
#
# Usage:
#   MISP_API_KEY=your_key ./scripts/list-misp-events.sh       # list 10 events
#   MISP_API_KEY=your_key ./scripts/list-misp-events.sh 25   # list 25 events
#
# Optional: MISP_URL=https://misp.local (default)

set -e
MISP_URL="${MISP_URL:-https://misp.local}"
LIMIT="${1:-10}"

if [[ -z "${MISP_API_KEY:-}" ]]; then
  echo "Error: MISP_API_KEY is not set. Get your key from MISP: Admin → My Profile → Auth Keys" >&2
  exit 1
fi

echo "=== MISP events (last $LIMIT) ==="
RESP=$(curl -sk -X GET "${MISP_URL}/events/index/limit:${LIMIT}" \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Accept: application/json")

if ! echo "$RESP" | jq -e . >/dev/null 2>&1; then
  echo "Error: Invalid JSON response. Check MISP_URL and MISP_API_KEY." >&2
  echo "$RESP" | head -5
  exit 1
fi

# Handle array or object with .response
EVENTS=$(echo "$RESP" | jq 'if type == "array" then . elif .response != null then .response else . end')
if ! echo "$EVENTS" | jq -e 'type == "array"' >/dev/null 2>&1; then
  echo "Unexpected response format:"
  echo "$RESP" | jq .
  exit 1
fi
COUNT=$(echo "$EVENTS" | jq 'length')
echo "Total returned: $COUNT events"
echo ""
echo "=== Event list (id, date, info) ==="
echo "$EVENTS" | jq -r '.[] | "\(.id)\t\(.date)\t\(.info // "n/a")"' 2>/dev/null || echo "$EVENTS" | jq .
echo ""
echo "=== Full JSON (first 3 events) ==="
echo "$EVENTS" | jq '.[0:3]'
