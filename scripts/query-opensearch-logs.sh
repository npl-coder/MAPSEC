#!/usr/bin/env bash
# Query OpenSearch for logs using the nginx vhost URL (https://opensearch.local).
# Requires opensearch.local in /etc/hosts and nginx + main stack running.
#
# Usage:
#   ./scripts/query-opensearch-logs.sh                    # list indices
#   ./scripts/query-opensearch-logs.sh INDEX               # search index (match_all, 10 hits)
#   ./scripts/query-opensearch-logs.sh INDEX '{"query":...}'  # custom query
#
# Examples:
#   ./scripts/query-opensearch-logs.sh
#   ./scripts/query-opensearch-logs.sh linux-security-logs
#   ./scripts/query-opensearch-logs.sh linux-security-logs '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}'

set -e
OPENSEARCH_URL="${OPENSEARCH_URL:-https://opensearch.local}"
INDEX="${1:-}"
CUSTOM_QUERY="${2:-}"

if [[ -z "$INDEX" ]]; then
  echo "=== Indices ==="
  curl -sk "${OPENSEARCH_URL}/_cat/indices?v"
  echo ""
  echo "=== Cluster health ==="
  curl -sk "${OPENSEARCH_URL}/_cluster/health?pretty"
  exit 0
fi

if [[ -n "$CUSTOM_QUERY" ]]; then
  BODY="$CUSTOM_QUERY"
else
  BODY='{"size":10,"query":{"match_all":{}},"sort":[{"@timestamp":{"order":"desc"}}]}'
fi

echo "=== Search: $INDEX ==="
curl -sk -X GET "${OPENSEARCH_URL}/${INDEX}/_search" \
  -H 'Content-Type: application/json' \
  -d "$BODY" | jq .
