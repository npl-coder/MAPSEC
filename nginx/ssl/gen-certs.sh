#!/usr/bin/env bash
# Generate self-signed cert for misp.local, opensearch.local, opensearch-dashboards.local
set -e
cd "$(dirname "$0")"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -config openssl.cnf -extensions v3_req
echo "Created cert.pem and key.pem"
