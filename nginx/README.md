# Nginx reverse proxy (ports 80 and 443)

Nginx runs **outside** the MISP stack and reaches services via the host using `host.docker.internal`. It listens on 80 (redirects to HTTPS) and 443 (HTTPS with a self-signed cert).

Add these to `/etc/hosts`:

```
127.0.0.1 misp.local
127.0.0.1 opensearch.local
127.0.0.1 opensearch-dashboards.local
```

## Usage

1. **Generate SSL certs** (once): `./ssl/gen-certs.sh` (creates `ssl/cert.pem` and `ssl/key.pem`).
2. Start the main stack from project root: `docker-compose up -d` (exposes 8443, 9200, 5601 on the host).
3. Start nginx from this directory: `docker-compose up -d`.

Then open (use HTTPS; HTTP redirects to HTTPS):

- **MISP:** https://misp.local → `host.docker.internal:8443` (HTTPS)
- **OpenSearch API:** https://opensearch.local → `host.docker.internal:9200`
- **OpenSearch Dashboards:** https://opensearch-dashboards.local → `host.docker.internal:5601`

Accept the self-signed certificate in your browser when prompted.

## Network

Nginx does **not** join the MISP network. It uses `extra_hosts: host.docker.internal:host-gateway` to reach the host; the main stack must publish the above ports so they are reachable on the host.
