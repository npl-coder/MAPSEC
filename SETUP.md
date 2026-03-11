# Local setup: MISP + OpenSearch + Nginx (HTTPS vhosts)

This repo runs MISP, OpenSearch, and OpenSearch Dashboards via `docker compose`, and (optionally) an **nginx reverse-proxy** that provides convenient local domains over **HTTPS**.

Nginx runs **outside** the Docker network and talks to the stack via published host ports using `host.docker.internal`.

## Prerequisites

- Docker Desktop (or Docker Engine) with Compose v2 (`docker compose`)
- You will update `/etc/hosts` yourself

## 1) Start the main stack (project root)

From the repo root:

```bash
cd /Users/arman/Documents/Personal/mapsec/projects/mcp
docker compose up -d
```

### Published ports (host)

- **MISP (HTTPS)**: `8443 -> misp:443`
- **OpenSearch**: `9200 -> opensearch:9200`
- **OpenSearch Dashboards**: `5601 -> opensearch-dashboards:5601`

## 2) Set up local nginx (HTTPS on 443)

### 2.1) Add hostnames

Add these lines to `/etc/hosts`:

```text
127.0.0.1 misp.local
127.0.0.1 opensearch.local
127.0.0.1 opensearch-dashboards.local
```

### 2.2) Generate local TLS certs (one-time)

```bash
cd /Users/arman/Documents/Personal/mapsec/projects/mcp/nginx
./ssl/gen-certs.sh
```

This creates:

- `nginx/ssl/cert.pem`
- `nginx/ssl/key.pem`

### 2.3) Start nginx

```bash
cd /Users/arman/Documents/Personal/mapsec/projects/mcp/nginx
docker compose up -d
```

Nginx listens on:

- **80** (redirects to HTTPS)
- **443** (HTTPS with self-signed cert)

## 3) Access URLs

- **MISP**: `https://misp.local`
- **OpenSearch API**: `https://opensearch.local`
- **OpenSearch Dashboards**: `https://opensearch-dashboards.local`

Your browser will warn about the self-signed certificate the first time; accept it for these local hostnames.

## 4) Common issue: MISP still uses `https://localhost/...`

If MISP links / actions (e.g. feed fetch) still hit `https://localhost/...`, MISP has a stored base URL from earlier.

Fix it (with the stack up):

```bash
cd /Users/arman/Documents/Personal/mapsec/projects/mcp
./scripts/misp-set-baseurl.sh https://misp.local
```

Then reload MISP (hard refresh).

## 5) Stop / reset

Stop nginx:

```bash
cd /Users/arman/Documents/Personal/mapsec/projects/mcp/nginx
docker compose down
```

Stop the main stack:

```bash
cd /Users/arman/Documents/Personal/mapsec/projects/mcp
docker compose down
```

