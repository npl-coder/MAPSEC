# Scripts

Small helper scripts for interacting with the local MAPSEC stack (MISP, OpenSearch) via the nginx vhost domains.

## Prereqs

- **Hosts file**: `misp.local` and `opensearch.local` should resolve to your local machine (typically via `/etc/hosts`).
- **Stack running**: bring up the main `docker compose` stack (and nginx, if separated in your setup).
- **CLI tools**:
  - `curl`
  - `jq`
  - `docker compose` (for scripts that exec into containers)

## `list-misp-events.sh`

Lists recent MISP events from the local MISP instance and prints a small summary plus the first few events as JSON.

- **Env vars**:
  - **`MISP_API_KEY`** (required): MISP auth key (in MISP UI: *Admin → My Profile → Auth Keys*)
  - **`MISP_URL`** (optional): defaults to `https://misp.local`
- **Args**:
  - **`LIMIT`** (optional): number of events to fetch (default: `10`)

Examples:

```bash
MISP_API_KEY=your_key ./scripts/list-misp-events.sh
MISP_API_KEY=your_key ./scripts/list-misp-events.sh 25
MISP_API_KEY=your_key MISP_URL=https://misp.local ./scripts/list-misp-events.sh 5
```

## `misp-set-baseurl.sh`

Sets MISP’s base URL and `external_baseurl` setting inside the running `misp` container. Useful if the UI or feed fetches are using `https://localhost/...` or an incorrect domain.

- **Args**:
  - **`baseurl`** (optional): defaults to `https://misp.local`
- **Requires**:
  - A running container named **`misp`** in your `docker compose` project

Examples:

```bash
./scripts/misp-set-baseurl.sh
./scripts/misp-set-baseurl.sh https://misp.local
```

## `query-opensearch-logs.sh`

Queries OpenSearch via the nginx vhost domain. With no args, it lists indices and prints cluster health. With an index name, it runs a default `match_all` query (10 most recent hits by `@timestamp`) or a custom JSON query you provide.

- **Env vars**:
  - **`OPENSEARCH_URL`** (optional): defaults to `https://opensearch.local`
- **Args**:
  - **`INDEX`** (optional): when omitted, prints indices + cluster health
  - **`QUERY_JSON`** (optional): raw JSON string for the OpenSearch search body

Examples:

```bash
./scripts/query-opensearch-logs.sh
./scripts/query-opensearch-logs.sh linux-security-logs
./scripts/query-opensearch-logs.sh linux-security-logs '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}'
OPENSEARCH_URL=https://opensearch.local ./scripts/query-opensearch-logs.sh linux-security-logs
```

## `misp-query.py`

Python example using `pymisp` to search MISP attributes (IP source/destination) from the last day.

- **Requires**: `pymisp` installed (see repo `requirements.txt`)
- **Env vars**:
  - **`MISP_API_KEY`**: expected to be set (script checks for it)

Example:

```bash
python3 ./scripts/misp-query.py
```

Notes:

- This script is currently a **rough example** and includes hard-coded values (URL/key) that you’ll likely want to replace with environment variables before using it in earnest.

