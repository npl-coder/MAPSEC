"""OpenSearch tools for log searching and aggregation.

Uses the opensearch-py client directly for flexibility.
Falls back gracefully if OpenSearch is not available.
"""

import json
from langchain_core.tools import tool
from soc_agent.config.settings import settings

_client = None


def _get_client():
    """Lazy-initialize the OpenSearch client."""
    global _client
    if _client is None:
        from opensearchpy import OpenSearch
        _client = OpenSearch(
            hosts=[settings.OPENSEARCH_URL],
            http_auth=(settings.OPENSEARCH_USERNAME, settings.OPENSEARCH_PASSWORD),
            use_ssl=settings.OPENSEARCH_USE_SSL,
            verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
            ssl_show_warn=False,
            timeout=30,
        )
    return _client


@tool
def opensearch_search_logs(
    query_string: str,
    index: str = "*",
    time_range: str = "24h",
    size: int = 50,
) -> str:
    """Search OpenSearch logs using a query string.

    Args:
        query_string: Lucene/OpenSearch query (e.g. 'src_ip:185.220.101.45 AND dst_port:445')
        index: Index pattern to search (default: all indices)
        time_range: Time window - '1h', '24h', '7d', '30d' (default: 24h)
        size: Max results to return (default: 50)
    """
    try:
        client = _get_client()
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query_string}},
                    ],
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
                    ],
                }
            },
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        result = client.search(index=index, body=body)
        hits = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        documents = [
            {
                "_index": h["_index"],
                "_id": h["_id"],
                "_source": h["_source"],
            }
            for h in hits.get("hits", [])
        ]

        return json.dumps({
            "total_hits": total,
            "returned": len(documents),
            "query": query_string,
            "time_range": time_range,
            "documents": documents,
        }, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "query": query_string})


@tool
def opensearch_aggregate(
    query_string: str,
    agg_field: str,
    index: str = "*",
    time_range: str = "24h",
    agg_size: int = 20,
) -> str:
    """Run an aggregation query on OpenSearch to find top values for a field.

    Args:
        query_string: Base query to filter logs
        agg_field: Field to aggregate on (e.g. 'source.ip', 'destination.port')
        index: Index pattern
        time_range: Time window
        agg_size: Number of top buckets to return
    """
    try:
        client = _get_client()
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query_string}}],
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
                    ],
                }
            },
            "size": 0,
            "aggs": {
                "top_values": {
                    "terms": {"field": agg_field, "size": agg_size}
                }
            },
        }

        result = client.search(index=index, body=body)
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        buckets = result.get("aggregations", {}).get("top_values", {}).get("buckets", [])

        return json.dumps({
            "total_matching": total,
            "aggregation_field": agg_field,
            "buckets": [{"key": b["key"], "count": b["doc_count"]} for b in buckets],
        }, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "query": query_string})


@tool
def opensearch_list_indices() -> str:
    """List all available OpenSearch indices with document counts.
    Useful for understanding what log data is available."""
    try:
        client = _get_client()
        indices = client.cat.indices(format="json")
        result = [
            {
                "index": idx.get("index", ""),
                "docs_count": idx.get("docs.count", "0"),
                "store_size": idx.get("store.size", "0"),
                "health": idx.get("health", ""),
            }
            for idx in indices
            if not idx.get("index", "").startswith(".")
        ]
        return json.dumps({"indices": result, "count": len(result)}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


OPENSEARCH_TOOLS = [opensearch_search_logs, opensearch_aggregate, opensearch_list_indices]
