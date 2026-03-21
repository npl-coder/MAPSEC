"""LangChain @tool wrappers for semantic search over ChromaDB collections."""

import json
from langchain_core.tools import tool
from soc_agent.vector_store.chroma_store import (
    get_playbook_store,
    get_incident_store,
    get_ioc_store,
    get_threat_actor_store,
)


def _format_docs(docs_with_scores: list) -> str:
    """Format retrieval results into a readable JSON string."""
    results = []
    for doc, score in docs_with_scores:
        results.append({
            "content": doc.page_content,
            "metadata": doc.metadata,
            "relevance_score": round(1 - score, 3),  # ChromaDB uses distance (lower=better)
        })
    return json.dumps(results, indent=2, default=str)


@tool
def retrieve_playbook(scenario: str) -> str:
    """Retrieve the most relevant SOC response playbook for a given attack scenario.
    Example: 'ransomware with lateral movement via SMB'.
    Returns the playbook steps and metadata."""
    store = get_playbook_store()
    results = store.similarity_search_with_score(scenario, k=2)
    if not results:
        return json.dumps({"message": "No matching playbook found."})
    return _format_docs(results)


@tool
def retrieve_similar_incidents(query: str, k: int = 3) -> str:
    """Semantic search for past SOC investigations similar to the current situation.
    Query with IOCs, techniques, or attack descriptions.
    Returns incident summaries with resolution details."""
    store = get_incident_store()
    results = store.similarity_search_with_score(query, k=k)
    if not results:
        return json.dumps({"message": "No similar past incidents found."})
    return _format_docs(results)


@tool
def retrieve_ioc_context(query: str, k: int = 5) -> str:
    """Search for previously enriched IOC profiles matching a description.
    Useful for finding related infrastructure or known-bad indicators."""
    store = get_ioc_store()
    results = store.similarity_search_with_score(query, k=k)
    if not results:
        return json.dumps({"message": "No matching IOC context found."})
    return _format_docs(results)


@tool
def retrieve_threat_actor_profile(description: str) -> str:
    """Find threat actor profiles matching observed TTPs, infrastructure, or targets.
    Example: 'APT group targeting financial sector using spear phishing'."""
    store = get_threat_actor_store()
    results = store.similarity_search_with_score(description, k=2)
    if not results:
        return json.dumps({"message": "No matching threat actor profile found."})
    return _format_docs(results)


RAG_TOOLS = [
    retrieve_playbook,
    retrieve_similar_incidents,
    retrieve_ioc_context,
    retrieve_threat_actor_profile,
]
