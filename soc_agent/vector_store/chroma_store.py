"""ChromaDB persistent vector store with four collections.

Collections:
  - soc_playbooks: Response playbooks for various threat scenarios
  - past_incidents: Final reports from past investigations (grows over time)
  - ioc_context: Enriched IOC profiles with cross-source intelligence
  - threat_actors: Seed threat actor profiles with TTPs
"""

from langchain_chroma import Chroma
from soc_agent.config.settings import settings
from soc_agent.vector_store.embeddings import get_embedding_model

_stores: dict[str, Chroma] = {}

COLLECTION_NAMES = [
    "soc_playbooks",
    "past_incidents",
    "ioc_context",
    "threat_actors",
]


def get_store(collection_name: str) -> Chroma:
    """Return a Chroma vector store for the given collection (singleton)."""
    if collection_name not in _stores:
        _stores[collection_name] = Chroma(
            collection_name=collection_name,
            embedding_function=get_embedding_model(),
            persist_directory=settings.CHROMA_DB_PATH,
        )
    return _stores[collection_name]


def get_playbook_store() -> Chroma:
    return get_store("soc_playbooks")


def get_incident_store() -> Chroma:
    return get_store("past_incidents")


def get_ioc_store() -> Chroma:
    return get_store("ioc_context")


def get_threat_actor_store() -> Chroma:
    return get_store("threat_actors")
