"""Embedding model configuration for the vector store.

Uses HuggingFace sentence-transformers running locally (free, no API key).
"""

from langchain_huggingface import HuggingFaceEmbeddings
from soc_agent.config.settings import settings

_embeddings = None


def get_embedding_model() -> HuggingFaceEmbeddings:
    """Return a singleton embedding model instance."""
    global _embeddings
    if _embeddings is None:
        _embeddings = HuggingFaceEmbeddings(
            model_name=settings.EMBEDDING_MODEL,
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )
    return _embeddings
