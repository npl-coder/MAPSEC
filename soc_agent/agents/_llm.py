"""Shared LLM instance factory for all agents."""

from langchain_core.language_models import BaseChatModel
from soc_agent.config.settings import settings

_llm: BaseChatModel | None = None


def get_llm() -> BaseChatModel:
    """Return the configured LLM (singleton). Supports Anthropic or OpenAI."""
    global _llm
    if _llm is not None:
        return _llm

    if settings.LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        _llm = ChatAnthropic(
            model=settings.LLM_MODEL,
            anthropic_api_key=settings.ANTHROPIC_API_KEY,
            temperature=0,
            max_tokens=4096,
        )
    elif settings.LLM_PROVIDER == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        _llm = ChatGoogleGenerativeAI(
            model=settings.LLM_MODEL,
            google_api_key=settings.GOOGLE_API_KEY,
            temperature=0,
        )
    else:
        from langchain_openai import ChatOpenAI
        _llm = ChatOpenAI(
            model=settings.LLM_MODEL,
            api_key=settings.OPENAI_API_KEY,
            temperature=0,
        )

    return _llm
