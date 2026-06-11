"""LLM factory. One place that knows about providers and per-role models.

Agents call get_llm("writer" | "scoring" | "correlation") and never reference a
provider or model string themselves (CLAUDE.md invariant). Both the Anthropic
cloud path and the offline Ollama path return a LangChain chat model, so agent
code is provider-agnostic.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from .config import get_settings

Role = Literal["writer", "scoring", "correlation"]

# Generous-but-bounded output ceilings per role.
_MAX_TOKENS = {"writer": 2000, "scoring": 800, "correlation": 1500}


class LLMUnavailable(RuntimeError):
    """Raised when no LLM backend is configured (provider 'none').

    Every agent catches this and falls back to deterministic output
    (heuristic CVSS vectors, template narratives, rule-based chains), so the
    pipeline runs fully offline with no network dependency or auth errors.
    """


@lru_cache(maxsize=8)
def get_llm(role: Role = "writer"):
    """Return a LangChain chat model for the given role.

    Cached per (provider, role) so repeated calls reuse one client.
    """
    settings = get_settings()
    provider = settings.llm_provider.lower()
    max_tokens = _MAX_TOKENS.get(role, 1500)

    if provider in ("none", "off", "mock", ""):
        # Offline/template mode: no LLM. Agents fall back to deterministic output.
        raise LLMUnavailable(
            "LLM provider is 'none'; using deterministic heuristics/templates"
        )

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=settings.ollama_model,
            base_url=settings.ollama_base_url,
            num_predict=max_tokens,
            temperature=0,
            keep_alive="10m",  # keep model warm between pipeline calls
        )

    # Default: Anthropic cloud.
    from langchain_anthropic import ChatAnthropic

    model = {
        "writer": settings.writer_model,
        "scoring": settings.scoring_model,
        "correlation": settings.correlation_model,
    }.get(role, settings.writer_model)

    kwargs = {"model": model, "max_tokens": max_tokens}
    if settings.anthropic_api_key:
        kwargs["api_key"] = settings.anthropic_api_key
    return ChatAnthropic(**kwargs)


def reset_llm_cache() -> None:
    """Drop cached clients (e.g. after changing provider in tests)."""
    get_llm.cache_clear()
