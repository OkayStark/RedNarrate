"""Central configuration, loaded from environment / .env.

Everything that varies between deployments (provider, model names, paths) lives
here so agents never read os.environ directly.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="REDNARRATE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM provider ────────────────────────────────────────────────
    # "anthropic" (cloud) | "ollama" (offline) | "none" (template/heuristic mode,
    # no LLM calls). Resolved in __init__: defaults to "none" when "anthropic" is
    # requested but no API key is available, so offline runs degrade cleanly to
    # deterministic output instead of emitting authentication errors.
    llm_provider: str = "anthropic"

    # Anthropic key is read without the REDNARRATE_ prefix (standard name).
    anthropic_api_key: str = ""

    # Per-role model selection (see PROJECT_PLAN §1, §3).
    writer_model: str = "claude-opus-4-8"
    scoring_model: str = "claude-haiku-4-5"
    correlation_model: str = "claude-haiku-4-5"

    # Ollama (offline)
    ollama_model: str = "qwen2.5:14b"
    ollama_base_url: str = "http://localhost:11434"

    # ── paths ───────────────────────────────────────────────────────
    db_path: str = "rednarrate.db"
    chroma_dir: str = "chroma_db"
    output_dir: str = "output"
    knowledge_dir: str = "knowledge"

    # Embedding model for RAG (local, offline-capable)
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # ANTHROPIC_API_KEY has no REDNARRATE_ prefix; pick it up explicitly.
        if not self.anthropic_api_key:
            import os

            self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        # If the cloud provider is selected but no key is available, degrade to
        # "none" (template/heuristic mode) rather than failing every LLM call with
        # an authentication error. Explicit "ollama"/"none" are always honoured.
        if self.llm_provider.lower() == "anthropic" and not self.anthropic_api_key:
            self.llm_provider = "none"

        # Disable LangSmith telemetry when no key is configured.
        # langchain-core 1.x enables tracing by default and errors if it can't
        # authenticate, even when all LLM calls are local (Ollama).
        import os

        if not os.environ.get("LANGCHAIN_API_KEY") and not os.environ.get("LANGSMITH_API_KEY"):
            os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
            os.environ.setdefault("LANGSMITH_TRACING", "false")

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)

    @property
    def chroma_path(self) -> Path:
        return Path(self.chroma_dir)

    @property
    def knowledge_path(self) -> Path:
        return Path(self.knowledge_dir)


_settings: Settings | None = None


def _reset_settings() -> None:
    global _settings
    _settings = None


def get_settings() -> Settings:
    """Process-wide singleton so config is read once."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
