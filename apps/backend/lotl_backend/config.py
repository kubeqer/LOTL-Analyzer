from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

HERE = Path(__file__).resolve().parent
BACKEND_ROOT = HERE.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_ROOT / ".env",
        env_prefix="LOTL_",
        case_sensitive=False,
        extra="ignore",
    )

    window_seconds: int = 60
    max_buffered_events_per_host: int = 10_000

    ml_model_path: Path = BACKEND_ROOT.parent / "log_analyzer_ml" / "data" / "lotl_xgb.json"
    ml_sidecar_path: Path = (
        BACKEND_ROOT.parent / "log_analyzer_ml" / "data" / "lotl_xgb.sidecar.json"
    )
    ml_threshold: float = 0.5

    yara_rules_dir: Path = HERE / "detectors" / "yara_rules"

    llm_base_url: str = "http://localhost:8000/v1"
    llm_model: str = "meta-llama/Llama-3.1-8B-Instruct"
    llm_api_key: str = "not-needed"
    llm_timeout_seconds: float = 30.0
    llm_reasoning_effort: str = "high"
    llm_min_confidence: float = 0.6

    rag_store_dir: Path = BACKEND_ROOT / "data" / "rag_store"
    rag_collection: str = "lotl-knowledge"
    rag_embed_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    rag_refresh_hours: int = 24
    rag_top_k: int = 5
    rag_chunk_size: int = 900
    rag_chunk_overlap: int = 150
    lolbas_url: str = "https://lolbas-project.github.io/api/lolbas.json"
    advisory_feeds: str = (
        "https://www.cisa.gov/cybersecurity-advisories/all.xml,"
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog.xml"
    )

    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_index: str = "lotl-alerts"

    @property
    def advisory_feed_urls(self) -> list[str]:
        return [u.strip() for u in self.advisory_feeds.split(",") if u.strip()]


settings = Settings()
