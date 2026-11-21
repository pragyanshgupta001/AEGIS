"""Central configuration, read from environment variables / the .env file.

API keys are only ever read from the environment - never hard-coded.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

DEMO_DATA_DIR = PROJECT_ROOT / "demo_data"
REPORTS_DIR = PROJECT_ROOT / "reports"

SUPPORTED_PROVIDERS = ("openai_compatible", "anthropic")


def _float_or_none(value: str | None) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _bool(value: str | None, default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    api_key: str
    base_url: str
    model: str
    timeout_seconds: int
    temperature: float
    max_tokens: int
    json_mode: bool
    price_input_per_1m: float | None
    price_output_per_1m: float | None

    @property
    def is_configured(self) -> bool:
        local = "localhost" in self.base_url or "127.0.0.1" in self.base_url
        return bool(self.model) and (bool(self.api_key) or local)

    @property
    def pricing_configured(self) -> bool:
        return self.price_input_per_1m is not None and self.price_output_per_1m is not None

    def describe(self) -> str:
        return f"{self.provider} · {self.model or '(no model set)'}"


@dataclass(frozen=True)
class AppSettings:
    db_path: Path
    change_lookback_minutes: int
    context_minutes: int


def get_llm_config() -> LLMConfig:
    provider = os.getenv("LLM_PROVIDER", "openai_compatible").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        provider = "openai_compatible"
    default_url = "https://api.anthropic.com" if provider == "anthropic" else "https://api.openai.com/v1"
    temperature = _float_or_none(os.getenv("LLM_TEMPERATURE"))
    return LLMConfig(
        provider=provider,
        api_key=os.getenv("LLM_API_KEY", "").strip(),
        base_url=(os.getenv("LLM_BASE_URL", "").strip() or default_url).rstrip("/"),
        model=os.getenv("LLM_MODEL", "").strip(),
        timeout_seconds=_int(os.getenv("LLM_TIMEOUT_SECONDS"), 90),
        temperature=0.1 if temperature is None else temperature,
        max_tokens=_int(os.getenv("LLM_MAX_TOKENS"), 2500),
        json_mode=_bool(os.getenv("LLM_JSON_MODE"), True),
        price_input_per_1m=_float_or_none(os.getenv("LLM_PRICE_INPUT_PER_1M")),
        price_output_per_1m=_float_or_none(os.getenv("LLM_PRICE_OUTPUT_PER_1M")),
    )


def get_app_settings() -> AppSettings:
    db_path = Path(os.getenv("AEGIS_DB_PATH", "data/aegis.db"))
    if not db_path.is_absolute():
        db_path = PROJECT_ROOT / db_path
    return AppSettings(
        db_path=db_path,
        change_lookback_minutes=_int(os.getenv("AEGIS_CHANGE_LOOKBACK_MINUTES"), 60),
        context_minutes=_int(os.getenv("AEGIS_CONTEXT_MINUTES"), 10),
    )
