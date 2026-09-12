from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL") or "gemini-3.6-flash")
    groq_api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))
    groq_model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL") or "auto")
    llm_provider: str = field(default_factory=lambda: (os.getenv("LLM_PROVIDER") or "").strip().lower()
                              or ("groq" if os.getenv("GROQ_API_KEY") else "gemini"))
    step_budget: int = field(default_factory=lambda: int(os.getenv("STEP_BUDGET") or "24"))
    sandbox_url: str = field(default_factory=lambda: os.getenv("SANDBOX_URL", ""))
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT") or "sandbox")   # sandbox | live
    incident_db: str = field(default_factory=lambda: os.getenv("INCIDENT_DB", "data/incidents.db"))
    # Confidence needed before the agent may block on its own.
    block_confidence: float = 0.7
    # Confidence cap when a fallback evidence path was used (e.g. logs unavailable).
    degraded_confidence_cap: float = 0.6
    tool_retries: int = 3
    tool_backoff_s: float = 0.4


settings = Settings()
