"""
Application configuration via environment variables.
All settings have sensible defaults for local development.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Server ---
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # --- Ollama (optional LLM triage) ---
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "mistral"
    OLLAMA_TIMEOUT: int = 120  # seconds

    # --- Scan limits ---
    MAX_REPO_SIZE_MB: int = 500
    SCAN_TIMEOUT_SECONDS: int = 600  # per-scanner timeout
    MAX_UPLOAD_SIZE_MB: int = 200

    # --- Paths ---
    TEMP_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp_scans")
    HISTORY_FILE: str = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "scan_history.json"
    )
    REPORTS_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports")

    # --- History ---
    MAX_HISTORY_ENTRIES: int = 20

    model_config = {"env_prefix": "SECUREDEPLOY_", "env_file": ".env", "extra": "ignore"}


settings = Settings()

# Ensure directories exist
Path(settings.TEMP_DIR).mkdir(parents=True, exist_ok=True)
Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
Path(settings.HISTORY_FILE).parent.mkdir(parents=True, exist_ok=True)
