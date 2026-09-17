"""
Scan history endpoints.
"""

from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter

from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history")
async def get_history():
    """Return recent scan history."""
    try:
        if not os.path.isfile(settings.HISTORY_FILE):
            return {"history": []}

        with open(settings.HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)

        return {"history": history}
    except Exception as exc:
        logger.warning("Failed to load history: %s", exc)
        return {"history": []}
