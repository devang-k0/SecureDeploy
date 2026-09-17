"""
Scan history endpoints.
"""

from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, Depends

from app.auth import get_current_user
from app.database import get_supabase

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history")
async def get_history(user_id: str = Depends(get_current_user)):
    """Return recent scan history for the authenticated user from Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table("scan_history").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
        return {"history": response.data}
    except Exception as exc:
        logger.warning("Failed to load history from Supabase: %s", exc)
        return {"history": []}
