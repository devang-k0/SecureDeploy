import os
from supabase import create_client, Client
import logging

logger = logging.getLogger(__name__)

supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_SERVICE_KEY") or os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_ANON_KEY")

supabase: Client | None = None

if supabase_url and supabase_key:
    supabase = create_client(supabase_url, supabase_key)
    logger.info(f"Supabase client initialized for {supabase_url}")
else:
    logger.warning("Supabase credentials not found in environment variables. Database integration disabled.")

def get_supabase() -> Client:
    if supabase is None:
        raise ValueError("Supabase is not configured.")
    return supabase
