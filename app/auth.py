from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.database import get_supabase
import logging

logger = logging.getLogger(__name__)

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Verifies the Supabase JWT token and returns the user ID.
    """
    token = credentials.credentials
    try:
        supabase = get_supabase()
        # Verify token by fetching the user. Supabase handles the JWT decoding and validation securely.
        res = supabase.auth.get_user(token)
        if not res or not res.user:
            raise ValueError("Invalid user session")
        return res.user.id
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
