"""
FastAPI application entrypoint.
Serves the API and static frontend.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.routers import history, scans

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Create app
app = FastAPI(
    title="SecureDeploy",
    description="Security scanner web application for code repositories",
    version="1.0.0",
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(scans.router)
app.include_router(history.router)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
async def serve_index():
    """Serve the main SPA page."""
    return FileResponse("app/static/index.html")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": "1.0.0"}


@app.on_event("startup")
async def startup_event():
    logger.info("SecureDeploy starting on %s:%d", settings.APP_HOST, settings.APP_PORT)
    logger.info("Ollama URL: %s (model: %s)", settings.OLLAMA_URL, settings.OLLAMA_MODEL)
    logger.info("Temp dir: %s", settings.TEMP_DIR)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=True,
    )
