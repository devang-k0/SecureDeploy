"""
Scan API endpoints — submit scans, poll status, get results, download reports.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse, Response

from app.config import settings
from app.models import (
    HistoryEntry,
    ScanRequest,
    ScanResult,
    ScanStatus,
    SourceType,
)
from app.scanners.runner import run_all_scanners
from app.services.ollama_service import analyze_findings
from app.services.repo_handler import RepoHandlerError, cleanup_repo, prepare_repo
from app.services.report_generator import generate_json_report, generate_markdown_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["scans"])

# In-memory scan store (keyed by scan_id)
_scans: dict[str, ScanResult] = {}


def get_scan_store() -> dict[str, ScanResult]:
    """Expose scan store for history router."""
    return _scans


# ---------------------------------------------------------------------------
# Submit a scan
# ---------------------------------------------------------------------------

@router.post("/scan")
async def submit_scan(
    background_tasks: BackgroundTasks,
    source_type: str = Form(None),
    source_value: str = Form(None),
    file: Optional[UploadFile] = File(None),
    json_body: Optional[str] = Form(None),
):
    """Submit a new security scan."""
    # Handle JSON body submission (from fetch with JSON content-type)
    if source_type is None and json_body:
        try:
            data = json.loads(json_body)
            source_type = data.get("source_type")
            source_value = data.get("source_value")
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid JSON body")

    if not source_type or not source_value:
        raise HTTPException(400, "source_type and source_value are required")

    # Validate source_type
    try:
        src_type = SourceType(source_type)
    except ValueError:
        raise HTTPException(
            400, f"Invalid source_type: {source_type}. Must be one of: git_url, zip_upload, local_path"
        )

    # Read upload bytes if ZIP
    upload_bytes: Optional[bytes] = None
    if src_type == SourceType.ZIP_UPLOAD and file:
        upload_bytes = await file.read()

    scan_id = str(uuid.uuid4())[:12]
    scan_result = ScanResult(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        source_type=src_type,
        source_value=source_value,
        started_at=datetime.now(timezone.utc),
        phase_message="Scan queued...",
    )
    _scans[scan_id] = scan_result

    # Launch scan in background
    background_tasks.add_task(_execute_scan, scan_id, src_type, source_value, upload_bytes)

    return {"scan_id": scan_id, "status": scan_result.status.value}


@router.post("/scan/json")
async def submit_scan_json(
    background_tasks: BackgroundTasks,
    request: ScanRequest,
):
    """Submit a new scan via JSON body."""
    scan_id = str(uuid.uuid4())[:12]
    scan_result = ScanResult(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        source_type=request.source_type,
        source_value=request.source_value,
        started_at=datetime.now(timezone.utc),
        phase_message="Scan queued...",
    )
    _scans[scan_id] = scan_result

    background_tasks.add_task(
        _execute_scan, scan_id, request.source_type, request.source_value, None
    )

    return {"scan_id": scan_id, "status": scan_result.status.value}


# ---------------------------------------------------------------------------
# Poll status
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the current status of a scan."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")

    return {
        "scan_id": scan.scan_id,
        "status": scan.status.value,
        "phase_message": scan.phase_message,
        "total_findings": len(scan.findings),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
    }


# ---------------------------------------------------------------------------
# Get results
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the full scan results."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")

    return scan.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Download reports
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/report/markdown")
async def download_markdown(scan_id: str):
    """Download the scan report as Markdown."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")

    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(400, "Scan is not yet complete")

    md = generate_markdown_report(scan)
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=securedeploy-{scan_id}.md"},
    )


@router.get("/scan/{scan_id}/report/json")
async def download_json(scan_id: str):
    """Download the scan report as JSON."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")

    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(400, "Scan is not yet complete")

    json_report = generate_json_report(scan)
    return Response(
        content=json_report,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=securedeploy-{scan_id}.json"},
    )


# ---------------------------------------------------------------------------
# Background scan execution
# ---------------------------------------------------------------------------

async def _execute_scan(
    scan_id: str,
    source_type: SourceType,
    source_value: str,
    upload_bytes: Optional[bytes],
) -> None:
    """Execute the full scan pipeline in the background."""
    scan = _scans[scan_id]
    repo_path = None

    try:
        # Phase 1: Prepare repo
        scan.status = ScanStatus.CLONING
        scan.phase_message = "Preparing repository..."
        repo_path = await prepare_repo(source_type.value, source_value, upload_bytes)

        # Phase 2: Run scanners
        scan.status = ScanStatus.SCANNING
        scan.phase_message = "Running security scanners..."
        await run_all_scanners(repo_path, scan)

        # Phase 3: AI analysis (optional)
        scan.status = ScanStatus.ANALYZING
        scan.phase_message = "Running AI analysis (if available)..."
        if scan.findings:
            ai_result = await analyze_findings(scan.findings)
            if ai_result:
                scan.ai_analysis = ai_result
                scan.phase_message = "AI analysis complete"
            else:
                scan.phase_message = "AI analysis skipped (Ollama not available)"

        # Done
        scan.status = ScanStatus.COMPLETE
        scan.completed_at = datetime.now(timezone.utc)
        scan.phase_message = f"Scan complete — {len(scan.findings)} findings"

        # Save to history
        _save_to_history(scan)

        logger.info("Scan %s complete: %d findings", scan_id, len(scan.findings))

    except RepoHandlerError as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)
        scan.phase_message = f"Failed: {exc}"
        logger.error("Scan %s failed: %s", scan_id, exc)

    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Unexpected error: {exc}"
        scan.phase_message = f"Failed: unexpected error"
        logger.error("Scan %s crashed: %s", scan_id, exc, exc_info=True)

    finally:
        # Always clean up temp files
        if repo_path and source_type != SourceType.LOCAL_PATH:
            cleanup_repo(repo_path)


def _save_to_history(scan: ScanResult) -> None:
    """Append scan result to the history file."""
    try:
        history: list[dict] = []
        if os.path.isfile(settings.HISTORY_FILE):
            with open(settings.HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)

        entry = HistoryEntry(
            scan_id=scan.scan_id,
            source_type=scan.source_type,
            source_value=scan.source_value,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            status=scan.status,
            total_findings=len(scan.findings),
            critical=scan.summary.critical if scan.summary else 0,
            high=scan.summary.high if scan.summary else 0,
        )
        history.insert(0, entry.model_dump(mode="json"))

        # Keep only recent entries
        history = history[: settings.MAX_HISTORY_ENTRIES]

        with open(settings.HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)

    except Exception as exc:
        logger.warning("Failed to save history: %s", exc)
