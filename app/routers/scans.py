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

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile, Depends
from fastapi.responses import PlainTextResponse, Response

from app.config import settings
from app.models import (
    HistoryEntry,
    ScanRequest,
    ScanResult,
    ScanStatus,
    SourceType,
)
from app.auth import get_current_user
from app.database import get_supabase
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
    user_id: str = Depends(get_current_user),
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
        user_id=user_id,
        status=ScanStatus.QUEUED,
        source_type=src_type,
        source_value=source_value,
        started_at=datetime.now(timezone.utc),
        phase_message="Scan queued...",
    )
    _scans[scan_id] = scan_result

    # Launch scan in background
    background_tasks.add_task(_execute_scan, scan_id, src_type, source_value, upload_bytes, user_id)

    return {"scan_id": scan_id, "status": scan_result.status.value}


@router.post("/scan/json")
async def submit_scan_json(
    background_tasks: BackgroundTasks,
    request: ScanRequest,
    user_id: str = Depends(get_current_user),
):
    """Submit a new scan via JSON body."""
    scan_id = str(uuid.uuid4())[:12]
    scan_result = ScanResult(
        scan_id=scan_id,
        user_id=user_id,
        status=ScanStatus.QUEUED,
        source_type=request.source_type,
        source_value=request.source_value,
        started_at=datetime.now(timezone.utc),
        phase_message="Scan queued...",
    )
    _scans[scan_id] = scan_result

    background_tasks.add_task(
        _execute_scan, scan_id, request.source_type, request.source_value, None, user_id
    )

    return {"scan_id": scan_id, "status": scan_result.status.value}


def _get_authorized_scan(scan_id: str, user_id: str) -> ScanResult:
    """Helper to fetch a scan from memory or Supabase, ensuring user_id matches."""
    # Check in-memory first (for currently running scans)
    scan = _scans.get(scan_id)
    if scan:
        if scan.user_id != user_id:
            raise HTTPException(403, "Access denied")
        return scan

    # Fetch from Supabase
    try:
        supabase = get_supabase()
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(404, f"Scan {scan_id} not found")
        
        row = res.data[0]
        # We need to construct a ScanResult.
        # Check if reports exist
        rep_res = supabase.table("scan_reports").select("findings").eq("scan_id", scan_id).execute()
        findings_data = rep_res.data[0]["findings"] if rep_res.data else []
        
        # We parse the row back into a ScanResult model. 
        # (This is a bit simplified; in reality, we map the DB fields)
        return ScanResult(
            scan_id=row["id"],
            user_id=row["user_id"],
            status=ScanStatus(row["status"]),
            source_type=SourceType(row.get("git_url", "git_url").split("://")[0] if "://" in row.get("git_url", "") else SourceType.GIT_URL),
            source_value=row["git_url"],
            started_at=row["created_at"],
            completed_at=row.get("completed_at"),
            findings=findings_data,
            summary=row.get("summary"),
            phase_message="Loaded from history"
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error fetching scan %s: %s", scan_id, exc)
        raise HTTPException(404, f"Scan {scan_id} not found")


# ---------------------------------------------------------------------------
# Poll status
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, user_id: str = Depends(get_current_user)):
    """Get the current status of a scan."""
    scan = _get_authorized_scan(scan_id, user_id)

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
async def get_scan_results(scan_id: str, user_id: str = Depends(get_current_user)):
    """Get the full scan results."""
    scan = _get_authorized_scan(scan_id, user_id)
    return scan.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Download reports
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/report/markdown")
async def download_markdown(scan_id: str, user_id: str = Depends(get_current_user)):
    """Download the scan report as Markdown."""
    scan = _get_authorized_scan(scan_id, user_id)

    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(400, "Scan is not yet complete")

    md = generate_markdown_report(scan)
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=securedeploy-{scan_id}.md"},
    )


@router.get("/scan/{scan_id}/report/json")
async def download_json(scan_id: str, user_id: str = Depends(get_current_user)):
    """Download the scan report as JSON."""
    scan = _get_authorized_scan(scan_id, user_id)

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
    user_id: str,
) -> None:
    """Execute the full scan pipeline in the background."""
    scan = _scans[scan_id]
    repo_path = None
    
    # Pre-create history record in Supabase so it shows up as Queued
    try:
        supabase = get_supabase()
        supabase.table("scan_history").insert({
            "id": scan_id,
            "user_id": user_id,
            "git_url": source_value,
            "status": ScanStatus.QUEUED.value
        }).execute()
    except Exception as exc:
        logger.error("Failed to insert initial scan record: %s", exc)

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
            
        # Update Supabase status (even on failure)
        try:
            supabase = get_supabase()
            supabase.table("scan_history").update({
                "status": scan.status.value
            }).eq("id", scan_id).execute()
        except Exception:
            pass


def _save_to_history(scan: ScanResult) -> None:
    """Append scan result to Supabase."""
    try:
        supabase = get_supabase()
        
        # Update scan_history
        supabase.table("scan_history").update({
            "status": scan.status.value,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "summary": scan.summary.model_dump(mode="json") if scan.summary else None
        }).eq("id", scan.scan_id).execute()
        
        # Insert findings into scan_reports
        supabase.table("scan_reports").insert({
            "scan_id": scan.scan_id,
            "findings": [f.model_dump(mode="json") for f in scan.findings]
        }).execute()
        
    except Exception as exc:
        logger.warning("Failed to save history to Supabase: %s", exc)
