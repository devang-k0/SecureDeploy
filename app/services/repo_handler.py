"""
Repository handler — clone Git repos, extract ZIPs, validate local paths.
All operations use temp directories with guaranteed cleanup.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)


class RepoHandlerError(Exception):
    """Raised when repo acquisition fails."""


async def prepare_repo(
    source_type: str, source_value: str, upload_bytes: bytes | None = None
) -> str:
    """
    Prepare a repo directory for scanning.
    Returns the path to the prepared directory.
    Caller is responsible for cleanup via cleanup_repo().
    """
    if source_type == "git_url":
        return await _clone_git_repo(source_value)
    elif source_type == "zip_upload":
        return _extract_zip(upload_bytes, source_value)
    elif source_type == "local_path":
        return _validate_local_path(source_value)
    else:
        raise RepoHandlerError(f"Unknown source type: {source_type}")


async def _clone_git_repo(url: str) -> str:
    """Clone a public Git repo to a temp directory (shallow clone)."""
    # Basic URL validation
    if not url.startswith(("https://", "http://", "git@")):
        raise RepoHandlerError(
            "Invalid Git URL. Must start with https://, http://, or git@"
        )

    dest = tempfile.mkdtemp(dir=settings.TEMP_DIR, prefix="repo_")
    logger.info("Cloning %s to %s", url, dest)

    try:
        proc = await asyncio.create_subprocess_exec(
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            url,
            dest,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=120
        )

        if proc.returncode != 0:
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")
            raise RepoHandlerError(
                f"Git clone failed (exit {proc.returncode}): {stderr_text[:500]}"
            )

        # Check size
        repo_size_mb = _dir_size_mb(dest)
        if repo_size_mb > settings.MAX_REPO_SIZE_MB:
            raise RepoHandlerError(
                f"Repository is too large ({repo_size_mb:.0f} MB, max {settings.MAX_REPO_SIZE_MB} MB)"
            )

        logger.info("Clone complete: %.1f MB", repo_size_mb)
        return dest

    except asyncio.TimeoutError:
        cleanup_repo(dest)
        raise RepoHandlerError("Git clone timed out after 120 seconds")
    except RepoHandlerError:
        cleanup_repo(dest)
        raise
    except Exception as exc:
        cleanup_repo(dest)
        raise RepoHandlerError(f"Git clone error: {exc}") from exc


def _extract_zip(data: bytes | None, filename: str) -> str:
    """Extract a ZIP archive to a temp directory."""
    if not data:
        raise RepoHandlerError("No ZIP data received")

    # Check size
    size_mb = len(data) / (1024 * 1024)
    if size_mb > settings.MAX_UPLOAD_SIZE_MB:
        raise RepoHandlerError(
            f"Upload too large ({size_mb:.0f} MB, max {settings.MAX_UPLOAD_SIZE_MB} MB)"
        )

    dest = tempfile.mkdtemp(dir=settings.TEMP_DIR, prefix="zip_")

    try:
        zip_path = os.path.join(dest, "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(data)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Security: check for zip bomb / path traversal
            for info in zf.infolist():
                if info.filename.startswith("/") or ".." in info.filename:
                    raise RepoHandlerError(
                        f"Unsafe path in ZIP: {info.filename}"
                    )
                if info.file_size > settings.MAX_REPO_SIZE_MB * 1024 * 1024:
                    raise RepoHandlerError(
                        f"File too large in ZIP: {info.filename}"
                    )

            extract_dir = os.path.join(dest, "source")
            os.makedirs(extract_dir, exist_ok=True)
            zf.extractall(extract_dir)

        # Remove the zip file
        os.unlink(zip_path)

        # If the zip contains a single top-level directory, use that
        contents = os.listdir(extract_dir)
        if len(contents) == 1:
            inner = os.path.join(extract_dir, contents[0])
            if os.path.isdir(inner):
                return inner

        return extract_dir

    except zipfile.BadZipFile:
        cleanup_repo(dest)
        raise RepoHandlerError("Invalid ZIP file")
    except RepoHandlerError:
        cleanup_repo(dest)
        raise
    except Exception as exc:
        cleanup_repo(dest)
        raise RepoHandlerError(f"ZIP extraction error: {exc}") from exc


def _validate_local_path(path: str) -> str:
    """Validate that a local path exists and is a directory."""
    resolved = str(Path(path).resolve())

    if not os.path.isdir(resolved):
        raise RepoHandlerError(f"Local path does not exist or is not a directory: {path}")

    size_mb = _dir_size_mb(resolved)
    if size_mb > settings.MAX_REPO_SIZE_MB:
        raise RepoHandlerError(
            f"Directory too large ({size_mb:.0f} MB, max {settings.MAX_REPO_SIZE_MB} MB)"
        )

    return resolved


def cleanup_repo(repo_path: str) -> None:
    """Safely remove a temporary repo directory."""
    if not repo_path:
        return

    # Only remove directories under our temp dir (safety guard)
    try:
        temp_base = str(Path(settings.TEMP_DIR).resolve())
        resolved = str(Path(repo_path).resolve())
        if resolved.startswith(temp_base):
            shutil.rmtree(resolved, ignore_errors=True)
            logger.info("Cleaned up temp repo: %s", resolved)
        else:
            logger.debug("Not cleaning up non-temp path: %s", resolved)
    except Exception as exc:
        logger.warning("Cleanup failed for %s: %s", repo_path, exc)


def _dir_size_mb(path: str) -> float:
    """Calculate total directory size in MB."""
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total / (1024 * 1024)
