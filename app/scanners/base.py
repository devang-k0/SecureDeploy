"""
Abstract base class for all security scanners.
Provides common subprocess execution with timeout and error handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from abc import ABC, abstractmethod
from typing import Optional

from app.config import settings
from app.models import Finding

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Interface that every scanner plugin must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""

    @property
    @abstractmethod
    def binary(self) -> str:
        """CLI binary name (used for availability check)."""

    def is_available(self) -> bool:
        """Check if the scanner binary is on PATH."""
        return shutil.which(self.binary) is not None

    @abstractmethod
    async def run(self, repo_path: str) -> list[Finding]:
        """Execute the scan and return normalized findings."""

    async def _run_subprocess(
        self,
        cmd: list[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> tuple[int, str, str]:
        """
        Run a subprocess asynchronously with timeout.
        Returns (return_code, stdout, stderr).
        """
        _timeout = timeout or settings.SCAN_TIMEOUT_SECONDS
        logger.info("[%s] Running: %s", self.name, " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=_timeout
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            logger.debug(
                "[%s] Exit code: %d | stdout: %d chars | stderr: %d chars",
                self.name,
                proc.returncode or 0,
                len(stdout),
                len(stderr),
            )
            return proc.returncode or 0, stdout, stderr

        except asyncio.TimeoutError:
            logger.error("[%s] Timed out after %ds", self.name, _timeout)
            if proc:  # type: ignore[possibly-undefined]
                proc.kill()
            return -1, "", f"Scanner timed out after {_timeout}s"

        except FileNotFoundError:
            logger.error("[%s] Binary not found: %s", self.name, self.binary)
            return -1, "", f"Binary not found: {self.binary}"

        except Exception as exc:
            logger.error("[%s] Unexpected error: %s", self.name, exc)
            return -1, "", str(exc)

    @staticmethod
    def _safe_json_parse(raw: str) -> Optional[dict | list]:
        """Try to parse JSON; return None on failure."""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
