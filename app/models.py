"""
Pydantic models for the normalized finding schema, scan requests, and scan results.
All scanner outputs are normalized into the Finding model.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, enum.Enum):
    CODE_PATTERN = "code_pattern"
    DEPENDENCY = "dependency"
    SECRET = "secret"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    CLONING = "cloning"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


class SourceType(str, enum.Enum):
    GIT_URL = "git_url"
    ZIP_UPLOAD = "zip_upload"
    LOCAL_PATH = "local_path"


# ---------------------------------------------------------------------------
# Normalized finding schema — shared by all scanners
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single security finding, normalized from any scanner."""

    id: str = Field(..., description="Unique finding ID (scanner_prefix + index)")
    scanner: str = Field(..., description="Scanner that produced this finding")
    category: Category
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = Field(
        None, description="Relevant code snippet (redacted for secrets)"
    )
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    fix_suggestion: Optional[str] = None
    reference_urls: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scan request / response
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    source_type: SourceType
    source_value: str = Field(
        ..., description="Git URL, local path, or filename for ZIP upload"
    )


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    scanners_used: list[str] = Field(default_factory=list)
    top_files: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    status: ScanStatus = ScanStatus.QUEUED
    source_type: SourceType
    source_value: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    phase_message: str = "Waiting to start..."
    findings: list[Finding] = Field(default_factory=list)
    summary: Optional[ScanSummary] = None
    ai_analysis: Optional[str] = None
    error_message: Optional[str] = None


class HistoryEntry(BaseModel):
    scan_id: str
    source_type: SourceType
    source_value: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: ScanStatus
    total_findings: int = 0
    critical: int = 0
    high: int = 0
