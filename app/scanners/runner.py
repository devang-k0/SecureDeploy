"""
Scanner orchestrator.
Discovers available scanners, runs them concurrently, merges and deduplicates findings.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter

from app.models import Finding, ScanResult, ScanStatus, ScanSummary, Severity
from app.scanners.bandit_scanner import BanditScanner
from app.scanners.base import BaseScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.pip_audit_scanner import PipAuditScanner
from app.scanners.semgrep_scanner import SemgrepScanner

logger = logging.getLogger(__name__)

# Severity sort order (lower = more critical)
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# All registered scanner classes
ALL_SCANNERS: list[type[BaseScanner]] = [
    SemgrepScanner,
    BanditScanner,
    PipAuditScanner,
    GitleaksScanner,
]


async def run_all_scanners(
    repo_path: str,
    scan_result: ScanResult,
) -> list[Finding]:
    """
    Run all available scanners concurrently, merge results, and update scan_result
    with progress information.
    """
    # Discover available scanners
    scanners: list[BaseScanner] = []
    for cls in ALL_SCANNERS:
        instance = cls()
        if instance.is_available():
            scanners.append(instance)
            logger.info("Scanner available: %s", instance.name)
        else:
            logger.warning("Scanner not available: %s", instance.name)

    if not scanners:
        logger.error("No scanners available!")
        scan_result.phase_message = "No scanners are installed. Please install at least one scanner."
        return []

    scan_result.status = ScanStatus.SCANNING
    scanner_names = [s.name for s in scanners]
    scan_result.phase_message = f"Running scanners: {', '.join(scanner_names)}"

    # Run all scanners concurrently
    tasks = [_run_single_scanner(s, repo_path) for s in scanners]
    results = await asyncio.gather(*tasks)

    # Merge all findings
    all_findings: list[Finding] = []
    scanners_used: list[str] = []

    for scanner, findings in zip(scanners, results):
        if findings:
            all_findings.extend(findings)
            scanners_used.append(scanner.name)
        else:
            scanners_used.append(f"{scanner.name} (0 findings)")

    # Deduplicate by (file, line, rule_id)
    all_findings = _deduplicate(all_findings)

    # Sort: critical first, then by file path
    all_findings.sort(
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            f.file_path or "",
            f.line_start or 0,
        )
    )

    # Re-index IDs after dedup + sort
    for idx, finding in enumerate(all_findings):
        finding.id = f"F{idx + 1:04d}"

    # Build summary
    scan_result.summary = _build_summary(all_findings, scanners_used)
    scan_result.findings = all_findings

    logger.info(
        "Scan complete: %d findings from %d scanners",
        len(all_findings),
        len(scanners),
    )
    return all_findings


async def _run_single_scanner(
    scanner: BaseScanner, repo_path: str
) -> list[Finding]:
    """Run a single scanner and catch exceptions to prevent one failure from
    stopping the entire scan."""
    try:
        return await scanner.run(repo_path)
    except Exception as exc:
        logger.error("Scanner %s crashed: %s", scanner.name, exc, exc_info=True)
        return []


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on file + line + rule_id."""
    seen: set[tuple] = set()
    unique: list[Finding] = []

    for f in findings:
        key = (f.file_path, f.line_start, f.rule_id, f.category)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    removed = len(findings) - len(unique)
    if removed:
        logger.info("Removed %d duplicate findings", removed)

    return unique


def _build_summary(findings: list[Finding], scanners_used: list[str]) -> ScanSummary:
    """Build a structured summary of scan results."""
    sev_counts = Counter(f.severity for f in findings)
    cat_counts = Counter(f.category.value for f in findings)

    # Top affected files
    file_counts = Counter(f.file_path for f in findings if f.file_path)
    top_files = [fp for fp, _ in file_counts.most_common(10)]

    return ScanSummary(
        total_findings=len(findings),
        critical=sev_counts.get(Severity.CRITICAL, 0),
        high=sev_counts.get(Severity.HIGH, 0),
        medium=sev_counts.get(Severity.MEDIUM, 0),
        low=sev_counts.get(Severity.LOW, 0),
        info=sev_counts.get(Severity.INFO, 0),
        by_category=dict(cat_counts),
        scanners_used=scanners_used,
        top_files=top_files,
    )
