"""
Scanner orchestrator.
Discovers available scanners, runs them concurrently, merges and deduplicates findings.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter

from app.models import Category, Finding, ScanResult, ScanStatus, ScanSummary, Severity
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

    # Deduplicate by (file, line, category)
    all_findings = _deduplicate(all_findings)

    # Enrich findings with Attack Types and Risk Explanations
    for finding in all_findings:
        _enrich_finding(finding)

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
    """Merge findings based on file + line + category."""
    grouped: dict[tuple, Finding] = {}

    for f in findings:
        # Group by file, line, and category. Treat missing line as 0 for grouping.
        key = (f.file_path, f.line_start or 0, f.category)
        if key not in grouped:
            grouped[key] = f
        else:
            existing = grouped[key]
            # Merge scanners
            if f.scanner not in existing.scanner:
                existing.scanner += f", {f.scanner}"
            # Merge reference URLs
            for url in f.reference_urls:
                if url not in existing.reference_urls:
                    existing.reference_urls.append(url)
            # Take the highest severity
            if _SEVERITY_ORDER.get(f.severity, 99) < _SEVERITY_ORDER.get(existing.severity, 99):
                existing.severity = f.severity
            # Use CWE if existing doesn't have it
            if not existing.cwe and f.cwe:
                existing.cwe = f.cwe

    unique = list(grouped.values())
    removed = len(findings) - len(unique)
    if removed:
        logger.info("Merged %d duplicate findings", removed)

    return unique

def _enrich_finding(finding: Finding):
    """Populate attack_type and risk_explanation statically if not already set."""
    if finding.category == Category.SECRET:
        finding.attack_type = "Credential Exposure"
        finding.risk_explanation = "Allows attackers to impersonate users, access private repositories, or breach databases."
        return

    # A simple mapping of CWE to Attack Type and Risk
    cwe_map = {
        "CWE-79": ("Cross-Site Scripting (XSS)", "Attackers can execute arbitrary JavaScript in victims' browsers, stealing sessions."),
        "CWE-89": ("SQL Injection", "Attackers can bypass authentication or execute arbitrary database queries, leading to data loss/breach."),
        "CWE-22": ("Path Traversal", "Attackers can read sensitive files (like /etc/passwd) on the server."),
        "CWE-78": ("OS Command Injection", "Attackers can execute arbitrary shell commands on the server host."),
        "CWE-312": ("Cleartext Storage of Sensitive Information", "Exposes credentials or PII if the storage medium is compromised."),
        "CWE-327": ("Broken or Risky Cryptographic Algorithm", "Weak crypto can be cracked, exposing data in transit or at rest."),
        "CWE-918": ("Server-Side Request Forgery (SSRF)", "Attackers can make requests on behalf of the server, accessing internal networks."),
        "CWE-94": ("Code Injection", "Allows arbitrary code execution on the server."),
        "CWE-502": ("Insecure Deserialization", "Can lead to remote code execution when un-pickling or deserializing untrusted data."),
        "CWE-352": ("Cross-Site Request Forgery (CSRF)", "Attackers can perform actions on behalf of an authenticated user."),
    }

    # Common rule mapping as fallback
    rule_map = {
        "B101": ("Improper Validation", "Using assert for validation can be bypassed if Python is run in optimized mode (-O)."),
        "B102": ("Code Injection", "exec() allows arbitrary python code execution."),
        "B104": ("Network Exposure", "Binding to all interfaces (0.0.0.0) may expose internal services to the public internet."),
        "B108": ("Insecure Temp File", "Using hardcoded /tmp paths can lead to symlink attacks or data exposure."),
        "B501": ("Man-in-the-Middle (MitM)", "Disabling SSL verification allows attackers to intercept or modify traffic."),
        "B608": ("SQL Injection", "String formatting in SQL queries allows attackers to execute arbitrary queries."),
    }

    if finding.cwe and finding.cwe in cwe_map:
        attack, risk = cwe_map[finding.cwe]
        if not finding.attack_type:
            finding.attack_type = attack
        if not finding.risk_explanation:
            finding.risk_explanation = risk
    elif finding.rule_id and finding.rule_id in rule_map:
        attack, risk = rule_map[finding.rule_id]
        if not finding.attack_type:
            finding.attack_type = attack
        if not finding.risk_explanation:
            finding.risk_explanation = risk
    else:
        if not finding.attack_type:
            finding.attack_type = "Security Misconfiguration"
        if not finding.risk_explanation:
            finding.risk_explanation = "Violates secure coding best practices, potentially allowing unauthorized access or unstable behavior."



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
