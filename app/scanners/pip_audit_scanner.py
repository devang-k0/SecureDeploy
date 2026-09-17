"""
pip-audit scanner integration.
Detects requirements files and runs `pip-audit -r <file> -f json`.
"""

from __future__ import annotations

import logging
import os

from app.models import Category, Finding, Severity
from app.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Filenames that pip-audit can work with
_REQ_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "dev-requirements.txt",
    "requirements-prod.txt",
]


class PipAuditScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "pip-audit"

    @property
    def binary(self) -> str:
        return "pip-audit"

    async def run(self, repo_path: str) -> list[Finding]:
        if not self.is_available():
            logger.warning("pip-audit is not installed — skipping")
            return []

        # Find requirements files
        req_files = []
        for fname in _REQ_FILES:
            fpath = os.path.join(repo_path, fname)
            if os.path.isfile(fpath):
                req_files.append(fpath)

        if not req_files:
            logger.info("No requirements files found — skipping pip-audit")
            return []

        all_findings: list[Finding] = []
        finding_idx = 0

        for req_file in req_files:
            code, stdout, stderr = await self._run_subprocess(
                ["pip-audit", "-r", req_file, "-f", "json", "--progress-spinner=off"],
                cwd=repo_path,
            )

            if code < 0:
                logger.error("pip-audit failed for %s: %s", req_file, stderr)
                continue

            data = self._safe_json_parse(stdout)
            if not data:
                logger.warning("pip-audit produced no parseable output for %s", req_file)
                continue

            # pip-audit JSON can be a dict with "dependencies" or a list
            deps = data if isinstance(data, list) else data.get("dependencies", [])

            for dep in deps:
                vulns = dep.get("vulns", [])
                if not vulns:
                    continue

                pkg_name = dep.get("name", "unknown")
                pkg_version = dep.get("version", "?")

                for vuln in vulns:
                    finding_idx += 1
                    vuln_id = vuln.get("id", "UNKNOWN")
                    fix_versions = vuln.get("fix_versions", [])
                    desc = vuln.get("description", f"Vulnerability {vuln_id} in {pkg_name}")

                    # Estimate severity from vulnerability ID patterns
                    severity = _estimate_severity(vuln_id, desc)

                    fix_text = (
                        f"Upgrade {pkg_name} to version {', '.join(fix_versions)}."
                        if fix_versions
                        else f"Check for a patched version of {pkg_name} or find an alternative."
                    )

                    all_findings.append(
                        Finding(
                            id=f"pip-audit-{finding_idx}",
                            scanner=self.name,
                            category=Category.DEPENDENCY,
                            severity=severity,
                            title=f"{vuln_id}: {pkg_name}=={pkg_version}",
                            description=desc[:500],
                            file_path=os.path.basename(req_file),
                            rule_id=vuln_id,
                            fix_suggestion=fix_text,
                            reference_urls=_build_refs(vuln_id),
                        )
                    )

        logger.info("pip-audit found %d vulnerable dependencies", len(all_findings))
        return all_findings


def _estimate_severity(vuln_id: str, description: str) -> Severity:
    """Heuristic severity estimation from vuln IDs and descriptions."""
    desc_lower = description.lower()

    # Known critical patterns
    if any(kw in desc_lower for kw in ("remote code execution", "rce", "arbitrary code")):
        return Severity.CRITICAL
    if any(kw in desc_lower for kw in ("denial of service", "dos", "buffer overflow")):
        return Severity.HIGH
    if any(kw in desc_lower for kw in ("injection", "sqli", "xss")):
        return Severity.HIGH

    # GHSA advisories tend to be meaningful
    if vuln_id.startswith("GHSA-"):
        return Severity.HIGH

    # CVEs without more context default to medium
    if vuln_id.startswith("CVE-"):
        return Severity.MEDIUM

    return Severity.MEDIUM


def _build_refs(vuln_id: str) -> list[str]:
    """Build reference URLs for a vulnerability ID."""
    refs = []
    if vuln_id.startswith("CVE-"):
        refs.append(f"https://nvd.nist.gov/vuln/detail/{vuln_id}")
    if vuln_id.startswith("GHSA-"):
        refs.append(f"https://github.com/advisories/{vuln_id}")
    if vuln_id.startswith("PYSEC-"):
        refs.append(f"https://osv.dev/vulnerability/{vuln_id}")
    return refs
