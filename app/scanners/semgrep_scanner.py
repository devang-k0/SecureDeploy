"""
Semgrep scanner integration.
Runs `semgrep scan --config auto --json` and normalizes output into Finding objects.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.models import Category, Finding, Severity
from app.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Map Semgrep severity strings to our enum
_SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}


class SemgrepScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def binary(self) -> str:
        return "semgrep"

    async def run(self, repo_path: str) -> list[Finding]:
        if not self.is_available():
            logger.warning("Semgrep is not installed — skipping")
            return []

        code, stdout, stderr = await self._run_subprocess(
            ["semgrep", "scan", "--config", "auto", "--json", "--quiet", repo_path]
        )

        # Semgrep returns exit code 1 when findings exist, which is expected
        if code < 0:
            logger.error("Semgrep failed: %s", stderr)
            return []

        data = self._safe_json_parse(stdout)
        if not data or not isinstance(data, dict):
            logger.warning("Semgrep produced no parseable JSON output")
            return []

        results = data.get("results", [])
        findings: list[Finding] = []

        for idx, r in enumerate(results):
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})

            # Extract CWE
            cwe: Optional[str] = None
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, list) and cwe_list:
                cwe = cwe_list[0] if isinstance(cwe_list[0], str) else str(cwe_list[0])
            elif isinstance(cwe_list, str):
                cwe = cwe_list

            # Extract references
            refs = metadata.get("references", [])
            if isinstance(refs, str):
                refs = [refs]
            refs = [r for r in refs if isinstance(r, str) and (r.startswith("http://") or r.startswith("https://"))]

            sev_str = extra.get("severity", "INFO").upper()
            severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

            findings.append(
                Finding(
                    id=f"semgrep-{idx + 1}",
                    scanner=self.name,
                    category=Category.CODE_PATTERN,
                    severity=severity,
                    title=r.get("check_id", "Unknown Rule"),
                    description=extra.get("message", "No description available."),
                    file_path=r.get("path"),
                    line_start=r.get("start", {}).get("line"),
                    line_end=r.get("end", {}).get("line"),
                    code_snippet=extra.get("lines", ""),
                    rule_id=r.get("check_id"),
                    cwe=cwe,
                    fix_suggestion=extra.get("fix")
                    or metadata.get("fix")
                    or _generate_fix_hint(extra.get("message", "")),
                    reference_urls=refs[:5],
                )
            )

        logger.info("Semgrep found %d issues", len(findings))
        return findings


def _generate_fix_hint(message: str) -> str:
    """Generate a basic fix hint from the finding message."""
    msg_lower = message.lower()
    if "sql" in msg_lower and "inject" in msg_lower:
        return "Use parameterized queries instead of string concatenation."
    if "xss" in msg_lower or "cross-site" in msg_lower:
        return "Sanitize and escape user input before rendering in HTML."
    if "deserializ" in msg_lower:
        return "Avoid deserializing untrusted data. Use safe alternatives like json.loads()."
    if "hardcoded" in msg_lower or "password" in msg_lower:
        return "Move secrets to environment variables or a secrets manager."
    if "eval" in msg_lower or "exec" in msg_lower:
        return "Avoid eval/exec with user input. Use safer alternatives."
    return "Review the flagged code and apply the recommended secure coding practice."
