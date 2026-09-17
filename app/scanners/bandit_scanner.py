"""
Bandit scanner integration.
Runs `bandit -r <path> -f json` and normalizes output into Finding objects.
"""

from __future__ import annotations

import logging

from app.models import Category, Finding, Severity
from app.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_CONFIDENCE_BOOST = {
    # When confidence is HIGH and severity is MEDIUM, escalate
    ("MEDIUM", "HIGH"): Severity.HIGH,
}


class BanditScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "bandit"

    @property
    def binary(self) -> str:
        return "bandit"

    async def run(self, repo_path: str) -> list[Finding]:
        if not self.is_available():
            logger.warning("Bandit is not installed — skipping")
            return []

        code, stdout, stderr = await self._run_subprocess(
            ["bandit", "-r", repo_path, "-f", "json", "-q", "--exit-zero"]
        )

        if code < 0:
            logger.error("Bandit failed: %s", stderr)
            return []

        data = self._safe_json_parse(stdout)
        if not data or not isinstance(data, dict):
            logger.warning("Bandit produced no parseable JSON output")
            return []

        results = data.get("results", [])
        findings: list[Finding] = []

        for idx, r in enumerate(results):
            sev_str = r.get("issue_severity", "LOW").upper()
            conf_str = r.get("issue_confidence", "LOW").upper()

            severity = _CONFIDENCE_BOOST.get(
                (sev_str, conf_str), _SEVERITY_MAP.get(sev_str, Severity.LOW)
            )

            # Build CWE from issue_cwe if available
            cwe = None
            cwe_data = r.get("issue_cwe", {})
            if isinstance(cwe_data, dict) and cwe_data.get("id"):
                cwe = f"CWE-{cwe_data['id']}"
            elif isinstance(cwe_data, (int, str)):
                cwe = f"CWE-{cwe_data}"

            findings.append(
                Finding(
                    id=f"bandit-{idx + 1}",
                    scanner=self.name,
                    category=Category.CODE_PATTERN,
                    severity=severity,
                    title=f"{r.get('test_id', 'B???')}: {r.get('test_name', 'Unknown')}",
                    description=r.get("issue_text", "No description."),
                    file_path=r.get("filename"),
                    line_start=r.get("line_number"),
                    line_end=r.get("end_col_offset"),  # sometimes present
                    code_snippet=r.get("code", ""),
                    rule_id=r.get("test_id"),
                    cwe=cwe,
                    fix_suggestion=_bandit_fix(r.get("test_id", "")),
                    reference_urls=[
                        f"https://bandit.readthedocs.io/en/latest/plugins/{r.get('test_id', '').lower()}.html"
                    ],
                )
            )

        logger.info("Bandit found %d issues", len(findings))
        return findings


def _bandit_fix(test_id: str) -> str:
    """Provide targeted fix suggestions for common Bandit rules."""
    _fixes = {
        "B101": "Remove assert statements used for security checks; use proper validation.",
        "B102": "Avoid using exec(). Use safer alternatives.",
        "B103": "Set restrictive permissions (e.g., 0o600) when creating files.",
        "B104": "Do not bind to 0.0.0.0 in production; use specific addresses.",
        "B105": "Move hardcoded passwords to environment variables.",
        "B106": "Move hardcoded passwords to environment variables.",
        "B107": "Move hardcoded passwords to environment variables.",
        "B108": "Avoid using /tmp directly; use tempfile.mkdtemp() instead.",
        "B110": "Do not use bare 'except: pass'; handle exceptions properly.",
        "B301": "Avoid pickle with untrusted data; use json or safer formats.",
        "B303": "Use strong hashing algorithms (SHA-256+) instead of MD5/SHA-1.",
        "B307": "Avoid eval(). Parse data with json.loads() or ast.literal_eval().",
        "B311": "Use secrets.choice() or secrets.token_* for security-sensitive randomness.",
        "B320": "Use defusedxml to prevent XML injection attacks.",
        "B324": "Use hashlib.sha256() or stronger instead of MD5/SHA-1.",
        "B501": "Do not disable SSL verification; use verify=True.",
        "B502": "Use modern TLS (TLSv1.2+) instead of deprecated SSL versions.",
        "B506": "Use yaml.safe_load() instead of yaml.load().",
        "B608": "Use parameterized queries to prevent SQL injection.",
        "B701": "Use Jinja2 autoescape=True to prevent XSS.",
    }
    return _fixes.get(test_id, "Review the finding and apply secure coding best practices.")
