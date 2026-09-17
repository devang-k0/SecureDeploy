"""
Gitleaks scanner integration.
Runs `gitleaks detect` with redaction and normalizes output into Finding objects.
Secret values are NEVER stored or logged.
"""

from __future__ import annotations

import logging
import os
import tempfile

from app.models import Category, Finding, Severity
from app.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class GitleaksScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def binary(self) -> str:
        return "gitleaks"

    async def run(self, repo_path: str) -> list[Finding]:
        if not self.is_available():
            logger.warning("Gitleaks is not installed — skipping")
            return []

        # Write results to a temp file to avoid stdout issues
        report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks_")
        os.close(report_fd)

        try:
            code, stdout, stderr = await self._run_subprocess(
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    repo_path,
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
                    "--redact",
                    "--no-git",
                    "--exit-code",
                    "0",
                ]
            )

            if code < 0:
                logger.error("Gitleaks failed: %s", stderr)
                return []

            # Read the report file
            if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
                logger.info("Gitleaks found no secrets")
                return []

            with open(report_path, "r", encoding="utf-8") as f:
                raw = f.read()

            data = self._safe_json_parse(raw)
            if not data or not isinstance(data, list):
                logger.warning("Gitleaks report is not a valid JSON array")
                return []

            findings: list[Finding] = []
            for idx, item in enumerate(data):
                rule_id = item.get("RuleID", "unknown-rule")
                description = item.get("Description", "Potential secret detected")
                file_path = item.get("File", "")
                line = item.get("StartLine", item.get("Line"))

                # NEVER include the actual secret — only the redacted version
                match = item.get("Match", "")
                # Further redact: keep only first 4 and last 4 chars if long enough
                if len(match) > 12:
                    redacted_match = match[:4] + "****" + match[-4:]
                else:
                    redacted_match = "****REDACTED****"

                findings.append(
                    Finding(
                        id=f"gitleaks-{idx + 1}",
                        scanner=self.name,
                        category=Category.SECRET,
                        severity=Severity.HIGH,
                        title=f"Secret detected: {description}",
                        description=(
                            f"A potential {description.lower()} was found in {file_path}. "
                            f"Hardcoded secrets in source code can lead to unauthorized access."
                        ),
                        file_path=file_path,
                        line_start=line,
                        code_snippet=f"[REDACTED] {redacted_match}",
                        rule_id=rule_id,
                        fix_suggestion=(
                            "Remove the hardcoded secret and use environment variables "
                            "or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). "
                            "Rotate the exposed credential immediately."
                        ),
                        reference_urls=[
                            "https://github.com/gitleaks/gitleaks",
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                        ],
                    )
                )

            logger.info("Gitleaks found %d potential secrets", len(findings))
            return findings

        finally:
            # Always clean up the temp report
            if os.path.exists(report_path):
                os.unlink(report_path)
