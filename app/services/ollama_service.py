"""
Ollama LLM service — optional AI triage of scan findings.
Calls local Ollama HTTP API to prioritize and explain findings in plain language.
Gracefully degrades if Ollama is not available.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

from app.config import settings
from app.models import Finding, Severity

logger = logging.getLogger(__name__)


async def is_ollama_available() -> bool:
    """Check if Ollama is running and the configured model is available."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OLLAMA_URL}/api/tags")
            if resp.status_code != 200:
                return False
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            # Check for model name (with or without :latest tag)
            model = settings.OLLAMA_MODEL
            available = any(
                m == model or m.startswith(f"{model}:") for m in models
            )
            if not available:
                logger.info(
                    "Ollama is running but model '%s' not found. Available: %s",
                    model,
                    models,
                )
            return available
    except Exception as exc:
        logger.info("Ollama not available: %s", exc)
        return False


async def analyze_findings(findings: list[Finding]) -> Optional[str]:
    """
    Send findings to Ollama for AI triage.
    Returns a plain-language analysis string, or None if unavailable.
    """
    if not findings:
        return None

    if not await is_ollama_available():
        logger.info("Ollama not available — skipping AI analysis")
        return None

    try:
        # Build a concise summary for the LLM (don't send all code snippets)
        findings_summary = _prepare_findings_for_llm(findings)
        prompt = _build_prompt(findings_summary)

        async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2000,
                    },
                },
            )

            if resp.status_code != 200:
                logger.warning(
                    "Ollama returned status %d: %s", resp.status_code, resp.text[:200]
                )
                return None

            data = resp.json()
            analysis = data.get("response", "").strip()

            if not analysis:
                logger.warning("Ollama returned empty response")
                return None

            logger.info("AI analysis complete (%d chars)", len(analysis))
            return analysis

    except httpx.TimeoutException:
        logger.warning("Ollama request timed out after %ds", settings.OLLAMA_TIMEOUT)
        return None
    except Exception as exc:
        logger.warning("Ollama analysis failed: %s", exc)
        return None


def _prepare_findings_for_llm(findings: list[Finding]) -> list[dict]:
    """Prepare a concise representation of findings for the LLM."""
    summaries = []
    # Send at most 30 findings to avoid token limits
    for f in findings[:30]:
        entry: dict = {
            "id": f.id,
            "severity": f.severity.value,
            "category": f.category.value,
            "title": f.title,
            "description": f.description[:200],
            "file": f.file_path or "N/A",
        }
        if f.cwe:
            entry["cwe"] = f.cwe
        # Never send code snippets for secrets
        if f.category.value != "secret" and f.code_snippet:
            entry["code"] = f.code_snippet[:150]
        summaries.append(entry)
    return summaries


def _build_prompt(findings_summary: list[dict]) -> str:
    """Build the LLM prompt for triage analysis."""
    findings_json = json.dumps(findings_summary, indent=2)

    return f"""You are a senior application security engineer. Analyze these security scan findings and provide a clear, actionable executive summary.

FINDINGS:
{findings_json}

Please provide:
1. **Executive Summary** (2-3 sentences): What is the overall security posture? How urgent is remediation?
2. **Top Priority Issues** (numbered list): List the most critical issues that need immediate attention, explaining WHY each matters in plain language a developer can understand.
3. **Quick Wins** (numbered list): Easy fixes that would reduce risk quickly.
4. **Recommendations**: Concrete next steps for the development team.

Rules:
- Write in plain language, not security jargon
- Focus on real-world impact (what could an attacker do?)
- Be specific about what to fix and how
- Do NOT repeat the raw finding data — synthesize and prioritize
- Keep the entire response under 800 words
"""
