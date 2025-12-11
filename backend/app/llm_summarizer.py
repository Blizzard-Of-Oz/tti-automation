import os
from typing import Any, Dict, List, Optional

from openai import OpenAI

from . import models

# If OPENAI_API_KEY is not set, client() will fail; we handle that below.
def _get_client() -> Optional[OpenAI]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    # The Python SDK will read OPENAI_API_KEY from env automatically,
    # so we don't need to pass it explicitly.
    return OpenAI()


def _build_prompt(vuln: models.Vulnerability, references: List[Dict[str, Any]]) -> str:
    ref_lines = []
    for ref in references[:8]:
        url = ref.get("url", "")
        rtype = ref.get("type", "")
        ref_lines.append(f"- [{rtype}] {url}")
    refs_text = "\n".join(ref_lines) or "No major vendor references available."

    description = vuln.description or "No description available."
    severity = vuln.severity or "UNKNOWN"
    cvss = vuln.cvss_score or 0.0

    prompt = f"""
You are a senior cybersecurity analyst.

Write a concise technical summary for the following vulnerability, targeting SOC / security engineering teams.

Requirements:
- 3 to 6 sentences.
- First sentence: what the vulnerability is and where it sits (component / product).
- Mention severity and CVSS briefly.
- Explain exploitation risk (what an attacker can do).
- End with a short remediation recommendation (patch, config, or mitigation).

Vulnerability details:
- CVE: {vuln.cve_id}
- Title: {vuln.title or "N/A"}
- Severity: {severity}
- CVSS: {cvss}
- Description: {description}

Key references:
{refs_text}
"""
    return prompt.strip()


def _fallback_summary(vuln: models.Vulnerability) -> str:
    """Used when no API key or OpenAI client is available."""
    severity = vuln.severity or "UNKNOWN"
    cvss = vuln.cvss_score or 0.0
    desc = (vuln.description or "").strip()
    if len(desc) > 400:
        desc = desc[:400] + "..."

    return (
        f"{vuln.cve_id} is a {severity} vulnerability (CVSS {cvss}) affecting "
        f"{vuln.title or 'one of the software components in your environment'}. "
        f"{desc or 'The official description has not been provided in the source data yet.'} "
        "Apply vendor patches or recommended mitigations as soon as they are available."
    )


def generate_llm_summary(vuln: models.Vulnerability) -> str:
    """
    Generate a human-readable summary for a vulnerability.
    - Uses OpenAI if OPENAI_API_KEY is set.
    - Falls back to a simple local summary if not.
    """
    # references are stored in vuln.llm_summary["references"] from Phase 5
    meta = vuln.llm_summary or {}
    references = meta.get("references", [])
    if not isinstance(references, list):
        references = []

    client = _get_client()
    if not client:
        return _fallback_summary(vuln)

    prompt = _build_prompt(vuln, references)

    try:
        # Use Responses API for text generation
        response = client.responses.create(
            model="gpt-5.1-mini",  # you can change this later
            input=prompt,
        )
        text = (response.output_text or "").strip()
        return text or _fallback_summary(vuln)
    except Exception:
        # In case of any API/network error, do not break the pipeline
        return _fallback_summary(vuln)
