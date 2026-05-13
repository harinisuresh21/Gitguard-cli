from __future__ import annotations

import json
import os
from pathlib import Path

from gitguard.core.models import (
    AIAuditResult,
    DependencyAnalysisResult,
    ObfuscationAnalysisResult,
    SandboxResult,
    ScanAssessment,
)
from gitguard.core.runtime_analysis import truncate_readme_text

GEMINI_MODEL_NAME = "gemini-2.5-flash"


class AIAuditError(RuntimeError):
    """Raised when optional AI audit cannot complete cleanly."""


def load_readme_context(checkout_root: Path) -> str | None:
    for candidate in ("README.md", "README.MD", "readme.md"):
        path = checkout_root / candidate
        if not path.exists():
            continue
        return truncate_readme_text(path.read_text(encoding="utf-8", errors="replace"))
    return None


def run_ai_audit(
    readme_text: str | None,
    dependency_result: DependencyAnalysisResult,
    obfuscation_result: ObfuscationAnalysisResult,
    runtime_assessment: ScanAssessment,
    sandbox_result: SandboxResult | None,
) -> AIAuditResult | None:
    if not os.getenv("GEMINI_API_KEY"):
        return None

    try:
        from google import genai
        from google.genai import types
    except ImportError as error:
        raise AIAuditError("google-genai is required for AI audit but is not installed.") from error

    prompt = _build_prompt(
        readme_text=readme_text,
        dependency_result=dependency_result,
        obfuscation_result=obfuscation_result,
        runtime_assessment=runtime_assessment,
        sandbox_result=sandbox_result,
    )
    schema = {
        "type": "OBJECT",
        "required": ["verdict_recommendation", "reasoning", "evidence_summary"],
        "properties": {
            "verdict_recommendation": {"type": "STRING"},
            "reasoning": {"type": "STRING"},
            "evidence_summary": {"type": "STRING"},
        },
    }

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    response = client.models.generate_content(
        model=GEMINI_MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=(
                "You are an expert malware analyst. Your job is to find logical contradictions "
                "between a tool's stated purpose and its runtime and static behavior."
            ),
            temperature=0.1,
            response_mime_type="application/json",
            response_schema=schema,
        ),
    )
    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, dict):
        payload = parsed
    else:
        payload = json.loads(response.text)
    if not isinstance(payload, dict):
        raise AIAuditError("AI audit returned an unparseable JSON payload.")

    verdict_recommendation = str(payload.get("verdict_recommendation", "UNKNOWN"))
    reasoning = str(payload.get("reasoning", "")).strip()
    evidence_summary = str(payload.get("evidence_summary", "")).strip()
    return AIAuditResult(
        verdict_recommendation=verdict_recommendation,
        reasoning=reasoning,
        evidence_summary=evidence_summary,
        raw_json=payload,
        model_name=GEMINI_MODEL_NAME,
    )


def _build_prompt(
    readme_text: str | None,
    dependency_result: DependencyAnalysisResult,
    obfuscation_result: ObfuscationAnalysisResult,
    runtime_assessment: ScanAssessment,
    sandbox_result: SandboxResult | None,
) -> str:
    evidence_lines = [
        f"Deterministic verdict: {runtime_assessment.verdict}",
        f"Deterministic summary: {runtime_assessment.summary}",
        f"Dependency findings: {len(dependency_result.findings)}",
        f"Obfuscation findings: {len(obfuscation_result.findings)}",
        f"Coverage: {runtime_assessment.coverage}",
    ]
    evidence_lines.extend(f"- {finding.message}" for finding in dependency_result.findings[:10])
    evidence_lines.extend(f"- {finding.message}" for finding in obfuscation_result.findings[:10])
    evidence_lines.extend(f"- {line}" for line in runtime_assessment.evidence[:10])

    runtime_summary = "No sandbox runtime telemetry was collected."
    if sandbox_result is not None:
        request_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "request")
        websocket_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "websocket")
        permission_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "permission")
        file_nav_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "file_navigation")
        runtime_summary = (
            f"Requests={request_count}, WebSockets={websocket_count}, "
            f"Permissions={permission_count}, FileNavigations={file_nav_count}, "
            f"Coverage={sandbox_result.coverage}"
        )

    return "\n".join(
        [
            "Repository README context:",
            readme_text or "README not present.",
            "",
            "Runtime summary:",
            runtime_summary,
            "",
            "Evidence:",
            *evidence_lines,
            "",
            "Return JSON only.",
        ]
    )
