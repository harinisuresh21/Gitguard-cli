from __future__ import annotations

import json
from pathlib import Path

from gitguard.core.models import (
    AIAuditResult,
    DependencyAnalysisResult,
    ObfuscationAnalysisResult,
    SandboxResult,
    ScanAssessment,
    ScanRecord,
)
from gitguard.core.state import get_reports_dir


def build_scan_report(
    record: ScanRecord,
    scans_file: Path,
    preflight,
    assessment: ScanAssessment,
    dependency_result: DependencyAnalysisResult | None,
    obfuscation_result: ObfuscationAnalysisResult,
    ai_audit_warning: str | None,
    ai_audit_result: AIAuditResult | None,
    sandbox_result: SandboxResult | None,
) -> dict[str, object]:
    report: dict[str, object] = {
        "scan_id": record.scan_id,
        "target_url": record.target_url,
        "timestamp": record.timestamp,
        "status": assessment.verdict.lower(),
        "verdict": assessment.verdict,
        "summary": assessment.summary,
        "evidence": assessment.evidence,
        "coverage": assessment.coverage,
        "state_file": str(scans_file),
        "host": {
            "os": record.host_os,
            "docker_status": preflight.docker_status,
            "ai_configured": bool(preflight.ai_key_present),
        },
        "static_analysis": {
            "dependency_guard": _serialize_dependency_result(dependency_result),
            "obfuscation_review": _serialize_obfuscation_result(obfuscation_result),
        },
    }
    if ai_audit_result is not None or ai_audit_warning is not None:
        report["ai_audit"] = {
            "warning": ai_audit_warning,
            "result": None if ai_audit_result is None else {
                "model_name": ai_audit_result.model_name,
                "verdict_recommendation": ai_audit_result.verdict_recommendation,
                "reasoning": ai_audit_result.reasoning,
                "evidence_summary": ai_audit_result.evidence_summary,
                "raw_json": ai_audit_result.raw_json,
            },
        }
    if sandbox_result is not None:
        report["runtime_analysis"] = {
            "image": sandbox_result.image,
            "container_id": sandbox_result.container_id,
            "exit_code": sandbox_result.exit_code,
            "runtime_seconds": sandbox_result.runtime_seconds,
            "coverage": sandbox_result.coverage,
            "coverage_reason": sandbox_result.coverage_reason,
            "entrypoint": sandbox_result.entrypoint,
            "warnings": sandbox_result.warnings,
            "progress_messages": sandbox_result.progress_messages,
            "telemetry_events": sandbox_result.telemetry_events,
        }
    return report


def write_scan_report(scan_id: str, report: dict[str, object]) -> Path:
    report_path = get_reports_dir() / f"{scan_id}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report_path


def render_scan_report_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2)


def _serialize_dependency_result(result: DependencyAnalysisResult | None) -> dict[str, object] | None:
    if result is None:
        return None
    return {
        "manifests": result.manifests,
        "packages": result.packages,
        "package_count_by_ecosystem": result.package_count_by_ecosystem,
        "blocked": result.blocked,
        "warnings": result.warnings,
        "findings": [
            {
                "severity": finding.severity,
                "category": finding.category,
                "package_name": finding.package_name,
                "manifest_path": finding.manifest_path,
                "message": finding.message,
            }
            for finding in result.findings
        ],
    }


def _serialize_obfuscation_result(result: ObfuscationAnalysisResult) -> dict[str, object]:
    return {
        "warnings": result.warnings,
        "findings": [
            {
                "severity": finding.severity,
                "category": finding.category,
                "file_path": finding.file_path,
                "message": finding.message,
                "snippet": finding.snippet,
            }
            for finding in result.findings
        ],
    }
