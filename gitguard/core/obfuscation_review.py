from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path
import re

from gitguard.core.models import ObfuscationAnalysisResult, ObfuscationFinding

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".html",
}
MAX_FILE_SIZE_BYTES = 512_000
MIN_ENTROPY_STRING_LENGTH = 24
HIGH_ENTROPY_THRESHOLD = 4.5
TEXT_LITERAL_PATTERN = re.compile(r"['\"]([A-Za-z0-9+/=_-]{24,})['\"]")
JS_DECODE_PATTERNS = (
    ("atob_chain", re.compile(r"\batob\s*\(", re.IGNORECASE)),
    ("base64_buffer_chain", re.compile(r"Buffer\.from\s*\([^)]*base64", re.IGNORECASE)),
    ("nested_eval", re.compile(r"\beval\s*\(\s*.*\b(atob|Buffer\.from|decodeURIComponent)\b", re.IGNORECASE)),
    ("function_constructor", re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)),
)


def analyze_obfuscation(checkout_root: Path) -> ObfuscationAnalysisResult:
    findings: list[ObfuscationFinding] = []
    warnings: list[str] = []
    for path in sorted(checkout_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                warnings.append(f"Skipped large source file {path.relative_to(checkout_root).as_posix()}.")
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            warnings.append(f"Failed to read {path.relative_to(checkout_root).as_posix()}: {error}.")
            continue

        relative_path = path.relative_to(checkout_root).as_posix()
        findings.extend(_scan_text_literals(relative_path, source))
        if path.suffix.lower() == ".py":
            findings.extend(_scan_python_source(relative_path, source))
        else:
            findings.extend(_scan_script_source(relative_path, source))
    return ObfuscationAnalysisResult(findings=findings, warnings=warnings)


def _scan_text_literals(relative_path: str, source: str) -> list[ObfuscationFinding]:
    findings: list[ObfuscationFinding] = []
    for match in TEXT_LITERAL_PATTERN.finditer(source):
        literal = match.group(1)
        if _shannon_entropy(literal) <= HIGH_ENTROPY_THRESHOLD:
            continue
        findings.append(
            ObfuscationFinding(
                severity="MEDIUM",
                category="high_entropy_string",
                file_path=relative_path,
                message="High-entropy string literal may indicate an encoded payload.",
                snippet=literal[:120],
            )
        )
    return findings


def _scan_python_source(relative_path: str, source: str) -> list[ObfuscationFinding]:
    findings: list[ObfuscationFinding] = []
    try:
        tree = ast.parse(source, filename=relative_path)
    except SyntaxError as error:
        return [
            ObfuscationFinding(
                severity="LOW",
                category="parse_warning",
                file_path=relative_path,
                message=f"Python source could not be parsed cleanly: {error.msg}.",
                snippet=source.splitlines()[max(error.lineno or 1, 1) - 1][:120] if source.splitlines() else "",
            )
        ]

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dotted_name = _get_dotted_name(node.func)
            if dotted_name in {"eval", "exec"} and _contains_nested_eval_argument(node):
                findings.append(
                    ObfuscationFinding(
                        severity="HIGH",
                        category="nested_eval_exec",
                        file_path=relative_path,
                        message=f"Nested {dotted_name} pattern detected.",
                        snippet=ast.get_source_segment(source, node) or dotted_name,
                    )
                )
            if dotted_name.endswith("b64decode") and _contains_exec_parent(tree, node):
                findings.append(
                    ObfuscationFinding(
                        severity="HIGH",
                        category="decode_exec_chain",
                        file_path=relative_path,
                        message="Base64 decode output flows into eval/exec style execution.",
                        snippet=ast.get_source_segment(source, node) or dotted_name,
                    )
                )
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= MIN_ENTROPY_STRING_LENGTH and _shannon_entropy(node.value) > HIGH_ENTROPY_THRESHOLD:
                findings.append(
                    ObfuscationFinding(
                        severity="MEDIUM",
                        category="high_entropy_string",
                        file_path=relative_path,
                        message="High-entropy Python string literal may hide encoded content.",
                        snippet=node.value[:120],
                    )
                )
    return _deduplicate_findings(findings)


def _scan_script_source(relative_path: str, source: str) -> list[ObfuscationFinding]:
    findings: list[ObfuscationFinding] = []
    for category, pattern in JS_DECODE_PATTERNS:
        for match in pattern.finditer(source):
            snippet = source[max(match.start() - 40, 0): min(match.end() + 80, len(source))]
            severity = "HIGH" if category in {"nested_eval", "function_constructor"} else "MEDIUM"
            findings.append(
                ObfuscationFinding(
                    severity=severity,
                    category=category,
                    file_path=relative_path,
                    message=f"Suspicious script decode or dynamic execution pattern detected: {category}.",
                    snippet=snippet.strip(),
                )
            )
    return _deduplicate_findings(findings)


def _contains_nested_eval_argument(node: ast.Call) -> bool:
    for arg in node.args:
        if isinstance(arg, ast.Call):
            return True
        if isinstance(arg, ast.BinOp):
            return True
    return False


def _contains_exec_parent(tree: ast.AST, target: ast.Call) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted_name = _get_dotted_name(node.func)
        if dotted_name not in {"eval", "exec"}:
            continue
        for child in ast.walk(node):
            if child is target:
                return True
    return False


def _get_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return _entropy_with_logs(value)


def _entropy_with_logs(value: str) -> float:
    import math

    counts = Counter(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / len(value)
        entropy -= probability * math.log2(probability)
    return entropy


def _deduplicate_findings(findings: list[ObfuscationFinding]) -> list[ObfuscationFinding]:
    unique: list[ObfuscationFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.category, finding.file_path, finding.snippet)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
