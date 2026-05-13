from __future__ import annotations

import ast
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from gitguard.core.models import DependencyAnalysisResult, DependencyFinding
from gitguard.core.state import get_state_dir

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


MANIFEST_NAMES = ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "package.json")
TOP_PYPI_CACHE_FILE = "top_pypi_packages.json"
TOP_NPM_CACHE_FILE = "top_npm_packages.json"
TOP_PYPI_SEED = (
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "flask",
    "django",
    "fastapi",
    "uvicorn",
    "pydantic",
    "pyyaml",
    "pytest",
    "setuptools",
    "pip",
    "wheel",
    "colorama",
    "rich",
    "typer",
    "docker",
    "psutil",
    "urllib3",
    "aiohttp",
    "httpx",
    "jinja2",
    "sqlalchemy",
    "boto3",
    "botocore",
    "matplotlib",
    "pillow",
    "torch",
    "transformers",
    "beautifulsoup4",
    "lxml",
    "celery",
    "redis",
    "cryptography",
    "click",
    "tqdm",
    "black",
    "mypy",
    "notebook",
    "ipython",
    "sphinx",
    "twine",
    "virtualenv",
    "poetry",
    "tomli",
    "opencv-python",
    "seaborn",
    "plotly",
    "grpcio",
)
PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+")
RECENT_PACKAGE_MAX_AGE_DAYS = 7
TOP_NPM_SEED = (
    "react",
    "react-dom",
    "next",
    "vue",
    "angular",
    "lodash",
    "axios",
    "express",
    "chalk",
    "commander",
    "typescript",
    "vite",
    "webpack",
    "esbuild",
    "rollup",
    "rxjs",
    "dotenv",
    "prettier",
    "eslint",
    "tailwindcss",
    "classnames",
    "dayjs",
    "moment",
    "firebase",
    "socket.io",
    "socket.io-client",
    "three",
    "zustand",
    "zod",
    "playwright",
)
NPM_LIFECYCLE_SCRIPT_NAMES = ("preinstall", "install", "postinstall", "prepare")
SUSPICIOUS_SCRIPT_PATTERN = re.compile(
    r"(curl|wget|Invoke-WebRequest|powershell|pwsh|bash|sh\s+-c|node\s+-e|python\s+-c|nc\s|ncat\s|certutil)",
    re.IGNORECASE,
)


class DependencyGuardError(RuntimeError):
    """Raised when static dependency analysis cannot complete safely."""


@dataclass(slots=True)
class PackageMetadata:
    latest_version: str | None
    latest_release_time: datetime | None


def run_dependency_guard(target_url: str) -> DependencyAnalysisResult:
    checkout_root = clone_repository_to_tempdir(target_url)
    try:
        return analyze_dependency_manifests(checkout_root)
    finally:
        cleanup_checkout(checkout_root)


def analyze_dependency_manifests(checkout_root: Path) -> DependencyAnalysisResult:
    manifests = _discover_manifests(checkout_root)
    findings: list[DependencyFinding] = []
    warnings: list[str] = []
    packages: set[str] = set()
    package_sources: dict[str, str] = {}
    package_count_by_ecosystem = {"python": 0, "node": 0}
    top_packages = _load_top_pypi_cache()
    top_npm_packages = _load_top_npm_cache()

    for manifest in manifests:
        relative_manifest = manifest.relative_to(checkout_root).as_posix()
        extracted_packages: list[str] = []
        ecosystem = "python"
        if manifest.name == "requirements.txt":
            extracted_packages = _parse_requirements_manifest(manifest)
        elif manifest.name == "pyproject.toml":
            extracted_packages = _parse_pyproject_manifest(manifest)
        elif manifest.name == "Pipfile":
            extracted_packages = _parse_pipfile_manifest(manifest)
        elif manifest.name == "setup.py":
            setup_result = _analyze_setup_manifest(manifest)
            extracted_packages = setup_result.packages
            findings.extend(
                DependencyFinding(
                    severity="HIGH",
                    category="setup_py_code_execution",
                    package_name=None,
                    manifest_path=relative_manifest,
                    message=message,
                )
                for message in setup_result.suspicious_calls
            )
        elif manifest.name == "package.json":
            ecosystem = "node"
            package_json_result = _analyze_package_json_manifest(manifest)
            extracted_packages = package_json_result.packages
            findings.extend(
                DependencyFinding(
                    severity="HIGH",
                    category="npm_lifecycle_script",
                    package_name=None,
                    manifest_path=relative_manifest,
                    message=message,
                )
                for message in package_json_result.suspicious_scripts
            )

        for package_name in extracted_packages:
            normalized_name = _normalize_package_name(package_name)
            if not normalized_name:
                continue
            packages.add(normalized_name)
            package_sources[normalized_name] = ecosystem
            package_count_by_ecosystem[ecosystem] += 1
            typo_target = _detect_typosquat(
                normalized_name,
                top_npm_packages if ecosystem == "node" else top_packages,
            )
            if typo_target is not None:
                findings.append(
                    DependencyFinding(
                        severity="CRITICAL",
                        category="npm_typosquatting" if ecosystem == "node" else "typosquatting",
                        package_name=normalized_name,
                        manifest_path=relative_manifest,
                        message=f"Package '{normalized_name}' closely matches popular package '{typo_target}'.",
                    )
                )

    for package_name in sorted(packages):
        try:
            metadata = (
                fetch_npm_package_metadata(package_name)
                if package_sources.get(package_name) == "node"
                else fetch_pypi_package_metadata(package_name)
            )
        except DependencyGuardError as error:
            warnings.append(str(error))
            continue

        if metadata.latest_release_time is not None:
            age = datetime.now(timezone.utc) - metadata.latest_release_time
            if age <= timedelta(days=RECENT_PACKAGE_MAX_AGE_DAYS):
                findings.append(
                    DependencyFinding(
                        severity="MEDIUM",
                        category="recent_publish",
                        package_name=package_name,
                        manifest_path="registry metadata",
                        message=(
                            f"Package '{package_name}' was published {age.days} day(s) ago in the public registry."
                        ),
                    )
                )
        if metadata.latest_version and _is_disproportionately_low_version(metadata.latest_version):
            findings.append(
                DependencyFinding(
                        severity="LOW",
                        category="low_version_reputation",
                        package_name=package_name,
                        manifest_path="registry metadata",
                        message=(
                            f"Package '{package_name}' has unusually early latest version '{metadata.latest_version}'."
                        ),
                    )
            )

    blocked = any(finding.severity in {"CRITICAL", "HIGH"} for finding in findings)
    return DependencyAnalysisResult(
        manifests=[manifest.relative_to(checkout_root).as_posix() for manifest in manifests],
        packages=sorted(packages),
        findings=findings,
        warnings=warnings,
        blocked=blocked,
        package_count_by_ecosystem=package_count_by_ecosystem,
    )


def fetch_pypi_package_metadata(package_name: str) -> PackageMetadata:
    request = Request(
        f"https://pypi.org/pypi/{package_name}/json",
        headers={"User-Agent": "GitGuard/0.1"},
    )
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise DependencyGuardError(f"PyPI metadata lookup failed for '{package_name}': HTTP {error.code}.") from error
    except URLError as error:
        raise DependencyGuardError(f"PyPI metadata lookup failed for '{package_name}': {error.reason}.") from error

    latest_version = None
    latest_release_time = None
    info = payload.get("info")
    if isinstance(info, dict):
        version = info.get("version")
        if isinstance(version, str):
            latest_version = version

    releases = payload.get("releases")
    if isinstance(releases, dict) and latest_version:
        files = releases.get(latest_version)
        if isinstance(files, list):
            release_times: list[datetime] = []
            for item in files:
                if not isinstance(item, dict):
                    continue
                raw_timestamp = item.get("upload_time_iso_8601")
                if not isinstance(raw_timestamp, str):
                    continue
                parsed = _parse_iso8601(raw_timestamp)
                if parsed is not None:
                    release_times.append(parsed)
            if release_times:
                latest_release_time = min(release_times)
    return PackageMetadata(latest_version=latest_version, latest_release_time=latest_release_time)


def fetch_npm_package_metadata(package_name: str) -> PackageMetadata:
    request = Request(
        f"https://registry.npmjs.org/{package_name}",
        headers={"User-Agent": "GitGuard/0.1"},
    )
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise DependencyGuardError(f"npm metadata lookup failed for '{package_name}': HTTP {error.code}.") from error
    except URLError as error:
        raise DependencyGuardError(f"npm metadata lookup failed for '{package_name}': {error.reason}.") from error

    latest_version = None
    latest_release_time = None
    dist_tags = payload.get("dist-tags")
    if isinstance(dist_tags, dict):
        latest = dist_tags.get("latest")
        if isinstance(latest, str):
            latest_version = latest
    times = payload.get("time")
    if isinstance(times, dict) and latest_version:
        raw_timestamp = times.get(latest_version)
        if isinstance(raw_timestamp, str):
            latest_release_time = _parse_iso8601(raw_timestamp)
    return PackageMetadata(latest_version=latest_version, latest_release_time=latest_release_time)


def clone_repository_to_tempdir(target_url: str) -> Path:
    state_dir = get_state_dir()
    checkout_root = Path(tempfile.mkdtemp(prefix="dep-guard-", dir=state_dir))
    command = ["git", "clone", "--depth", "1", target_url, str(checkout_root)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    except FileNotFoundError as error:
        shutil.rmtree(checkout_root, ignore_errors=True)
        raise DependencyGuardError("Git executable is required for dependency analysis.") from error
    except subprocess.TimeoutExpired as error:
        shutil.rmtree(checkout_root, ignore_errors=True)
        raise DependencyGuardError("Repository clone timed out during dependency analysis.") from error

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "unknown git clone failure"
        cleanup_checkout(checkout_root)
        raise DependencyGuardError(f"Repository clone failed during dependency analysis: {stderr}")
    return checkout_root


def cleanup_checkout(checkout_root: Path) -> None:
    shutil.rmtree(checkout_root, ignore_errors=True)


def _discover_manifests(checkout_root: Path) -> list[Path]:
    manifests: list[Path] = []
    for pattern in MANIFEST_NAMES:
        manifests.extend(checkout_root.rglob(pattern))
    manifests.sort()
    return manifests


def _parse_requirements_manifest(path: Path) -> list[str]:
    packages: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")) or "://" in line:
            continue
        candidate = _extract_requirement_name(line)
        if candidate:
            packages.append(candidate)
    return packages


def _parse_pyproject_manifest(path: Path) -> list[str]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    packages: list[str] = []

    project = data.get("project")
    if isinstance(project, dict):
        packages.extend(_extract_names_from_requirement_list(project.get("dependencies")))
        optional_dependencies = project.get("optional-dependencies")
        if isinstance(optional_dependencies, dict):
            for value in optional_dependencies.values():
                packages.extend(_extract_names_from_requirement_list(value))

    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            packages.extend(_extract_names_from_toml_package_map(poetry.get("dependencies")))
            packages.extend(_extract_names_from_toml_group(poetry.get("group")))
    return packages


def _parse_pipfile_manifest(path: Path) -> list[str]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    packages: list[str] = []
    packages.extend(_extract_names_from_toml_package_map(data.get("packages")))
    packages.extend(_extract_names_from_toml_package_map(data.get("dev-packages")))
    return packages


@dataclass(slots=True)
class PackageJsonAnalysisResult:
    packages: list[str]
    suspicious_scripts: list[str]


def _analyze_package_json_manifest(path: Path) -> PackageJsonAnalysisResult:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return PackageJsonAnalysisResult(packages=[], suspicious_scripts=[])
    packages: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        value = payload.get(key)
        if isinstance(value, dict):
            for package_name in value.keys():
                if isinstance(package_name, str):
                    packages.append(package_name)
    suspicious_scripts: list[str] = []
    scripts = payload.get("scripts")
    if isinstance(scripts, dict):
        for script_name in NPM_LIFECYCLE_SCRIPT_NAMES:
            command = scripts.get(script_name)
            if not isinstance(command, str):
                continue
            if SUSPICIOUS_SCRIPT_PATTERN.search(command):
                suspicious_scripts.append(
                    f"Suspicious npm lifecycle script '{script_name}' detected with command: {command}"
                )
    return PackageJsonAnalysisResult(packages=packages, suspicious_scripts=suspicious_scripts)


def _extract_names_from_toml_group(group: object) -> list[str]:
    packages: list[str] = []
    if not isinstance(group, dict):
        return packages
    for value in group.values():
        if not isinstance(value, dict):
            continue
        packages.extend(_extract_names_from_toml_package_map(value.get("dependencies")))
    return packages


def _extract_names_from_toml_package_map(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    packages = []
    for package_name in value.keys():
        if isinstance(package_name, str) and _normalize_package_name(package_name) != "python":
            packages.append(package_name)
    return packages


def _extract_names_from_requirement_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    packages: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        candidate = _extract_requirement_name(item)
        if candidate:
            packages.append(candidate)
    return packages


@dataclass(slots=True)
class SetupAnalysisResult:
    packages: list[str]
    suspicious_calls: list[str]


def _analyze_setup_manifest(path: Path) -> SetupAnalysisResult:
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(path))
    packages: list[str] = []
    suspicious_calls: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_setup_call(node):
            packages.extend(_extract_setup_packages(node))
        if isinstance(node, ast.Call):
            suspicious_target = _match_suspicious_call(node)
            if suspicious_target is not None:
                suspicious_calls.append(
                    f"Suspicious executable call '{suspicious_target}' detected in setup.py at line {node.lineno}."
                )
    return SetupAnalysisResult(packages=packages, suspicious_calls=suspicious_calls)


def _extract_setup_packages(call: ast.Call) -> list[str]:
    packages: list[str] = []
    for keyword in call.keywords:
        if keyword.arg == "install_requires":
            packages.extend(_extract_string_list(keyword.value))
        elif keyword.arg == "extras_require" and isinstance(keyword.value, ast.Dict):
            for value in keyword.value.values:
                packages.extend(_extract_string_list(value))
    return packages


def _extract_string_list(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    packages: list[str] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            candidate = _extract_requirement_name(element.value)
            if candidate:
                packages.append(candidate)
    return packages


def _is_setup_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id == "setup"
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return node.func.attr == "setup"
    return False


def _match_suspicious_call(node: ast.Call) -> str | None:
    dotted_name = _get_dotted_name(node.func)
    if dotted_name in {"os.system", "os.popen"}:
        return dotted_name
    if dotted_name.startswith("subprocess."):
        return dotted_name
    if dotted_name.startswith("urllib.request."):
        return dotted_name
    return None


def _get_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _extract_requirement_name(requirement: str) -> str | None:
    cleaned = requirement.strip()
    if not cleaned or cleaned.startswith(("-", "--")):
        return None
    candidate = PACKAGE_NAME_PATTERN.match(cleaned)
    if candidate is None:
        return None
    package_name = candidate.group(0)
    if "[" in package_name:
        package_name = package_name.split("[", 1)[0]
    return package_name or None


def _normalize_package_name(package_name: str) -> str:
    return re.sub(r"[-_.]+", "-", package_name.strip().lower())


def _load_top_pypi_cache() -> set[str]:
    cache_path = get_state_dir() / TOP_PYPI_CACHE_FILE
    if cache_path.exists():
        with suppress(OSError, json.JSONDecodeError):
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                normalized = {
                    _normalize_package_name(item)
                    for item in payload
                    if isinstance(item, str) and _normalize_package_name(item)
                }
                if normalized:
                    return normalized

    cache_path.write_text(json.dumps(sorted(TOP_PYPI_SEED), indent=2), encoding="utf-8")
    return {_normalize_package_name(item) for item in TOP_PYPI_SEED}


def _load_top_npm_cache() -> set[str]:
    cache_path = get_state_dir() / TOP_NPM_CACHE_FILE
    if cache_path.exists():
        with suppress(OSError, json.JSONDecodeError):
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                normalized = {
                    _normalize_package_name(item)
                    for item in payload
                    if isinstance(item, str) and _normalize_package_name(item)
                }
                if normalized:
                    return normalized
    cache_path.write_text(json.dumps(sorted(TOP_NPM_SEED), indent=2), encoding="utf-8")
    return {_normalize_package_name(item) for item in TOP_NPM_SEED}


def _detect_typosquat(package_name: str, top_packages: set[str]) -> str | None:
    if package_name in top_packages or len(package_name) < 4:
        return None
    for top_package in top_packages:
        if abs(len(package_name) - len(top_package)) > 1:
            continue
        if _levenshtein_distance(package_name, top_package) <= 1 or _is_transposition(package_name, top_package):
            return top_package
    return None


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _is_transposition(left: str, right: str) -> bool:
    if len(left) != len(right) or left == right:
        return False
    mismatches = [index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
    if len(mismatches) != 2:
        return False
    first, second = mismatches
    return second == first + 1 and left[first] == right[second] and left[second] == right[first]


def _is_disproportionately_low_version(version: str) -> bool:
    match = re.match(r"^(\d+)\.(\d+)", version)
    if match is None:
        return False
    major = int(match.group(1))
    minor = int(match.group(2))
    return major == 0 and minor <= 1


def _parse_iso8601(raw_timestamp: str) -> datetime | None:
    candidate = raw_timestamp.replace("Z", "+00:00")
    with suppress(ValueError):
        return datetime.fromisoformat(candidate)
    return None
