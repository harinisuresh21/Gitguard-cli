from __future__ import annotations

from ipaddress import ip_address
import re
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen


ALLOWED_HOSTS = {"github.com", "gitlab.com"}
MAX_URL_LENGTH = 2048
SCP_STYLE_PATTERN = re.compile(
    r"^(?P<user>git)@(?P<host>github\.com|gitlab\.com):(?P<path>.+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


class ValidationError(ValueError):
    """Raised when a repository URL is invalid."""


def validate_repository_url(raw_url: str) -> str:
    candidate = raw_url.strip()
    if not candidate:
        raise ValidationError("Repository URL is required.")
    if len(candidate) > MAX_URL_LENGTH:
        raise ValidationError("Repository URL exceeds 2048 characters.")

    candidate = _normalize_input(candidate)
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError("Repository URL must start with http:// or https://.")
    if not parsed.netloc:
        raise ValidationError("Repository URL must include a valid domain.")

    hostname = (parsed.hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1"}:
        raise ValidationError("Localhost repositories are not allowed.")
    if hostname not in ALLOWED_HOSTS:
        if _looks_like_ip(hostname):
            raise ValidationError("IP-based repository URLs are not allowed.")
        raise ValidationError("Only public github.com and gitlab.com repositories are supported.")

    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 2:
        raise ValidationError("Repository URL must include both owner and repository name.")

    normalized_path = re.sub(r"\.git$", "", parsed.path or "")
    normalized = urlunparse(
        (
            parsed.scheme,
            hostname,
            normalized_path.rstrip("/"),
            "",
            "",
            "",
        )
    )
    _check_public_access(normalized)
    return normalized


def _normalize_input(candidate: str) -> str:
    scp_match = SCP_STYLE_PATTERN.match(candidate)
    if scp_match:
        host = scp_match.group("host").lower()
        path = scp_match.group("path").strip("/")
        return f"https://{host}/{path}"

    parsed = urlparse(candidate)
    if parsed.scheme == "ssh":
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").strip("/")
        if parsed.username != "git":
            raise ValidationError("Only public git SSH repository URLs are supported.")
        return f"https://{host}/{path}"

    if "://" not in candidate:
        trimmed = candidate.lstrip("/")
        if trimmed.startswith(("github.com/", "gitlab.com/")):
            return f"https://{trimmed}"
        raise ValidationError("Repository URL must start with http:// or https://.")

    return candidate


def _looks_like_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _check_public_access(url: str) -> None:
    request = Request(url, method="GET", headers={"User-Agent": "GitGuard/0.1"})
    try:
        with urlopen(request, timeout=5) as response:
            if response.status >= 400:
                raise ValidationError("Cannot access repository. Is it public?")
    except ValidationError:
        raise
    except Exception as error:  # pragma: no cover - network path
        raise ValidationError("Cannot access repository. Is it public?") from error
