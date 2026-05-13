from __future__ import annotations

import unittest
from unittest.mock import patch

from gitguard.core.validation import ValidationError, validate_repository_url


class DummyResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "DummyResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class ValidationTests(unittest.TestCase):
    @patch("gitguard.core.validation.urlopen", return_value=DummyResponse())
    def test_validate_repository_url_normalizes_supported_github_url(self, _: object) -> None:
        result = validate_repository_url("https://github.com/octocat/Hello-World.git?ref=main")
        self.assertEqual(result, "https://github.com/octocat/Hello-World")

    @patch("gitguard.core.validation.urlopen", return_value=DummyResponse())
    def test_validate_repository_url_accepts_ssh_scp_style(self, _: object) -> None:
        result = validate_repository_url("git@github.com:octocat/Hello-World.git")
        self.assertEqual(result, "https://github.com/octocat/Hello-World")

    @patch("gitguard.core.validation.urlopen", return_value=DummyResponse())
    def test_validate_repository_url_accepts_schemeless_short_link(self, _: object) -> None:
        result = validate_repository_url("gitlab.com/group/project")
        self.assertEqual(result, "https://gitlab.com/group/project")

    def test_validate_repository_url_rejects_localhost(self) -> None:
        with self.assertRaises(ValidationError):
            validate_repository_url("http://localhost/repo")

    def test_validate_repository_url_rejects_missing_repo_name(self) -> None:
        with self.assertRaises(ValidationError):
            validate_repository_url("https://github.com/octocat")

    def test_validate_repository_url_rejects_unsupported_host(self) -> None:
        with self.assertRaises(ValidationError):
            validate_repository_url("https://example.com/octocat/Hello-World")


if __name__ == "__main__":
    unittest.main()
