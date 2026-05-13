from __future__ import annotations

import unittest

from gitguard.core.models import SandboxResult
from gitguard.core.runtime_analysis import assess_runtime_behavior, parse_sandbox_telemetry


class RuntimeAnalysisTests(unittest.TestCase):
    def test_parse_sandbox_telemetry_extracts_coverage_and_events(self) -> None:
        logs = "\n".join(
            [
                "GITGUARD_PROGRESS: Starting shallow clone",
                '{"event":"coverage","mode":"browser_dynamic","entrypoint":"index.html"}',
                '{"event":"progress","message":"Navigating to application entrypoint"}',
                '{"event":"request","url":"https://example.com/api","method":"GET"}',
                "not-json",
            ]
        )

        coverage, coverage_reason, events, progress_messages, entrypoint = parse_sandbox_telemetry(logs)

        self.assertEqual(coverage, "browser_dynamic")
        self.assertIsNone(coverage_reason)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "request")
        self.assertEqual(
            progress_messages,
            ["Starting shallow clone", "Navigating to application entrypoint"],
        )
        self.assertEqual(entrypoint, "index.html")

    def test_assess_runtime_behavior_flags_external_request_as_suspicious(self) -> None:
        result = SandboxResult(
            image="img",
            container_id="cid",
            exit_code=0,
            logs="",
            runtime_seconds=1.0,
            warnings=[],
            coverage="browser_dynamic",
            coverage_reason=None,
            telemetry_events=[
                {"event": "request", "url": "https://evil.example/collect", "method": "POST"},
            ],
            progress_messages=[],
            entrypoint="index.html",
        )

        assessment = assess_runtime_behavior(result)

        self.assertEqual(assessment.verdict, "SUSPICIOUS")
        self.assertIn("evil.example", "\n".join(assessment.evidence))

    def test_assess_runtime_behavior_returns_safe_for_static_only_fallback(self) -> None:
        result = SandboxResult(
            image="img",
            container_id="cid",
            exit_code=0,
            logs="",
            runtime_seconds=1.0,
            warnings=[],
            coverage="static_only",
            coverage_reason="unsupported_repo_type",
            telemetry_events=[],
            progress_messages=[],
            entrypoint=None,
        )

        assessment = assess_runtime_behavior(result)

        self.assertEqual(assessment.verdict, "SAFE")
        self.assertEqual(assessment.coverage, "static_only")


if __name__ == "__main__":
    unittest.main()
