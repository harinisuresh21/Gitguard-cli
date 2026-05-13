from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import patch

from gitguard.core.ai_audit import GEMINI_MODEL_NAME, run_ai_audit
from gitguard.core.models import (
    DependencyAnalysisResult,
    ObfuscationAnalysisResult,
    ScanAssessment,
)


class AIAuditTests(unittest.TestCase):
    @patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False)
    def test_run_ai_audit_returns_structured_result(self) -> None:
        class DummyResponse:
            text = '{"verdict_recommendation":"SUSPICIOUS","reasoning":"Unexpected network behavior.","evidence_summary":"README says calculator, runtime opens websocket."}'
            parsed = {
                "verdict_recommendation": "SUSPICIOUS",
                "reasoning": "Unexpected network behavior.",
                "evidence_summary": "README says calculator, runtime opens websocket.",
            }

        class DummyModels:
            def generate_content(self, **kwargs):
                self.kwargs = kwargs
                return DummyResponse()

        class DummyClient:
            def __init__(self, api_key: str) -> None:
                self.api_key = api_key
                self.models = DummyModels()

        class DummyGenAI:
            Client = DummyClient

        class DummyTypes:
            class GenerateContentConfig:
                def __init__(self, **kwargs) -> None:
                    self.kwargs = kwargs

        google_module = types.ModuleType("google")
        google_module.genai = DummyGenAI
        google_genai_module = types.ModuleType("google.genai")
        google_genai_module.types = DummyTypes

        with patch.dict(sys.modules, {"google": google_module, "google.genai": google_genai_module}):
            result = run_ai_audit(
                readme_text="This is a local calculator.",
                dependency_result=DependencyAnalysisResult(
                    manifests=[],
                    packages=[],
                    findings=[],
                    warnings=[],
                    blocked=False,
                ),
                obfuscation_result=ObfuscationAnalysisResult(findings=[], warnings=[]),
                runtime_assessment=ScanAssessment(
                    verdict="SUSPICIOUS",
                    summary="Unexpected websocket observed.",
                    evidence=["Observed WebSocket attempt to wss://evil.example."],
                    coverage="browser_dynamic",
                ),
                sandbox_result=None,
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.model_name, GEMINI_MODEL_NAME)
        self.assertEqual(result.verdict_recommendation, "SUSPICIOUS")


if __name__ == "__main__":
    unittest.main()
