from __future__ import annotations

from pathlib import Path
import shutil
import unittest
from uuid import uuid4

from gitguard.core.obfuscation_review import analyze_obfuscation


class ObfuscationReviewTests(unittest.TestCase):
    def test_detects_nested_eval_and_base64_patterns(self) -> None:
        root = _make_temp_dir()
        try:
            source = root / "payload.py"
            source.write_text(
                """
import base64
exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
""".strip(),
                encoding="utf-8",
            )

            result = analyze_obfuscation(root)

            categories = {finding.category for finding in result.findings}
            self.assertIn("decode_exec_chain", categories)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_detects_script_atob_pattern(self) -> None:
        root = _make_temp_dir()
        try:
            source = root / "app.js"
            source.write_text("eval(atob('YWxlcnQoMSk='));", encoding="utf-8")

            result = analyze_obfuscation(root)

            categories = {finding.category for finding in result.findings}
            self.assertIn("nested_eval", categories)
            self.assertIn("atob_chain", categories)
        finally:
            shutil.rmtree(root, ignore_errors=True)


def _make_temp_dir() -> Path:
    path = Path.cwd() / "tests" / ".tmp" / str(uuid4())
    path.mkdir(parents=True, exist_ok=True)
    return path


if __name__ == "__main__":
    unittest.main()
