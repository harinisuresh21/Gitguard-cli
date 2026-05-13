from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
import shutil
from uuid import uuid4
from unittest.mock import patch

from gitguard.core.models import ScanRecord
from gitguard.core.state import append_scan_record, get_scans_file, load_scan_records


class StateTests(unittest.TestCase):
    def test_append_scan_record_creates_state_file_and_persists_records(self) -> None:
        fake_home = _make_fake_home()
        try:
            with patch("gitguard.core.state.Path.home", return_value=fake_home):
                record = ScanRecord.create(
                    target_url="https://github.com/octocat/Hello-World",
                    created_at=datetime.now(timezone.utc),
                    initial_status="initializing",
                )

                scans_file = append_scan_record(record)

                self.assertEqual(scans_file, fake_home / ".gitguard" / "scans.json")
                data = json.loads(scans_file.read_text(encoding="utf-8"))
                self.assertEqual(len(data), 1)
                self.assertEqual(data[0]["target_url"], record.target_url)
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)

    def test_load_scan_records_returns_most_recent_first(self) -> None:
        fake_home = _make_fake_home()
        try:
            with patch("gitguard.core.state.Path.home", return_value=fake_home):
                first = ScanRecord.create(
                    target_url="https://github.com/example/one",
                    created_at=datetime.now(timezone.utc),
                    initial_status="initializing",
                )
                second = ScanRecord.create(
                    target_url="https://github.com/example/two",
                    created_at=datetime.now(timezone.utc),
                    initial_status="initializing",
                )
                append_scan_record(first)
                append_scan_record(second)

                records = load_scan_records(limit=1)

                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["target_url"], second.target_url)
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)


def _make_fake_home() -> Path:
    fake_home = Path.cwd() / "tests" / ".tmp" / str(uuid4())
    fake_home.mkdir(parents=True, exist_ok=True)
    return fake_home


if __name__ == "__main__":
    unittest.main()
