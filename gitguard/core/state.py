from __future__ import annotations

import json
from pathlib import Path

from gitguard.core.models import ScanRecord

STATE_DIR_NAME = ".gitguard"
SCANS_FILE_NAME = "scans.json"
ACTIVE_SCAN_FILE_NAME = "active_scan.json"


def append_scan_record(record: ScanRecord) -> Path:
    scans_file = get_scans_file()
    existing = _load_records(scans_file)
    existing.append(record.to_dict())
    scans_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return scans_file


def load_scan_records(limit: int | None = None) -> list[dict[str, str]]:
    records = _load_records(get_scans_file())
    ordered = list(reversed(records))
    if limit is None:
        return ordered
    return ordered[:limit]


def update_scan_record_status(scan_id: str, status: str) -> Path:
    scans_file = get_scans_file()
    records = _load_records(scans_file)
    for record in records:
        if record.get("scan_id") == scan_id:
            record["status"] = status
            break
    scans_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return scans_file


def get_state_dir() -> Path:
    state_dir = Path.home() / STATE_DIR_NAME
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


def get_active_scan_file() -> Path:
    return get_state_dir() / ACTIVE_SCAN_FILE_NAME


def get_scans_file() -> Path:
    scans_file = get_state_dir() / SCANS_FILE_NAME
    if not scans_file.exists():
        scans_file.write_text("[]\n", encoding="utf-8")
    return scans_file


def _load_records(scans_file: Path) -> list[dict[str, str]]:
    try:
        content = scans_file.read_text(encoding="utf-8").strip()
        if not content:
            return []
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []
