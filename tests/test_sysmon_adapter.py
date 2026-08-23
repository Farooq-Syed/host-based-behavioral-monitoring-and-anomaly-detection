"""Tests for the Sysmon -> windowed-telemetry adapter.

These use a tiny inline ECS/Sysmon-format frame (not the full RADAR download) so the
adapter is CI-testable. The real-data run is reproduced by sysmon_adapter.py on the
RADAR raw logs (see REAL_DATA_RESULTS.md).
"""

import tempfile
from pathlib import Path

import pandas as pd

from sysmon_adapter import FEATURE_ORDER, _window_rows, load_sysmon


def _build_csv(path: Path) -> None:
    rows = []
    base = "Jan 05 2024 10:00:00.000"
    # 3 quick process creations + 1 network connect -> a high-activity window (ransom label)
    for i, code in enumerate([1, 1, 1, 3]):
        rows.append({
            "@timestamp": base,
            "event.code": code,
            "user.domain": "VICTIM",
            "user.name": "alice",
            "process.executable": r"C:\Windows\System32\cmd.exe",
            "file.path": r"C:\Users\alice\Desktop\file.docx",
            "winlog.event_data.Signed": "false",
            "target-class": 1,
        })
    # 1 low-activity process creation w/ signed binary -> a benign window
    rows.append({
        "@timestamp": base,
        "event.code": 1,
        "user.domain": "VICTIM",
        "user.name": "bob",
        "process.executable": r"C:\Program Files\App\app.exe",
        "file.path": "",
        "winlog.event_data.Signed": "true",
        "target-class": 0,
    })
    pd.DataFrame(rows).to_csv(path, index=False)


def test_load_sysmon_parses_ecs():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "events.csv"
        _build_csv(path)
        frame = load_sysmon(path)
        assert "ts" in frame.columns
        assert frame["host"].iloc[0] == "VICTIM\\alice"
        assert int(frame["event_code"].iloc[0]) == 1


def test_window_rows_schema_and_labels():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "events.csv"
        _build_csv(path)
        frame = load_sysmon(path)
        windows = _window_rows(frame, window_minutes=5)
        assert list(FEATURE_ORDER) == [
            "process_create_count", "file_create_count", "file_delete_count",
            "file_rename_like", "network_connections", "registry_events", "module_loads",
            "unsigned_process_events", "suspicious_extension_events",
            "shadow_copy_events", "event_count",
        ]
        assert set(FEATURE_ORDER).issubset(windows.columns)
        # the ransomware window is denser than the benign window
        rw = windows[windows["label"] == 1]
        gr = windows[windows["label"] == 0]
        assert not rw.empty and not gr.empty
        assert rw["event_count"].iloc[0] > gr["event_count"].iloc[0]
        # every numeric feature column is finite
        assert windows[FEATURE_ORDER].notna().all().all()
