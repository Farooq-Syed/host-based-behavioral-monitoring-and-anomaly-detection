"""Unit tests for the newer monitoring paths in monitor.py.

These cover the progression (sequence) detector, process-reputation enrichment,
and the precision-weighted ensemble. They follow the same style as test_detection.py:
tiny hand-built frames, one behavior per test.
"""

import sys
import unittest
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import monitor  # noqa: E402


def benign_row(**overrides):
    row = {
        "timestamp": "2026-05-12T09:00:00",
        "host": "host-a",
        "process_name": "explorer.exe",
        "cpu_percent": 10,
        "memory_mb": 400,
        "disk_write_mb": 5,
        "file_write_count": 20,
        "file_rename_count": 0,
        "network_connections": 15,
        "child_process_count": 1,
        "unsigned_binary": 0,
        "suspicious_extension_changes": 0,
        "entropy_score": 4.0,
        "shadow_copy_events": 0,
        "label": "benign",
    }
    row.update(overrides)
    return row


class ProgressionTests(unittest.TestCase):
    def test_full_trajectory_across_windows_is_flagged(self):
        rows = [
            # Stage 1 first: mass renames, no shadow-copy or encryption yet.
            benign_row(timestamp="2026-05-12T09:00:00", file_rename_count=150, shadow_copy_events=0, entropy_score=4.0),
            # Stage 2: shadow copy removed.
            benign_row(timestamp="2026-05-12T09:01:00", file_rename_count=0, shadow_copy_events=1, entropy_score=4.0),
            # Stage 3: encryption burst.
            benign_row(timestamp="2026-05-12T09:02:00", entropy_score=8.8, disk_write_mb=400, file_rename_count=300),
        ]
        frame = pd.DataFrame(rows)
        report = monitor.detect_progression(frame)
        self.assertEqual(int(report.iloc[2]["progression_flag"]), 1)
        # The earlier windows are not yet part of a completed trajectory.
        self.assertEqual(int(report.iloc[0]["progression_flag"]), 0)
        self.assertEqual(int(report.iloc[1]["progression_flag"]), 0)

    def test_stages_out_of_order_do_not_complete(self):
        rows = [
            # Encryption first, tampering later: the canonical order is missing.
            benign_row(timestamp="2026-05-12T09:00:00", entropy_score=8.8, disk_write_mb=400, file_rename_count=300),
            benign_row(timestamp="2026-05-12T09:01:00", shadow_copy_events=1),
        ]
        report = monitor.detect_progression(pd.DataFrame(rows))
        self.assertTrue((report["progression_flag"] == 0).all())

    def test_benign_host_never_flags(self):
        rows = [benign_row(timestamp=f"2026-05-12T09:0{i}:00") for i in range(4)]
        report = monitor.detect_progression(pd.DataFrame(rows))
        self.assertTrue((report["progression_flag"] == 0).all())
        self.assertTrue((report["window_stage"] == 0).all())


class ReputationTests(unittest.TestCase):
    def test_abuse_prone_process_flagged(self):
        frame = pd.DataFrame([benign_row(process_name="powershell.exe")])
        report = monitor.enrich_process_reputation(frame)
        self.assertEqual(report.iloc[0]["process_reputation"], "abuse_prone")
        self.assertEqual(int(report.iloc[0]["reputation_flag"]), 1)

    def test_trusted_process_not_flagged(self):
        frame = pd.DataFrame([benign_row(process_name="explorer.exe")])
        report = monitor.enrich_process_reputation(frame)
        self.assertEqual(report.iloc[0]["process_reputation"], "trusted")
        self.assertEqual(int(report.iloc[0]["reputation_flag"]), 0)

    def test_unknown_process_is_unknown(self):
        frame = pd.DataFrame([benign_row(process_name="mystery.exe")])
        report = monitor.enrich_process_reputation(frame)
        self.assertEqual(report.iloc[0]["process_reputation"], "unknown")

    def test_external_csv_extends_builtin_list(self, tmp_path=None):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reputation.csv"
            path.write_text("process_name,reputation\nprobe.exe,abuse_prone\n", encoding="utf-8")
            frame = pd.DataFrame([benign_row(process_name="probe.exe")])
            report = monitor.enrich_process_reputation(frame, reputation_csv=str(path))
            self.assertEqual(report.iloc[0]["process_reputation"], "abuse_prone")


class CalibratedEnsembleTests(unittest.TestCase):
    def test_weighted_ensemble_runs_and_is_suspicious_present(self):
        rows = [benign_row(host=f"b{i}") for i in range(8)]
        rows += [
            benign_row(
                host=f"m{i}",
                cpu_percent=96, disk_write_mb=410, file_rename_count=210,
                suspicious_extension_changes=96, entropy_score=8.6,
                shadow_copy_events=1, unsigned_binary=1, label="malicious",
            )
            for i in range(8)
        ]
        frame = pd.DataFrame(rows)
        report = monitor.build_report(frame, contamination=0.2, random_state=42, label_column="label", ensemble="weighted")
        self.assertIn("ensemble_weighted_score", report.columns)
        self.assertIn("is_suspicious_calibrated", report.columns)
        self.assertIn("progression_flag", report.columns)
        self.assertIn("reputation_flag", report.columns)
        # Some window should be flagged under the weighted ensemble.
        self.assertGreaterEqual(int(report["is_suspicious"].sum()), 1)

    def test_weights_prefer_precise_methods(self):
        rows = [benign_row(host=f"b{i}") for i in range(6)]
        rows += [benign_row(host=f"m{i}", label="malicious") for i in range(2)]
        frame = pd.DataFrame(rows)
        truth = frame["label"].apply(monitor.normalize_label)
        report = monitor.enrich_process_reputation(frame)
        report["rule_flag"] = 0
        report["isolation_forest_flag"] = 0
        report["lof_flag"] = 0
        report["random_forest_flag"] = 0
        report["progression_flag"] = 0
        report["reputation_flag"] = 0
        weights = monitor._ensemble_weights(report, truth)
        self.assertIn("rule_flag", weights)
        self.assertGreaterEqual(weights["rule_flag"], 0.05)


if __name__ == "__main__":
    unittest.main()
