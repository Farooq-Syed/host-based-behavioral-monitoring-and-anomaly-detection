"""Unit tests for the detection and scoring logic in monitor.py.

Each test builds a minimal telemetry frame so the pieces can be checked without
running the whole CLI. The ML detectors are exercised through build_report on a
small but non-degenerate frame.
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


def ransomware_row(**overrides):
    row = benign_row(
        host="host-m",
        process_name="encryptor.exe",
        cpu_percent=96,
        disk_write_mb=410,
        file_rename_count=210,
        suspicious_extension_changes=96,
        entropy_score=8.6,
        shadow_copy_events=1,
        unsigned_binary=1,
        label="malicious",
    )
    row.update(overrides)
    return row


class NormalizeLabelTests(unittest.TestCase):
    def test_positive_synonyms(self):
        for value in ["1", "true", "malicious", "suspicious", "attack", "yes", "MALICIOUS"]:
            self.assertEqual(monitor.normalize_label(value), 1)

    def test_negative_synonyms(self):
        for value in ["0", "false", "benign", "normal", "no", "Benign"]:
            self.assertEqual(monitor.normalize_label(value), 0)

    def test_unknown_label_raises(self):
        with self.assertRaises(ValueError):
            monitor.normalize_label("maybe")


class RuleDetectorTests(unittest.TestCase):
    def test_ransomware_pattern_flagged(self):
        frame = pd.DataFrame([ransomware_row()])
        report = monitor.rule_based_detector(frame)
        self.assertEqual(int(report.iloc[0]["rule_flag"]), 1)
        # Ransomware row trips well over the 3-signal threshold.
        self.assertGreaterEqual(int(report.iloc[0]["rule_score"]), 3)

    def test_benign_not_flagged(self):
        frame = pd.DataFrame([benign_row()])
        report = monitor.rule_based_detector(frame)
        self.assertEqual(int(report.iloc[0]["rule_flag"]), 0)
        self.assertEqual(report.iloc[0]["rule_reason"], "baseline behavior")


class EnsembleTests(unittest.TestCase):
    def test_rf_flag_matches_score_threshold(self):
        # A clearly separable frame: several benign rows and several ransomware
        # rows so cross-validation has both classes in every fold.
        rows = [benign_row(host=f"b{i}") for i in range(8)]
        rows += [ransomware_row(host=f"m{i}") for i in range(8)]
        frame = pd.DataFrame(rows)
        report = monitor.build_report(frame, contamination=0.2, random_state=42, label_column="label")
        # The consolidated single-pass RF must keep flag and score consistent.
        inconsistent = ((report["random_forest_score"] >= 0.5).astype(int)
                        != report["random_forest_flag"]).sum()
        self.assertEqual(int(inconsistent), 0)

    def test_ensemble_requires_two_votes(self):
        rows = [benign_row(host=f"b{i}") for i in range(8)]
        rows += [ransomware_row(host=f"m{i}") for i in range(8)]
        frame = pd.DataFrame(rows)
        report = monitor.build_report(frame, contamination=0.2, random_state=42, label_column="label")
        # is_suspicious is exactly ensemble_votes >= 2.
        expected = (report["ensemble_votes"] >= 2).astype(int)
        self.assertTrue((report["is_suspicious"] == expected).all())

    def test_small_imbalanced_data_does_not_crash(self):
        # Only 2 positives — the old hardcoded 5-fold split would raise; the
        # adaptive n_splits should keep this working.
        rows = [benign_row(host=f"b{i}") for i in range(8)]
        rows += [ransomware_row(host=f"m{i}") for i in range(2)]
        frame = pd.DataFrame(rows)
        report = monitor.build_report(frame, contamination=0.2, random_state=42, label_column="label")
        self.assertIn("random_forest_flag", report.columns)


if __name__ == "__main__":
    unittest.main()
