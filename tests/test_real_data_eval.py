"""Tests for real_data_eval: the comparative ML stack on an arbitrary feature frame."""

import tempfile
from pathlib import Path

import pandas as pd

from real_data_eval import evaluate, load_frame


def _frame():
    rows = []
    for i in range(200):
        mal = i >= 150
        rows.append({
            "cpu_percent": 90.0 if mal else 20.0,
            "memory_mb": 800.0 if mal else 300.0,
            "disk_write_mb": 300.0 if mal else 10.0,
            "file_write_count": 200 if mal else 5,
            "file_rename_count": 80 if mal else 1,
            "network_connections": 40 if mal else 3,
            "child_process_count": 15 if mal else 1,
            "unsigned_binary": 1 if mal else 0,
            "suspicious_extension_changes": 30 if mal else 0,
            "entropy_score": 7.5 if mal else 3.0,
            "shadow_copy_events": 1 if mal else 0,
            "label": "malicious" if mal else "benign",
        })
    return pd.DataFrame(rows)


def test_load_frame_handles_string_labels():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "frame.csv"
        _frame().to_csv(path, index=False)
        features, truth = load_frame(path, "label")
        assert truth.min() == 0 and truth.max() == 1
        assert features.shape[1] == 11


def test_evaluate_reports_in_range_and_vote_beats_unsupervised():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "frame.csv"
        _frame().to_csv(path, index=False)
        features, truth = load_frame(path, "label")
        result = evaluate(features, truth, folds=5, random_state=42, contamination=0.2)
        for name in ("iforest", "lof", "random_forest", "vote"):
            assert 0.0 <= result["metrics"][name]["f1_mean"] <= 1.0
        # The documented portfolio finding holds on an arbitrary separable frame:
        # supervised clearly beats unsupervised.
        assert result["metrics"]["random_forest"]["f1_mean"] > result["metrics"]["iforest"]["f1_mean"]
        assert 0.0 <= result["metrics"]["auc_random_forest"] <= 1.0
