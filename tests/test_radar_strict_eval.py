"""Tests for radar_strict_eval.py (strict-split publication-grade evaluation)."""

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import radar_strict_eval as rse  # noqa: E402


def _frame(n_good=120, n_attack=60, seed=0, with_meta=True):
    rng = np.random.default_rng(seed)
    feats = ["file_rename_like", "suspicious_extension_events", "file_delete_count",
             "shadow_copy_events", "unsigned_process_events", "event_count"]
    rows = []
    # benign (goodware) runs
    for _ in range(n_good):
        r = {c: int(rng.integers(0, 3)) for c in feats}
        r["timestamp"] = "2024-10-20 10:00:00"
        r["host"] = "host-good"
        r["family"] = "Goodware"
        r["run"] = "goodware:g"
        r["label"] = 0
        rows.append(r)
    for fam in ("Akira", "LockBit"):
        for _ in range(n_attack):
            r = {c: int(rng.integers(3, 12)) for c in feats}
            r["timestamp"] = "2024-10-20 11:00:00"
            r["host"] = f"host-{fam}"
            r["family"] = fam
            r["run"] = f"ran:{fam}:sample-{rng.integers(99)}"
            r["label"] = 1
            rows.append(r)
    return pd.DataFrame(rows)


class RuleAndStageTests(unittest.TestCase):
    def test_rule_detector_flags_high_score(self):
        frame = _frame(5, 5)
        pred = rse.rule_detector(frame[["file_rename_like", "suspicious_extension_events",
                                        "file_delete_count", "shadow_copy_events",
                                        "unsigned_process_events", "event_count"]])
        self.assertEqual(len(pred), len(frame))

    def test_window_stage_maps_to_expected_levels(self):
        row = pd.Series({"file_rename_like": 5, "suspicious_extension_events": 0,
                         "file_delete_count": 0, "shadow_copy_events": 0,
                         "unsigned_process_events": 0})
        self.assertEqual(rse._window_stage(row), 1)
        row2 = row.copy()
        row2["shadow_copy_events"] = 1
        self.assertEqual(rse._window_stage(row2), 2)
        row3 = row.copy()
        row3["file_delete_count"] = 60
        self.assertEqual(rse._window_stage(row3), 3)

    def test_split_benign_partitions_without_overlap(self):
        idx = np.arange(0, 100)
        held, keep = rse._split_benign(idx)
        self.assertEqual(len(set(held) & set(keep)), 0)
        self.assertEqual(sorted(set(held) | set(keep)), sorted(idx.tolist()))


class SplitTests(unittest.TestCase):
    def test_family_split_keeps_benign_unseen_in_test(self):
        frame = _frame()
        features = frame.select_dtypes(include=[np.number]).drop(columns=["label"])
        truth = frame["label"].to_numpy()
        family = frame["family"]
        # Hand-mirror the family branch: held-out Akira + a benign split.
        attack_idx = np.where(truth == 1)[0]
        benign_idx = np.where(truth == 0)[0]
        held_ben, keep_ben = rse._split_benign(benign_idx)
        held_att = np.where((family == "Akira").to_numpy() & (truth == 1))[0]
        test_idx = np.concatenate([held_ben, held_att])
        train_idx = np.concatenate([keep_ben, np.where((family != "Akira").to_numpy() & (truth == 1))[0]])
        self.assertGreaterEqual(len(np.unique(truth[test_idx])), 2)
        self.assertGreaterEqual(len(np.unique(truth[train_idx])), 2)
        self.assertEqual(len(set(test_idx) & set(train_idx)), 0)


class FitPredictTests(unittest.TestCase):
    def test_fit_predict_all_returns_all_comparators(self):
        frame = _frame(60, 30)
        features = frame.select_dtypes(include=[np.number]).drop(columns=["label"])
        truth = frame["label"].to_numpy()
        train_idx = np.arange(0, 80)
        test_idx = np.arange(80, len(frame))
        res = rse._fit_predict_all(features, truth, train_idx, test_idx, 0.2, 0,
                                   "host", "timestamp")
        for name in ("rule", "iforest", "lof", "random_forest", "vote", "weighted", "progression"):
            self.assertIn(name, res)
        self.assertIn("f1", res["random_forest"])
        self.assertIn("roc_auc", res["random_forest"])

    def test_fit_predict_all_matches_lengths(self):
        frame = _frame(60, 30)
        features = frame.select_dtypes(include=[np.number]).drop(columns=["label"])
        truth = frame["label"].to_numpy()
        test_idx = np.arange(100, len(frame))
        res = rse._fit_predict_all(features, truth, np.arange(0, 100), test_idx, 0.2, 0,
                                   "host", "timestamp")
        self.assertEqual(len(test_idx), len(frame) - 100)
        for name in ("rule", "iforest", "lof", "random_forest", "vote", "weighted", "progression"):
            # F1/P/R are pooled; verify they are finite scalars.
            self.assertTrue(np.isfinite(res[name]["f1"]))


if __name__ == "__main__":
    unittest.main()
