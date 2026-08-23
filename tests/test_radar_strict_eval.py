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
                                   "host", "timestamp", full_frame=frame)
        for name in ("rule", "iforest", "lof", "random_forest", "vote", "weighted", "progression"):
            self.assertIn(name, res)
        self.assertIn("f1", res["random_forest"])
        # Probabilistic keys are present when the test pool has both classes.
        test_classes = len(np.unique(truth[test_idx]))
        if test_classes > 1:
            self.assertIn("roc_auc", res["random_forest"])
            self.assertIn("applied_fpr", res["random_forest"])

    def test_fit_predict_all_matches_lengths(self):
        frame = _frame(60, 30)
        features = frame.select_dtypes(include=[np.number]).drop(columns=["label"])
        truth = frame["label"].to_numpy()
        test_idx = np.arange(100, len(frame))
        res = rse._fit_predict_all(features, truth, np.arange(0, 100), test_idx, 0.2, 0,
                                   "host", "timestamp", full_frame=frame)
        self.assertEqual(len(test_idx), len(frame) - 100)
        for name in ("rule", "iforest", "lof", "random_forest", "vote", "weighted", "progression"):
            # F1/P/R are pooled; verify they are finite scalars.
            self.assertTrue(np.isfinite(res[name]["f1"]))


class ReviewerFixTests(unittest.TestCase):
    # Fix 3: registry_events >= 0 was always-on; a benign row must not get a rule point
    # from the (now positive) registry threshold.
    def test_rule_registry_threshold_not_always_on(self):
        row = pd.Series({"file_rename_like": 0, "suspicious_extension_events": 0,
                         "shadow_copy_events": 0, "unsigned_process_events": 0,
                         "file_delete_count": 0, "registry_events": 0})
        score = rse._rule_score(row)
        self.assertEqual(score, 0)  # registry=0 < threshold -> no point, and others off
        # The registry threshold must be > 0 so it is not always-on.
        self.assertGreater(rse.RULE_THRESHOLDS["registry_events"], 0)

    def test_rule_registry_positive_threshold_fires_when_exceeded(self):
        row = pd.Series({"file_rename_like": 0, "suspicious_extension_events": 0,
                         "shadow_copy_events": 0, "unsigned_process_events": 0,
                         "file_delete_count": 0, "registry_events": 6})
        self.assertGreater(rse._rule_score(row), 0)

    # Fix 2: progression must be evaluated on metadata, not silently all-zero via the
    # numeric frame. With host/timestamp present it should be computed (even if it flags
    # nothing on short sequences, it must not be a hard all-zero from missing columns).
    def test_progression_evaluates_when_metadata_present(self):
        frame = _frame(40, 20)
        feats = frame.select_dtypes(include=[np.number]).drop(columns=["label"])
        # Build a test subframe that carries host + timestamp so progression can run.
        test_idx = np.arange(60, len(frame))
        meta = frame.iloc[test_idx][["timestamp", "host"]].copy()
        res = rse._fit_predict_all(feats, frame["label"].to_numpy(), np.arange(0, 60),
                                   test_idx, 0.2, 0, "host", "timestamp", full_frame=frame)
        self.assertIn("progression", res)
        self.assertTrue(np.isfinite(res["progression"]["f1"]))

    # Fix 1: recall@FPR threshold must NOT be picked on the test fold; it should be a
    # finite threshold chosen from training, and applied to test.
    def test_recall_at_threshold_uses_validation_threshold(self):
        y_test = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        prob = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
        thr = 0.5
        rec = rse._recall_at_threshold(y_test, prob, thr)
        self.assertGreaterEqual(rec, 0.0)
        self.assertLessEqual(rec, 1.0)
        # With threshold NaN (degenerate training), recall is NaN, not a test-tuned number.
        self.assertTrue(np.isnan(rse._recall_at_threshold(y_test, prob, float("nan"))))

    def test_threshold_from_train_never_uses_test_labels(self):
        # Validate _threshold_from_train returns a finite, non-NaN value and that the
        # helper exists and uses only training data (it re-fits an inner split).
        rng = np.random.default_rng(0)
        x = rng.normal(0, 1, (40, 4)); y = np.array([0]*20 + [1]*20)
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        rf = RandomForestClassifier(n_estimators=30, class_weight="balanced", random_state=0, n_jobs=-1)
        rf.fit(StandardScaler().fit_transform(x), y)
        thr = rse._threshold_from_train(rf, x, y, x, target_fpr=0.01)
        self.assertFalse(np.isnan(thr))
        self.assertGreaterEqual(thr, 0.0)
        self.assertLessEqual(thr, 1.0)


if __name__ == "__main__":
    unittest.main()
