"""Tests for generate_telemetry.py.

Checks that generated data has the right schema, both labels, the requested size,
and realistic (non-trivially-separable) overlap between classes.
"""

import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import generate_telemetry as gt  # noqa: E402


class GeneratorTests(unittest.TestCase):
    def test_schema_and_size(self):
        frame = gt.generate(rows=300, seed=1, label_noise=0.03)
        self.assertEqual(len(frame), 300)
        expected = ["timestamp", "host", "process_name", *gt.FEATURE_ORDER, "label"]
        self.assertEqual(list(frame.columns), expected)

    def test_both_labels_present(self):
        frame = gt.generate(rows=300, seed=1, label_noise=0.03)
        self.assertEqual(set(frame["label"]), {"benign", "suspicious"})

    def test_reproducible_with_seed(self):
        a = gt.generate(rows=100, seed=7, label_noise=0.03)
        b = gt.generate(rows=100, seed=7, label_noise=0.03)
        self.assertTrue(a.equals(b))

    def test_classes_overlap_not_trivially_separable(self):
        # If the classes were trivially separable on a single feature the dataset
        # would be unrealistic. Assert the CPU ranges overlap substantially.
        frame = gt.generate(rows=800, seed=2, label_noise=0.03)
        benign_cpu = frame.loc[frame["label"] == "benign", "cpu_percent"]
        attack_cpu = frame.loc[frame["label"] == "suspicious", "cpu_percent"]
        # benign's high tail should reach into attack's low range.
        self.assertGreater(benign_cpu.max(), attack_cpu.min())

    def test_no_negative_values(self):
        frame = gt.generate(rows=300, seed=3, label_noise=0.03)
        for feature in gt.FEATURE_ORDER:
            self.assertGreaterEqual(frame[feature].min(), 0, f"{feature} went negative")


if __name__ == "__main__":
    unittest.main()
