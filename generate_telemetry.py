"""Generate a larger synthetic host-telemetry dataset.

The bundled 40-row sample is enough to validate the pipeline but too small for its
metrics to mean much. This script produces a larger dataset with the same schema,
drawn from documented per-behavior distributions, so experiments have more statistical
weight while staying fully reproducible and offline.

This data is SYNTHETIC. It is modeled on the qualitative shape of real endpoint
telemetry (ransomware bursts of renames and high entropy, cryptominers pinning CPU,
exfiltration opening many connections) but the numbers are drawn from hand-specified
distributions, not measured from real hosts. It is meant for pipeline development and
teaching, not as a benchmark. For a realistic benchmark, adapt the input path to
Sysmon/EDR exports; see docs/DATA.md.

Design choices that keep the data honest:
  - benign and attack distributions deliberately OVERLAP on several features, so the
    problem is not trivially separable and the detectors' recall stays realistic;
  - each attack archetype is strong on a different subset of features, matching how
    real detection has to combine signals rather than rely on any single one;
  - a small amount of label noise and benign "power user" activity is injected so the
    classes are not perfectly clean.

Usage:
    python generate_telemetry.py --rows 2000 --output data/synthetic_host_telemetry.csv
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

FEATURE_ORDER = [
    "cpu_percent", "memory_mb", "disk_write_mb", "file_write_count",
    "file_rename_count", "network_connections", "child_process_count",
    "unsigned_binary", "suspicious_extension_changes", "entropy_score",
    "shadow_copy_events",
]

BENIGN_PROCESSES = ["explorer.exe", "chrome.exe", "outlook.exe", "code.exe",
                    "teams.exe", "svchost.exe", "python.exe", "excel.exe"]

# Each archetype is a dict of (mean, std) per feature. Benign overlaps the attacks on
# generic resource features (cpu, memory, network) so those alone cannot separate the
# classes; the attacks separate on their characteristic features instead.
PROFILES = {
    "benign": {
        "label": "benign", "weight": 0.62, "process": None,
        "cpu_percent": (25, 18), "memory_mb": (900, 500), "disk_write_mb": (20, 25),
        "file_write_count": (40, 35), "file_rename_count": (3, 5),
        "network_connections": (30, 25), "child_process_count": (2, 2),
        "unsigned_binary": (0.05, 0), "suspicious_extension_changes": (1, 2),
        "entropy_score": (4.3, 0.6), "shadow_copy_events": (0.02, 0),
    },
    "ransomware": {
        "label": "suspicious", "weight": 0.12, "process": "encryptor.exe",
        "cpu_percent": (90, 8), "memory_mb": (1200, 400), "disk_write_mb": (360, 90),
        "file_write_count": (300, 120), "file_rename_count": (180, 60),
        "network_connections": (25, 20), "child_process_count": (3, 2),
        "unsigned_binary": (0.9, 0), "suspicious_extension_changes": (85, 30),
        "entropy_score": (8.4, 0.4), "shadow_copy_events": (0.8, 0),
    },
    "destructive_script": {
        "label": "suspicious", "weight": 0.10, "process": "powershell.exe",
        "cpu_percent": (78, 15), "memory_mb": (700, 300), "disk_write_mb": (140, 80),
        "file_write_count": (120, 70), "file_rename_count": (70, 40),
        "network_connections": (40, 30), "child_process_count": (8, 4),
        "unsigned_binary": (0.6, 0), "suspicious_extension_changes": (35, 20),
        "entropy_score": (6.8, 0.9), "shadow_copy_events": (0.5, 0),
    },
    "cryptominer": {
        "label": "suspicious", "weight": 0.08, "process": "miner.exe",
        "cpu_percent": (97, 3), "memory_mb": (1500, 400), "disk_write_mb": (15, 15),
        "file_write_count": (20, 20), "file_rename_count": (2, 3),
        "network_connections": (60, 30), "child_process_count": (2, 2),
        "unsigned_binary": (0.8, 0), "suspicious_extension_changes": (1, 2),
        "entropy_score": (4.6, 0.7), "shadow_copy_events": (0.05, 0),
    },
    "exfiltration": {
        "label": "suspicious", "weight": 0.08, "process": "rclone.exe",
        "cpu_percent": (45, 20), "memory_mb": (800, 350), "disk_write_mb": (60, 50),
        "file_write_count": (50, 40), "file_rename_count": (5, 6),
        "network_connections": (180, 70), "child_process_count": (3, 3),
        "unsigned_binary": (0.7, 0), "suspicious_extension_changes": (2, 3),
        "entropy_score": (5.0, 1.0), "shadow_copy_events": (0.05, 0),
    },
}


def _sample_feature(rng, mean, std):
    if std == 0:  # binary-ish indicator: interpret mean as a probability
        return int(rng.random() < mean)
    return max(0.0, rng.normal(mean, std))


def generate(rows: int, seed: int, label_noise: float) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    names = list(PROFILES)
    weights = np.array([PROFILES[n]["weight"] for n in names])
    weights = weights / weights.sum()

    base_time = datetime(2026, 5, 12, 9, 0, 0)
    records = []
    for i in range(rows):
        archetype = names[rng.choice(len(names), p=weights)]
        profile = PROFILES[archetype]
        row = {
            "timestamp": (base_time + timedelta(minutes=5 * i)).isoformat(),
            "host": f"host-{rng.integers(1, 60):02d}",
            "process_name": profile["process"] or rng.choice(BENIGN_PROCESSES),
        }
        for feature in FEATURE_ORDER:
            mean, std = profile[feature]
            value = _sample_feature(rng, mean, std)
            # round the count-like features to integers
            if feature not in ("entropy_score", "disk_write_mb"):
                value = int(round(value))
            else:
                value = round(value, 1)
            row[feature] = value

        label = profile["label"]
        # inject a little label noise so the classes are not perfectly clean
        if rng.random() < label_noise:
            label = "benign" if label == "suspicious" else "suspicious"
        row["label"] = label
        records.append(row)

    columns = ["timestamp", "host", "process_name", *FEATURE_ORDER, "label"]
    return pd.DataFrame(records)[columns]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate synthetic host telemetry.")
    parser.add_argument("--rows", type=int, default=2000, help="Number of rows to generate.")
    parser.add_argument("--output", default="data/synthetic_host_telemetry.csv")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--label-noise", type=float, default=0.03,
                        help="Fraction of rows whose label is flipped (0-1).")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    frame = generate(args.rows, args.seed, args.label_noise)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(out, index=False)
    counts = frame["label"].value_counts().to_dict()
    print(f"Wrote {len(frame)} rows to {out}")
    print(f"Label distribution: {counts}")


if __name__ == "__main__":
    main()
