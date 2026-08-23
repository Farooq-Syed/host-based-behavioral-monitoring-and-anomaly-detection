"""Reproduce the RADAR window datasets and record the raw-input manifest.

Two outputs:
  - data/radar_real_windows.csv              (numeric-only, byte-compatible with committed)
  - data/radar_real_windows_with_family.csv  (adds family + run columns for strict splits)

The goodware sample is capped at 400000 rows (the committed setting). Raw file SHA-256
hashes are written into radar_manifest.json so the reproduction is auditable.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd  # noqa: F401  (used indirectly via adapter)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW = PROJECT_ROOT / "data" / "raw" / "JamilIsp-RADAR-cb0c4c2"
GOODWARE = RAW / "Raw logs" / "goodware" / "extracted" / "goodware-logs.csv"
RANSOURCES = list((RAW / "Raw logs" / "ransomware" / "extracted").glob("*.csv"))
OUT = PROJECT_ROOT / "data" / "radar_real_windows.csv"
OUT_FAMILY = PROJECT_ROOT / "data" / "radar_real_windows_with_family.csv"
MANIFEST = PROJECT_ROOT / "radar_manifest.json"

GOODWARE_SAMPLE = 400000
WINDOW_MINUTES = 5


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if not GOODWARE.exists():
        raise FileNotFoundError(f"Raw goodware not present: {GOODWARE}")

    # Byte-compatible rebuild (no metadata) via the adapter entry point.
    rans_sorted = sorted(str(p) for p in RANSOURCES)
    import subprocess
    import sys

    subprocess.run(
        [sys.executable, "sysmon_adapter.py", "--goodware", str(GOODWARE),
         "--ransomware", *rans_sorted, "--window-minutes", str(WINDOW_MINUTES),
         "--goodware-sample", str(GOODWARE_SAMPLE), "--output", str(OUT)],
        check=True,
    )

    # Family-tagged variant.
    subprocess.run(
        [sys.executable, "sysmon_adapter.py", "--goodware", str(GOODWARE),
         "--ransomware", *rans_sorted, "--window-minutes", str(WINDOW_MINUTES),
         "--goodware-sample", str(GOODWARE_SAMPLE), "--include-metadata",
         "--output", str(OUT_FAMILY)],
        check=True,
    )

    # Record hashes in the manifest.
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["dataset"]["raw_file_sha256"] = {
        "goodware-logs.csv": sha256(GOODWARE),
        "ransomware-logs-raw.zip": sha256(RAW / "Raw logs" / "ransomware" / "ransomware-logs-raw.zip"),
        "radar_zip_md5": "f82b0dfee5332448de9a03ae3f7cc911",
    }
    manifest["dataset"]["num_ransomware_samples"] = len(RANSOURCES)
    manifest["dataset"]["url"] = "https://zenodo.org/records/14564541"
    manifest["reproduce_windows"] = (
        f"python sysmon_adapter.py --goodware data/raw/JamilIsp-RADAR-cb0c4c2/Raw logs/goodware/extracted/goodware-logs.csv "
        f"--ransomware <62 family CSVs> --window-minutes {WINDOW_MINUTES} --goodware-sample {GOODWARE_SAMPLE} "
        f"--output data/radar_real_windows.csv"
    )
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote hashes -> {MANIFEST}")
    print(f"  goodware sha256: {manifest['dataset']['raw_file_sha256']['goodware-logs.csv']}")


if __name__ == "__main__":
    main()
