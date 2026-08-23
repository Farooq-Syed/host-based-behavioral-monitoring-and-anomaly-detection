# Artifact Checklist — Reproduction Guide

A reviewer can reproduce every result in this repository by following the steps below. All
commands assume a Unix-like shell (PowerShell on Windows, bash on Linux/macOS), run from the
repo root.

## Environment

- Python 3.11 or 3.12 (CI runs 3.12; project tested on 3.11)
- OS: Windows 11 (development), Ubuntu (CI) — pipeline is OS-agnostic beyond Python stdlib
- Dependencies pinned in `requirements-lock.txt`; use exactly these to reproduce the
  reported numbers (a prior sklearn/CV version drift changed the sample F1 1.00 → 0.97)

## Reproduction Commands

### Synthetic (development-only evidence)

```bash
python -m pip install -r requirements-lock.txt
python generate_telemetry.py --rows 2000 --seed 42 --output data/synthetic_host_telemetry.csv
python monitor.py                                  # 40-row sample
python monitor.py --input data/synthetic_host_telemetry.csv   # 2,000-row set
python monitor.py --ensemble weighted              # calibrated ensemble variant
```

### Real-data RADAR (publication evidence)

The raw RADAR archive (Zenodo `10.5281/zenodo.14564541`, MD5
`f82b0dfee5332448de9a03ae3f7cc911`) must be present. `scripts/reproduce_radar.py` downloads
nothing but expects the extracted raw CSVs under `data/raw/JamilIsp-RADAR-cb0c4c2/`; it
rebuilds the numeric windows file and produces the family-tagged counterpart, and records
raw-file hashes into `radar_manifest.json`:

```bash
# After extracting RADAR-v0.0.1-beta.zip -> data/raw/
python scripts/reproduce_radar.py
# -> data/radar_real_windows.csv            (numeric-only)
# -> data/radar_real_windows_with_family.csv (adds family + run columns)
# -> radar_manifest.json                     (frozen preprocessing definition)
```

Strict leave-one-family-out evaluation (7 held-out families, contamination tuned on an
inner validation split, full comparator ablation, 95% CI, recall@FPR):

```bash
python radar_strict_eval.py --input data/radar_real_windows_with_family.csv \
    --label-column label --split family --family-column family \
    --metrics-output results/radar_strict_family_eval.json
```

Development-era random-CV (in-distribution reference):

```bash
python real_data_eval.py --input data/radar_real_windows.csv --label-column label \
    --contamination 0.13 --metrics-output results/radar_real_eval.json
```

### Tests

```bash
python -m pytest -q         # 35 passed
```

## Expected Output Files

Real-data strict split (`radar_strict_eval.py`):
- `results/radar_strict_family_eval.json` — pooled comparators (95% CI) + per-family

Real-data random-CV (`real_data_eval.py`):
- `results/radar_real_eval.json`

Synthetic (`monitor.py`):
- `output/alerts_report.csv`, `output/summary.json`, `output/metrics.json`

## Artifact Checklist

- [x] **README.md** — real-data RADAR result foregrounded (strict family split), synthetic
      marked development-only
- [x] **PAPER.md** — abstract + §5 report the strict leave-one-family-out result
- [x] **REAL_DATA_RESULTS.md** — random-CV (development) + strict-split (publication) tables
- [x] **PUBLICATION_NOTES.md** — narrow claim, reviewer risks, venue fit
- [x] **radar_manifest.json** — frozen window/label/feature/seed definition + raw hashes
- [x] **requirements-lock.txt** — pinned versions
- [x] **scripts/reproduce_radar.py** — reproduces windows + family-tagged data + manifest
- [x] **Tests passing** — 35 tests (adds `test_radar_strict_eval.py`, adapter family test)
- [x] **LICENSE**, **CI workflow**, **REFERENCES.md**

## Loose Ends

- `generate_telemetry.py` docstring references `docs/real_dataset_guide.md`; the real file is
  `docs/DATA.md`.
- RADAR raw CSVs are large (goodware ~126 MB) and are gitignored under `data/raw/`; only the
  windowed CSVs and the manifest are committed.
