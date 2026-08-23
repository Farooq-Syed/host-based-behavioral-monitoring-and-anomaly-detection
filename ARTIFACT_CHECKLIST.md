# Artifact Checklist — Reproduction Guide

A reviewer can reproduce every result in this repository by following the steps below. All commands assume a Unix-like shell (PowerShell on Windows, bash on Linux/macOS).

## Environment

- Python 3.11 or 3.12 (the CI workflow runs 3.12; the project is tested on 3.11)
- OS: Windows 11 (development), Ubuntu (CI) — the pipeline is OS-agnostic beyond the Python stdlib
- Dependencies are pinned in `requirements.txt`; use them exactly to reproduce the reported numbers

## Reproduction Commands

```bash
# 1. Clone and enter the repo
git clone https://github.com/Farooq-Syed/host-based-behavioral-monitoring-and-anomaly-detection.git
cd host-based-behavioral-monitoring-and-anomaly-detection

# 2. Install pinned dependencies
python -m pip install -r requirements.txt

# 3. Generate the larger synthetic dataset (optional — the 40-row sample ships with the repo)
python generate_telemetry.py --rows 2000 --seed 42 --output data/synthetic_host_telemetry.csv

# 4. Run the monitor on the 40-row sample (default)
python monitor.py

# 5. Run the monitor on the 2,000-row synthetic set
python monitor.py --input data/synthetic_host_telemetry.csv

# 6. Run the precision-calibrated ensemble variant
python monitor.py --ensemble weighted

# 7. Run the test suite
python -m unittest discover -s tests -v
```

## Expected Output Files

After `python monitor.py` (default sample input):

| File | Contents |
|------|----------|
| `output/alerts_report.csv` | Per-window predictions from all detectors |
| `output/summary.json` | Row count, host count, top flagged hosts, sample flagged windows |
| `output/metrics.json` | Precision, recall, F1, accuracy for every method |
| `output/plots/disk_writes_vs_renames.png` | Scatter plot colored by ensemble verdict |
| `output/plots/method_comparison.png` | Bar chart of flagged windows per method |
| `output/plots/f1_comparison.png` | Bar chart of F1 scores per method |
| `output/plots/ensemble_confusion_matrix.png` | Confusion matrix for the ensemble |

After `python generate_telemetry.py --rows 2000`:

| File | Contents |
|------|----------|
| `data/synthetic_host_telemetry.csv` | 2,000-row synthetic telemetry dataset |

## Artifact Checklist

- [x] **README.md** — Project overview, results table, usage examples, detection logic summary
- [x] **PAPER.md** — Full write-up framing the research question, methods, results, and limitations
- [x] **JOURNAL.md** — Development journal documenting bugs found and fixed, design decisions, and the 14-to-23 test expansion
- [x] **PUBLICATION_NOTES.md** — Publication-readiness notes, core claim, reviewer risks, venue fit
- [x] **REFERENCES.md** — Citations for Isolation Forest, LOF, Random Forest, MITRE ATT&CK; AI-use disclosure
- [x] **Tests passing** — 24 tests across 4 test files (see Summary below)
- [x] **LICENSE** — Non-commercial personal-use license (Copyright 2026 Farooq Syed)
- [x] **CI workflow** — `.github/workflows/ci.yml` runs on push/PR, installs deps, runs `unittest discover`
- [x] **Data generator** — `generate_telemetry.py` produces larger synthetic datasets with overlapping distributions and label noise
- [ ] **docs/real_dataset_guide.md** — Referenced in `generate_telemetry.py` docstring but does not exist (only `docs/DATA.md` exists)

## Test Summary

| File | Tests | Scope |
|------|-------|-------|
| `tests/test_smoke.py` | 1 | End-to-end CLI run produces output files |
| `tests/test_detection.py` | 8 | `normalize_label` synonyms, rule detector triggers, RF flag/score consistency, ensemble vote rule, small-imbalanced-data crash guard |
| `tests/test_generator.py` | 5 | Schema, both labels present, seed reproducibility, class overlap, no negative values |
| `tests/test_advanced_detection.py` | 10 | Progression trajectory (in-order, out-of-order, benign), reputation enrichment (abuse-prone, trusted, unknown, CSV extension), calibrated ensemble (runs, core-threshold anchoring, weights prefer precise methods) |
| **Total** | **24** | All pass on Python 3.11/3.12 (CI) |

## Loose Ends Noted in the Repo

- The README metrics table shows Random Forest at F1 = 1.00 on the sample; the JOURNAL records a run producing 0.97 from the same code due to sklearn/CV version drift. Pin `requirements.txt` exactly to reproduce the README numbers.
- `generate_telemetry.py` docstring references `docs/real_dataset_guide.md`; the actual file is `docs/DATA.md`.
- `data/synthetic_host_telemetry_eval.csv` is an identical copy of `data/synthetic_host_telemetry.csv` (2,000 rows, same seed 42). The `output/metrics.json` in the repo was produced from the eval copy.
- The tracked evaluation copy has SHA-256 `4fdb59fe1b2f5cbe14a5ce1f5a5efb6a55f4139e4b580d973ee4ed5a7bcc04f4`.
