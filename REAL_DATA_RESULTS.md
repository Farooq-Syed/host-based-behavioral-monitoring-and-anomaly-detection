# Real-data results — RADAR raw Sysmon (ransomware vs. goodware)

This is the host-monitor's **real-data** evaluation, replacing the synthetic-telemetry
result with actual Sysmon events from a real, public, labeled corpus.

## Data source and license

**[RADAR: A Realistic Dataset for Advancing Ransomware Detection]** (Ispahany, Charles Sturt
University), Zenodo `10.5281/zenodo.14564541`, **CC BY 4.0**. It ships **raw Sysmon logs**:
a large goodware log plus per-sample ransomware logs across families (Akira, BlackBasta,
CyberVolk, LockBit, Lynx, Medusa, Meow), each Sysmon event carrying the ECS-style fields
(`@timestamp`, `event.code` = Sysmon event ID, `file.path`, `process.executable`,
`source/destination.ip`, `target-class` = label).

## Pipeline

`sysmon_adapter.py` aggregates raw Sysmon events into per-(host, 5-minute) windows and
derives the windowed features that Sysmon actually exposes:

```
process_create_count  file_create_count  file_delete_count  file_rename_like
network_connections  registry_events  module_loads  unsigned_process_events
suspicious_extension_events  shadow_copy_events  event_count   label
```

Reproduce the run:

```bash
# Requires the RADAR raw logs (goodware-logs.csv + per-sample ransomware CSVs)
python sysmon_adapter.py --goodware <goodware-logs.csv> \
    --ransomware Akira-*.csv BlackBasta-*.csv LockBit-*.csv Medusa-*.csv ... \
    --window-minutes 5 --goodware-sample 400000 --output data/radar_real_windows.csv
# Comparative ML evaluation on those real windows (same stack monitor.py uses)
python real_data_eval.py --input data/radar_real_windows.csv --label-column label \
    --contamination 0.13 --metrics-output results/radar_real_eval.json
```

The committed output is `data/radar_real_windows.csv` (4,283 real windows) and
`results/radar_real_eval.json`. The frozen preprocessing definition is in
`radar_manifest.json`. The reproducible rebuild (all 62 ransomware samples) yields 4,300
windows (3,740 benign, 560 ransomware); the strict-split results report this reproducible
set.

### Raw inputs and family/session tagging

The RADAR Zenodo record is a single archive (`JamilIsp/RADAR-v0.0.1-beta.zip`,
MD5 `f82b0dfee5332448de9a03ae3f7cc911`). It contains `Raw logs/goodware/goodware-logs.csv`
and `Raw logs/ransomware/ransomware-logs-raw.zip` (62 per-sample CSVs across the seven
families). `scripts/reproduce_radar.py` extracts these, rebuilds the numeric windows file,
and produces a family-tagged counterpart:

```bash
python scripts/reproduce_radar.py
# -> data/radar_real_windows.csv            (numeric-only, byte-compatible)
# -> data/radar_real_windows_with_family.csv (adds family + run columns)
```

The family-tagged file is what the strict-split evaluation consumes.

## Results (random 5-fold CV — development-era)

4,283 real Sysmon windows (3,740 benign, 543 ransomware; ~13% attack rate), 5-fold CV.

| method | F1 | precision | recall |
| --- | ---: | ---: | ---: |
| IsolationForest (unsupervised) | 0.397 | 0.391 | 0.403 |
| LOF (unsupervised) | 0.163 | 0.166 | 0.162 |
| RandomForest (supervised) | **0.515** | 0.495 | 0.540 |
| Majority vote (ensemble) | 0.482 | 0.674 | 0.378 |
| RF AUC | — | — | 0.818 |

## The honest finding

On **real** Sysmon telemetry the same comparative method scores far **lower** than on the
synthetic generator: F1 ≈ 0.40–0.52, not the 0.89 from synthetic windows. This is not a
regression — it is the more credible result. Real telemetry is noisier, less separable and
the event-type window features carry less signal than engineered synthetic features, so:

- **Supervised clearly beats unsupervised** (RF 0.515 / AUC 0.82 vs. IF 0.40 / LOF 0.16) —
  the same ordering the portfolio reports on real benchmark flows (network-detector).
- **The vote is the more precise, lower-recall operating point** (precision 0.67, recall 0.38),
  exactly the cost-aware tradeoff the calibrated ensemble is designed for.
- This is a genuinely harder, honest result and should be **foregrounded** over the
  synthetic 0.89 in the paper and statement.

## Strict split (leave-one-family-out) — the publication headline

The 5-fold random-CV numbers above are **in-distribution** and optimistic: they mix windows
from the same family/session across train and test. RADAR's runs are pure (a run is either
a goodware execution or one ransomware family), so the strict protocol below holds out an
entire family's runs. `radar_strict_eval.py` also tunes `contamination` on an **inner
validation split** — never from the known 13% test prevalence.

`results/radar_strict_family_eval.json`: 7 held-out families, test = held-out family's
attacks + a 20% benign (goodware) split (the benign split is excluded from training). 95% CI
shown. Pooled comparators:

| comparator | F1 (95% CI) | precision | recall | AUC | recall @ 1% FPR |
|---|:--:|:--:|:--:|:--:|:--:|
| Random forest (supervised) | **0.400 (±0.13)** | 0.347 | 0.531 | 0.809 | 0.174 |
| Unweighted vote | 0.407 (±0.13) | 0.388 | 0.462 | — | — |
| Isolation Forest | 0.324 (±0.11) | 0.256 | 0.490 | — | — |
| Weighted ensemble | 0.208 (±0.06) | 0.967 | 0.118 | — | — |
| LOF | 0.195 (±0.10) | 0.152 | 0.296 | — | — |
| Rule-based | 0.057 (±0.08) | 0.714 | 0.030 | — | — |
| Progression | 0.000 | — | — | — | — |

Per-held-out-family (supervised RF):

| held-out family | test attacks | F1 | AUC |
|---|:--:|:--:|:--:|
| BlackBasta | 128 | 0.511 | 0.829 |
| Akira | 117 | 0.514 | 0.808 |
| LockBit | 126 | 0.480 | 0.796 |
| Medusa | 80 | 0.464 | 0.806 |
| Lynx | 56 | 0.429 | 0.861 |
| CyberVolk | 37 | 0.200 | 0.741 |
| Meow | 16 | 0.200 | 0.820 |

**Method notes (corrected).** Only `contamination` is tuned (on an inner validation
split). The Random Forest decision threshold is fixed at 0.5 and the weighted ensemble's
majority cutoff is fixed; **neither is tuned on validation or test data**. The RF
`recall @ 1% FPR` (0.174) is computed with a threshold selected on an inner validation
split of the training fold and applied once to the held-out family — it is NOT tuned on
the test fold. RADAR goodware is a single run, so the benign hold-out is a *random* 20%
pool, not a session-disjoint one; this is a sound unseen-ransomware-family test with a
held-out random benign pool, not a host/session-disjoint deployment claim.

**Reading.** Supervised detection beats every unsupervised baseline **on unseen families**:
RF F1 0.40 / AUC 0.81 vs IF 0.32 / LOF 0.20, and the precision-oriented weighted ensemble
reaches 0.967 precision. But the result is **sensitive to family/session shift**: F1 drops
from ~0.51 for the well-sampled families (BlackBasta, Akira, LockBit) to 0.20 for the
smallest (CyberVolk 37, Meow 16 windows), and RF recall at a 1% FPR budget is only 0.17
(where the model's default-0.5 FPR is ~0.09). The progression detector reports 0.000
because RADAR's per-run windows are too short to support the recon→tamper→encrypt
trajectory across the 265 per-host process groups in the test pool — it is reported as a
fair-evaluation **omission**, not a silently-zero result.

The narrow, defensible claim: **supervised detection beats unsupervised baselines on real
RADAR Sysmon windows, but the margin is sensitive to family/session shift, and the
random-CV number (0.515) is in-distribution-optimistic.**

## Limitations (stated plainly)

- Sysmon does not expose CPU, memory, or raw file entropy, so those `monitor.py` features
  are **not** derivable here; the evaluation runs on the Sysmon-recoverable event-type
  features. A raw-file-content or resource-ingest signal would be needed for the full
  11-feature model.
- Windows are 5-minute buckets aggregated per user; the label is per-event `target-class`.
- RADAR logs are lab-generated (controlled VM executions of real ransomware + goodware), so
  this is real malware-with-real-Sysmon, real covered traces, but not a live-enterprise trace.

## Citation

Jamil Ispahany, Md Rafiqul Islam, M. Arif Khan, Md Zahidul Islam. *RADAR: a realistic dataset
for advancing ransomware detection.* Zenodo, DOI `10.5281/zenodo.14564541` (CC BY 4.0).
