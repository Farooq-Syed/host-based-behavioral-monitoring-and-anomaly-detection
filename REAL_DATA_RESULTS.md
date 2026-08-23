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
`results/radar_real_eval.json`.

## Results (real data)

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
