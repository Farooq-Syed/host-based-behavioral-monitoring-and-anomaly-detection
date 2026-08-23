# Results Table — Headline Metrics

All metrics are **precision / recall / F1** unless noted. The **publication story is the
real-data RADAR evaluation** (see *RADAR real-data* below); the synthetic tables are
development-only evidence.

## RADAR real-data — strict leave-one-family-out (`results/radar_strict_family_eval.json`)

7 held-out families, test = held-out family attacks + 20% benign split (benign excluded from
training); contamination tuned on an inner validation split. Pooled 95% CI.

| Method | F1 | Precision | Recall | AUC | Recall @ 1% FPR |
|--------|---:|----------:|-------:|----:|----------------:|
| Random Forest (supervised) | **0.400** | 0.347 | 0.531 | 0.809 | 0.174 |
| Ensemble (vote) | 0.407 | 0.388 | 0.462 | — | — |
| Isolation Forest | 0.324 | 0.256 | 0.490 | — | — |
| Ensemble (weighted) | 0.208 | 0.967 | 0.118 | — | — |
| Local Outlier Factor | 0.195 | 0.152 | 0.296 | — | — |
| Rule-based | 0.057 | 0.714 | 0.030 | — | — |
| Progression | 0.000 | — | — | — | — |

Per-family (supervised RF): BlackBasta 0.511, Akira 0.514, LockBit 0.480, Medusa 0.464,
Lynx 0.429, CyberVolk 0.200, Meow 0.200.

## 40-Row Sample (`data/sample_host_telemetry.csv`)

| Method | Precision | Recall | F1 | Accuracy | Source |
|--------|----------:|-------:|---:|--------:|--------|
| Rule-based | 1.0000 | 0.5333 | 0.6957 | 0.8250 | `results/sample_metrics.json` — default seed 42, contamination 0.2 |
| Isolation Forest | 1.0000 | 0.5333 | 0.6957 | 0.8250 | same |
| Local Outlier Factor | 1.0000 | 0.5333 | 0.6957 | 0.8250 | same |
| Random Forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | same |
| Progression | 0.0000 | 0.0000 | 0.0000 | 0.6250 | same — no full recon->tamper->encrypt trajectory exists in 40 rows |
| Reputation | 0.6667 | 0.2667 | 0.3810 | 0.6750 | same — built-in name list catches 4 of 15 malicious windows |
| Ensemble (vote) | 1.0000 | 0.8000 | 0.8889 | 0.9250 | same — majority of 4 core detectors |
| Ensemble (weighted) | ~1.00 | ~0.60 | ~0.75 | not yet measured | PAPER.md — precision-calibrated, not yet captured as a JSON in the repo |

## 2,000-Row Synthetic Set (`data/synthetic_host_telemetry.csv`)

| Method | Precision | Recall | F1 | Accuracy | Source |
|--------|----------:|-------:|---:|--------:|--------|
| Rule-based | 0.9708 | 0.4772 | 0.6399 | 0.7940 | `output/metrics.json` — seed 42, contamination 0.2 |
| Isolation Forest | 0.9675 | 0.5046 | 0.6632 | 0.8035 | same |
| Local Outlier Factor | 0.4975 | 0.2595 | 0.3410 | 0.6155 | same |
| Random Forest | 0.9653 | 0.9426 | 0.9538 | 0.9650 | same — cross-validated, out-of-fold predictions |
| Progression | 0.4012 | 0.3546 | 0.3765 | 0.5495 | same — flags 678 rows; the synthetic set has enough multi-window hosts to form trajectories |
| Reputation | 0.9747 | 0.2516 | 0.4000 | 0.7105 | same |
| Ensemble (vote) | 0.9622 | 0.6975 | 0.8088 | 0.8735 | same — majority of 4 core detectors |
| Ensemble (weighted) | 0.9649 | 0.7888 | 0.8680 | 0.9080 | `results/synthetic_eval_weighted_metrics.json` — seed 42 input, precision-calibrated threshold |

## Ablation Summary

No formal ablation table exists in the repo yet. The closest is the side-by-side comparison
in the two tables above — every method runs on the same input, so the difference between
the ensemble and any single method is visible. The progression detector's contribution is
not isolated (e.g., a "progression off" vs. "progression on" column), which is noted in
PUBLICATION_NOTES.md as an experiment worth adding.

## Dataset Notes

- **40-row sample.** The bundled sample is tiny (15 malicious, 25 benign windows across 20
  hosts). Every method except progression and reputation scores near-perfect precision.
  The README explicitly warns that this makes things look "near-perfect" and is misleading
  for claims about real-world performance.
- **2,000-row synthetic set.** The generator (`generate_telemetry.py`) produces overlapping
  class distributions, five behavior archetypes (benign, ransomware, destructive scripting,
  cryptomining, exfiltration), and 3 % label noise. The metrics spread realistically
  (F1 0.34–0.95) rather than clustering at 1.00. **This is still synthetic data** — it
  validates the pipeline, not real-world detection rates.
- **No public benchmark or operational telemetry.** Neither dataset is a substitute for
  evaluation on real endpoint data (Sysmon, EDR exports, etc.).

## Calibrated Ensemble Details

The weighted ensemble described in PAPER.md replaces the majority vote with a
precision-weighted combination:

- **On the sample:** F1 ~0.75, recall ~0.60 (PAPER.md). The weights are dominated by
  the rule-based detector, which is the only method with perfect precision when it fires.
  This is a deliberate trade: it is the operating point a triage-aware defender would
  tune toward.
- **On the 2,000-row set:** Precision 0.9649, recall 0.7888, F1 0.8680, and
  accuracy 0.9080. The machine-readable result is tracked in
  `results/synthetic_eval_weighted_metrics.json`.

## Random-Forest Version Note

The README table reports RF at F1 = 1.00 on the sample. The JOURNAL records a later run
that produced 0.97 due to sklearn/CV version drift between captures. The `results/sample_metrics.json`
file (which ships with the repo) records 1.00. Pin `requirements.txt` exactly to reproduce
the shipped numbers.
