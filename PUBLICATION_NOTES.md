# Publication Notes

**Project:** `host-based-behavioral-monitoring-and-anomaly-detection`  
**Status date:** August 23, 2026

## Core claim (narrow)

On real RADAR Sysmon windows, **supervised detection beats unsupervised baselines, but
the margin is sensitive to family/session shift** — and the earlier 5-fold random-CV
number is in-distribution-optimistic.

## Why this is interesting

- It evaluates the method stack on a **real, public, labeled ransomware corpus** (RADAR),
  not only a synthetic generator.
- Under a strict **leave-one-family-out** split, the supervised/unsupervised ordering
  holds but degrades gracefully with family sparsity — a realistic, honest result.
- It reports the full comparator ablation (rule, IF, LOF, RF, vote, weighted, progression)
  with 95% CIs, recall@FPR, and per-family numbers.

## Strongest evidence in the repo

- Leave-one-family-out strict split: RF F1 0.400 (±0.13) / AUC 0.809 vs. IF 0.324 /
  LOF 0.195; precision-oriented weighted ensemble reaches 0.971 precision.
- Per-family: BlackBasta 0.511, Akira 0.514, LockBit 0.480, Medusa 0.464, Lynx 0.429,
  CyberVolk 0.200, Meow 0.200.
- Contamination tuned on an **inner validation split** (0.13–0.20 per family), never from
  the ~13% test prevalence.
- Frozen preprocessing manifest (`radar_manifest.json`), reproduction script
  (`scripts/reproduce_radar.py`), and a pinned `requirements-lock.txt`.
- 35 passing tests.

## Main reviewer risks

1. Several RADAR families are small (CyberVolk 37, Meow 16 windows), so their held-out F1
   estimates carry wide CIs; state this plainly.
2. The progression detector could not be evaluated fairly on RADAR (short per-run windows)
   and is reported as an omission, not omitted silently.
3. Real-data coverage is four families/4,300 windows; the RADAR imbalanced/drift
   sub-datasets are a natural extension.
4. RADAR is lab-generated (real malware + real Sysmon), not live enterprise telemetry —
   do not over-claim.

## Best venue fit

- workshop/short paper on endpoint telemetry, ransomware detection, or applied security ML
- a ML-for-security venue given the strict-split methodology and negative-family-shift finding

## One-sentence novelty line

Supervised detection beats unsupervised baselines on real RADAR Sysmon windows, but the
margin is sensitive to family/session shift — so the headline number is the strict-split
result, not the random-CV one.
