# Publication Notes

**Project:** `host-based-behavioral-monitoring-and-anomaly-detection`  
**Status date:** August 22, 2026

## Core claim

Ransomware-style host telemetry is better modeled by **comparing detector families**
and by adding **progression-aware logic** than by relying on one anomaly detector in
isolation.

## Why this is interesting

- It compares rules, unsupervised ML, supervised ML, and ensemble behavior on the
  same telemetry stream.
- It treats ransomware as a temporal progression rather than just a loud snapshot.
- It includes a precision-calibrated ensemble variant, which is closer to how a real
  defender thinks about operating points.

## Strongest evidence already in the repo

- ensemble recall improvement over any single unsupervised method on the sample
- harder synthetic telemetry generation to avoid the "everything scores 1.00" trap
- progression detector design that maps recon -> tampering -> encryption stages
- 23 passing tests

## Main reviewer risks

1. The strongest current dataset story is synthetic rather than a public benchmark or
   operational telemetry source.
2. The progression detector is persuasive conceptually, but needs explicit ablation
   evidence to show what it adds numerically.
3. A reviewer may ask whether the calibrated ensemble improves deployability more
   than raw F1; that should be answered directly.

## Best venue fit

- workshop paper on endpoint telemetry, ransomware detection, or applied security ML
- systems/security analytics venue if the progression framing is emphasized

## Experiments still worth adding

- ablation table: rules vs IF vs LOF vs RF vs ensemble vs progression
- threshold sweep or operating-point figure for the calibrated ensemble
- one clearer section on what would be required to validate on real endpoint data

## One-sentence novelty line

This project shows that host-based attack detection becomes more credible when an
attack is modeled as a **trajectory across windows**, not just an isolated anomaly
score.
