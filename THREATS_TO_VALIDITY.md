# Threats to Validity

This document states, for each class of validity threat, the honest weakness and the
mitigation that exists (or what would be needed to close it). It is meant to be read
alongside the claims in README.md, PAPER.md, and PUBLICATION_NOTES.md.

## 1. Dataset Limits

**Weakness.** There is no real endpoint data anywhere in the evaluation. The strongest
current dataset story is synthetic: a 40-row hand-built sample plus a 2,000-row generated
set. A reviewer cannot tell from these results how the pipeline behaves on a real
multi-window host, on a real OS, or against real adversary behavior.

**Mitigation / what is needed.** The input path is a documented CSV schema with a stable
feature set, and `docs/DATA.md` lists concrete real sources (Sysmon exports aggregated into
per-window features; DARPA Transparent Computing; academic EDR captures). Adapting a real
source is a matter of aggregating raw events into the 11 per-window features — no detector
changes required. Until that adaptation is done and metrics are re-measured, all numbers
here validate the pipeline, not real-world detection rates.

## 2. Synthetic-Data Caveats

**Weakness.** The generator draws features from hand-specified distributions
(`generate_telemetry.py` profiles), not from measured hosts. The archetypes encode the
author's priors about what ransomware, destructive scripting, cryptomining, and exfiltration
look like in numeric features. That means the data can only confirm methods behave sensibly
*relative to each other*; it cannot establish absolute detection quality, and it cannot catch
cases where the prior is wrong (e.g., a real ransomware family that does not produce the
mass-rename/high-entropy signature).

**Mitigation / what is needed.** The generator is deliberately honest in three ways: benign
and attack distributions overlap on generic resource features so no single feature separates
them; five behavior archetypes rather than one "attack" blob; and label noise is injected so
supervised accuracy stays realistic (the README calls out the "everything scores 1.00" trap
the 40-row sample falls into). What is still needed is an evaluation on non-synthetic data —
nothing in the repo substitutes for that.

## 3. Noise Assumptions

**Weakness.** The only noise modeled is 3 % uniform label noise in the generator, and a
synthetic "power-user" overlap baked into the benign distribution. The evaluation makes no
provision for feature noise, missing values, timestamp jitter, mislabeled *features* (as
opposed to labels), or hosts whose telemetry is partially captured. The 40-row sample has no
noise at all.

**Mitigation / what is needed.** `generate_telemetry.py` accepts `--label-noise`, and the
overlap in the profiles keeps the problem from being trivially separable. The honest gap is
that robustness to sensor-level noise (dropped windows, out-of-order events, malformed
process names) is not tested. A reviewer wanting to probe this would need a noise-injection
pass that perturbs features and timestamps and re-checks whether the detector rankings hold.

## 4. Portability Limits

**Weakness.** The pipeline is built around a fixed 11-feature CSV schema and a fixed
Windows-flavored threat model (shadow-copy tampering, powershell/mshta/certutil as
abuse-prone binaries, `.exe` processes). Two things are therefore not portable without work:
(1) non-Windows hosts or non-Windows-specific attacks, and (2) any telemetry source whose
features do not map cleanly onto the schema (e.g., Linux audit logs, container metrics).

**Mitigation / what is needed.** The feature extraction is deliberately small and documented,
and `docs/DATA.md` explains how Sysmon events map onto the per-window features. The
reputation list is extendable via a CSV (`--reputation-csv`), which covers re-targeting the
abuse-prone binary set. A true portability argument would require running the same code on a
second telemetry source and showing the metrics hold up.

## 5. Sources of Optimistic Bias

**Weakness.** Several design choices push metrics in a favorable direction:

- **Contamination is fixed and given the answer.** `--contamination` defaults to 0.2; the
  unsupervised methods are told how much of the data is anomalous, and the choice is not
  swept or learned. A tuned contamination would change the precision/recall trade.
- **The calibrated ensemble's weights are estimated on the training labels** (per-method
  precision on the very data being scored), not recalibrated on a holdout set. Its ~0.75 F1
  on the sample is therefore an optimistic, in-sample estimate.
- **The rule thresholds (CPU ≥ 85, renames ≥ 80, entropy ≥ 7.4, etc.) are hand-tuned on the
  sample and then evaluated on data the generator was designed to resemble.** There is no
  held-out tuning split for the rules.
- **Standardization is fit on the full dataset** before cross-validation. The JOURNAL shows
  this is inert for Random Forest (scale-invariant, byte-identical predictions) but would
  become real leakage if a scale-sensitive estimator (logistic regression, SVM, kNN) were
  added.
- **The progression detector's stage rule encodes the author's assumption** of a canonical
  recon → tamper → encrypt order rather than learning it. It also flags a host as soon as a
  single full path completes and keeps the flag set, which can inflate its recall on hosts
  that are really reusing staged-looking windows.
- **The strongest synthetic numbers (ensemble F1 0.81) are not the headline claim.** The
  repo is honest about this, but a reader skimming the README table could over-read them.

**Mitigation / what is needed.** PAPER.md already documents the leakage smell, the fixed
contamination, the training-set weight estimation, and the hand-built stage rule as
limitations. The concretely missing pieces a reviewer should ask for:

1. A held-out test split (or a proper CV Pipeline for scaling) so no metric is computed on
   data the rules or weights were tuned/estimated on.
2. A contamination sweep showing how ensemble operating points move.
3. An ablation isolating the progression detector (same ensemble, progression on/off) —
   currently its 0.3765 F1 on the synthetic set is visible only as a row in the comparison.
4. A threshold sweep or operating-point figure for the calibrated ensemble.
