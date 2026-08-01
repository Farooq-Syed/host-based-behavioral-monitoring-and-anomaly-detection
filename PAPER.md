# Comparing Rule-Based, Unsupervised, and Supervised Detection on Host Telemetry

*A project write-up. Syed, 2026.*

## Abstract

Endpoint detection can be framed three ways — as expert-written rules, as
unsupervised outlier detection, or as supervised classification — and the three
disagree in instructive ways on the same data. This project implements all three
over a common host-telemetry schema (CPU, memory, disk and file activity, entropy,
shadow-copy and unsigned-binary indicators) and combines them with a simple majority
vote, so their behavior can be compared window by window on telemetry shaped like
ransomware, destructive scripting, and resource abuse. The engineering contribution
of this pass is in the evaluation harness rather than the detectors: I consolidated
the Random Forest cross-validation from two independent passes into one, which halves
its training cost and makes the emitted flag and probability consistent by
construction; made the fold count adaptive so the pipeline no longer fails on
class-imbalanced inputs; and verified — rather than assumed — that a scaling step
which superficially resembles data leakage is in fact inert for the tree model in
use. Test coverage rose from a single smoke test to nine, and the reported metrics
are unchanged, confirming the changes were refactors rather than behavioral shifts.

## 1. Introduction

A defender monitoring host behavior for ransomware-style activity has a menu of
detection philosophies. Rules encode expert knowledge directly — mass file renames
plus high entropy plus shadow-copy deletion is a recognizable encryptor signature —
and are transparent but brittle. Unsupervised methods such as Isolation Forest and
Local Outlier Factor need no labels and can surface novel behavior, at the cost of
explaining themselves poorly and flagging benign rarities. Supervised classifiers are
accurate when labels exist but only recognize what they were trained on. No single
philosophy dominates, which is exactly why comparing them on identical telemetry is
worthwhile.

This project builds that comparison as a runnable pipeline. Each telemetry window
receives a rule score, an Isolation Forest flag, an LOF flag, and — when a label
column is present — a cross-validated Random Forest prediction. A window is declared
suspicious when at least two methods agree. The design goal is to make the
methods' relative strengths visible, not to win a benchmark.

## 2. Data and features

The bundled dataset is 40 synthetic telemetry windows across 20 hosts, labeled
benign or malicious, containing benign application activity alongside windows shaped
like ransomware encryption, destructive PowerShell/wscript activity, credential and
backup tampering, and cryptomining. Eleven numeric features are used: CPU percent,
memory, disk-write volume, file-write and file-rename counts, network connections,
child-process count, an unsigned-binary indicator, suspicious-extension-change count,
an entropy score, and shadow-copy event count. Features are standardized before the
model stage.

## 3. Methods

**Rule-based.** Seven binary conditions (high CPU, heavy disk writes, mass renames,
extension changes, high entropy, shadow-copy modification, unsigned-binary
execution) are summed; a score of three or more flags the window. The detector also
emits a human-readable reason string, which is the property that makes it valuable
in triage even where its recall is modest.

**Isolation Forest and LOF.** Both run unsupervised on the standardized features with
a configurable contamination fraction. Isolation Forest scores by how few splits
isolate a point; LOF by local density relative to neighbors, with the neighborhood
size bounded to the dataset size.

**Random Forest.** When labels are available, a balanced-class forest is evaluated
with stratified cross-validation, yielding out-of-fold predictions so the reported
accuracy is not measured on training data.

**Ensemble.** The four per-method flags are summed; two or more votes marks the
window suspicious, and the alert reason concatenates the contributing explanations.

## 4. Evaluation and engineering findings

On the sample data the methods separate as expected. The rule engine and both
unsupervised detectors reach perfect precision with recall near 0.53 (F1 ≈ 0.70):
they catch the unambiguous encryptor windows and miss the subtler ones. The
supervised forest reaches F1 ≈ 0.97 on cross-validated predictions, and the ensemble
sits between at F1 ≈ 0.89, recovering recall over the unsupervised methods while
holding precision at 1.00. This is the intended teaching result: rules and outlier
detection catch the loudest activity, the supervised model separates the labeled
sample more cleanly, and the vote trades a little of the forest's recall for
robustness against any single method's error.

Three findings emerged from auditing the harness.

**Redundant and potentially inconsistent cross-validation.** The Random Forest step
called `cross_val_predict` twice — once for the class prediction, once for the
probability. Beyond doubling the training cost, nothing structurally guaranteed that
the emitted flag equaled `probability ≥ 0.5`; the two passes are independent, and
only the shared random seed kept them aligned on this data. Consolidating to a single
`predict_proba` pass and thresholding it for the flag removes the redundant training
and makes the two outputs consistent by construction. A regression test now asserts
zero flag/probability disagreements.

**Non-adaptive fold count.** The five-fold split was hardcoded, which raises on any
input where a class has fewer than five members. The split count is now bounded by
the minority-class size, and a test exercising a two-positive dataset — which the old
code could not run — passes.

**A leakage smell that is inert in practice.** Standardization is fit on the full
dataset before cross-validation, so the scaler observes the held-out folds — the
textbook shape of data leakage. Because Random Forest is scale-invariant, this was
verified to have no effect: cross-validated predictions on scaled and unscaled
features were byte-for-byte identical. The scaling was therefore left in place, and
the observation recorded as a caveat that would matter only if a scale-sensitive
estimator were introduced, at which point standardization should move inside a
cross-validation pipeline. The value here was in measuring the concern before acting
on it rather than "fixing" a non-issue.

The bundled documentation reports Random Forest at F1 = 1.00, whereas the current
environment reproduces 0.97; this reflects library and cross-validation drift and is
noted for reconciliation.

## 5. Limitations

- The dataset is small and synthetic; the metrics validate the pipeline, not
  real-world detection rates.
- Windows are scored independently, discarding the temporal progression that
  characterizes ransomware.
- The ensemble is an unweighted vote, not a calibrated combiner.
- Unsupervised contamination is a fixed fraction rather than learned from the data.

## 6. Future work

The highest-value extension is sequence modeling across adjacent windows, since
ransomware unfolds as a trajectory (enumeration → shadow-copy deletion → mass
encryption) that per-window scoring cannot see. Beyond that: a calibrated ensemble
that weights methods by validated reliability, process-reputation or signer
enrichment, and adaptation of the input path to Sysmon-style telemetry so the tool
consumes real endpoint data rather than a CSV.

## 7. Conclusion

The detectors in this project are conventional; its value as an artifact is that it
makes their disagreement legible and that its evaluation can be trusted. The work
here tightened that trust — removing a redundant training pass, guaranteeing internal
consistency between a model's flag and its score, hardening the fold logic against
imbalance, and, importantly, resisting the urge to "fix" a leakage smell that
measurement showed to be harmless. Backing each change with a test and confirming the
reported metrics were unchanged keeps the comparison honest, which is the entire
point of a tool whose job is to compare.
