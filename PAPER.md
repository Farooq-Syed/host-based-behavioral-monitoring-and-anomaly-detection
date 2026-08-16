# Three Ways to Detect Ransomware — and the Progression It Actually Is

**Farooq Syed** · M.S. in Computer and Information Security Systems, Eastern Illinois University · 2026

*Independent research portfolio, prepared as part of a PhD application in cybersecurity.
Developed with AI coding assistance; all methods, experiments, and findings were
directed, reviewed, and verified by the author.*

## Abstract

Endpoint detection can be framed three ways — as expert-written rules, as
unsupervised outlier detection, or as supervised classification — and the three
disagree in instructive ways on the same telemetry. This project implements all
three over a common host-telemetry schema and combines them with a vote, so their
behavior can be compared window by window on data shaped like ransomware,
destructive scripting, and resource abuse. Two later additions changed the shape of
the project rather than just the scoreboard. The first is a *progression* detector
that stops scoring windows in isolation and instead walks each host's history in
time, only calling the encryption stage part of an attack trajectory when the
earlier stages (recon, shadow-copy tampering) actually preceded it. The second is a
precision-calibrated ensemble that replaces the unweighted vote with a weighted one,
letting each detector count only as much as it has earned. Along the way the
evaluation harness got two fixes worth mentioning: the Random Forest's
cross-validation was consolidated from two passes into one (halving its training
cost and making its flag and score consistent by construction), and the fold count
became adaptive so the pipeline no longer fails on class-imbalanced inputs.

## 1. The question

A defender watching host telemetry for ransomware has a menu of detection
philosophies. Rules encode expert knowledge directly — mass file renames plus high
entropy plus shadow-copy deletion is a recognizable encryptor signature — and are
transparent but brittle. Unsupervised methods like Isolation Forest and Local
Outlier Factor need no labels and can surface novel behavior, at the cost of
explaining themselves poorly and flagging benign rarities. Supervised classifiers
are accurate when labels exist but only recognize what they were trained on. No
single philosophy dominates, which is exactly why comparing them on identical
telemetry is worthwhile.

The second question is one I think matters more: ransomware is not a snapshot, it
is a *sequence*. The encryptor window is the loudest thing in the log, but it is
not the attack — the attack is the whole arc, from enumeration through shadow-copy
deletion to mass encryption. A detector that scores each window by itself cannot
tell a real trajectory from an unlucky coincidence of features.

## 2. Data and features

The bundled dataset is 40 synthetic telemetry windows across 20 hosts, labeled
benign or malicious, containing benign application activity alongside windows shaped
like ransomware encryption, destructive scripting, credential and backup tampering,
and cryptomining. Eleven numeric features are used: CPU percent, memory, disk-write
volume, file-write and file-rename counts, network connections, child-process count,
an unsigned-binary indicator, suspicious-extension-change count, an entropy score,
and shadow-copy event count. A documented generator (`generate_telemetry.py`)
produces a larger 2,000-row dataset with overlapping class distributions and
injected label noise, so the methods separate realistically rather than trivially.

## 3. Methods

**Rule-based.** Seven binary conditions are summed; a score of three or more flags
the window. The detector emits a human-readable reason string, which is what makes
it valuable in triage even where its recall is modest.

**Isolation Forest and LOF.** Both run unsupervised on standardized features with a
configurable contamination fraction. Isolation Forest scores by how few splits
isolate a point; LOF by local density relative to neighbors, with the neighborhood
size bounded to the dataset size.

**Random Forest.** When labels are available, a balanced forest is evaluated with
stratified cross-validation, yielding out-of-fold predictions so the reported
accuracy is not measured on training data. The flag and score come from a single
`predict_proba` pass, so the two cannot disagree.

**Progression.** For each host, windows are walked in time order and the set of
observed stages is tracked. A stage only counts once its predecessor has appeared:
a window is not part of an encryption trajectory unless recon (mass renames,
extension churn, unsigned code) and tampering (shadow-copy modification) were seen
earlier on the same host. Once a full 1→2→3 path completes, the flag stays set for
that host.

**Reputation.** A small hand-maintained map marks binaries that attackers routinely
lean on — `powershell.exe`, `mshta.exe`, `certutil.exe`, and friends — as
"abuse-prone." This is deliberately not a malware list; it is a weight. The
enrichment is extendable with a CSV.

**Ensemble.** The four core detectors vote (majority, two or more flags). A
calibrated variant replaces the vote with a weighted combination where each
detector's weight is its precision on the training labels, so a method that never
fires — or fires at random — counts for almost nothing.

## 4. Results

On the sample data the methods separate as expected. The rule engine and both
unsupervised detectors reach perfect precision with recall near 0.53 (F1 ≈ 0.70):
they catch the unambiguous encryptor windows and miss the subtler ones. The
supervised forest reaches F1 = 1.00 on cross-validated predictions, and the
majority-vote ensemble sits between at F1 ≈ 0.89, recovering recall while holding
precision at 1.00.

The weighted ensemble is a different creature. Because the rules are nearly perfect
when they fire, weighting by precision hands them most of the say; the result is
more conservative — F1 ≈ 0.75 with recall 0.60 on the sample — and, honestly, more
like what a defender who has to triage every alert would want. The interesting
finding is that precision weighting does not simply reproduce the best method; it
changes the operating point of the whole pipeline, which is precisely the knob a
cost-aware deployment needs.

The progression detector is honest about what the sample can and cannot show. None
of the 40 bundled windows forms a full recon → tampering → encryption arc on a single
host, so it flags nothing on this small set — which is the correct behavior for data
that contains no trajectory. Its value shows where the ordering exists: on the larger
synthetic set, and on any real multi-window host where the loud encryptor window is
preceded by quieter staging. The reputation detector, similarly, is modest on the
sample (F1 ≈ 0.38): the built-in list is a weak prior, not a detector, and it is
deliberately weighted that way in the calibrated ensemble.

## 5. What the audit of my own harness found

Three findings came out of checking the evaluation code, and each is worth keeping
on the record.

**Redundant cross-validation.** The Random Forest step called `cross_val_predict`
twice — once for the class, once for the probability. Beyond doubling the cost,
nothing structurally guaranteed the flag equaled `probability ≥ 0.5`; the two passes
were independent and only a shared seed kept them aligned. Consolidating to one
`predict_proba` pass removed the redundancy and made the outputs consistent by
construction. A regression test now asserts zero flag/score disagreements.

**Hardcoded folds.** The five-fold split was hardcoded and raised on any input where
a class had fewer than five members. The split count is now bounded by the
minority-class size, and a test exercising a two-positive dataset — which the old
code could not run — passes.

**A leakage smell that is inert in practice.** Standardization is fit on the full
dataset before cross-validation, so the scaler observes the held-out folds — the
textbook shape of data leakage. Because Random Forest is scale-invariant, this was
verified to have no effect: cross-validated predictions on scaled and unscaled
features were byte-for-byte identical. The scaling was left in place and the caveat
recorded; it would matter only if a scale-sensitive estimator were introduced.

## 6. Limitations

- The dataset is small and synthetic; the metrics validate the pipeline, not
  real-world detection rates.
- The progression detector is a hand-built stage rule, not a learned model. It
  encodes my assumption about the canonical order rather than discovering it.
- The weighted ensemble's weights come from training-set precision and are not
  recalibrated on a holdout set.
- Unsupervised contamination is a fixed fraction rather than learned from the data.

## 7. Future work

The natural next step is replacing the hand-built stage rule with a real sequence
model over the trajectory — first transparent features (stage-transition counts),
then proper sequence models — on a real endpoint dataset. A calibrated combination
that is validated on holdout data rather than training data, and process signer
enrichment beyond a name-based map, are both on the list. The input path should
grow to consume Sysmon-style telemetry so the tool works on real endpoint data
rather than a CSV.

## 8. Conclusion

The detectors here are conventional; the project's worth is that it makes their
disagreement legible and that its evaluation can be trusted. The two additions
changed what the tool can say: the progression detector lets it describe an attack
as a sequence rather than a set of loud moments, and the calibrated ensemble lets
it trade precision against recall deliberately instead of by accident. Backing
each change with a test, and confirming the reported metrics were unchanged where
they should be, keeps the comparison honest — which is the entire point of a tool
whose job is to compare.
