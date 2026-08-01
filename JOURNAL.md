# Dev journal — host behavioral monitoring

Cleanup pass notes. This is the most "ML-heavy" of my projects so I spent most of
the time poking at the evaluation code rather than the detection rules, which were
fine.

## What it does, quickly

Reads a CSV of host telemetry windows — CPU, memory, disk writes, file renames,
entropy, shadow-copy events, unsigned-binary flags, that kind of thing — and runs
four detectors over each window: a hand-written rule score, Isolation Forest, Local
Outlier Factor, and (when labels exist) a cross-validated Random Forest. Then it
takes a majority-ish vote: two or more methods agree, it's suspicious. The whole
point of the project is the *comparison* — showing how a rule engine, unsupervised
outlier detection, and a supervised model behave on the same stream.

Baseline run on the 40-row sample, before I touched anything:

- 40 windows, 20 hosts, 12 flagged suspicious
- rule / IF / LOF all land at F1 ≈ 0.70 (perfect precision, ~0.53 recall)
- RF at F1 ≈ 0.97
- ensemble at F1 ≈ 0.89

Side note: the README table says RF = 1.00 across the board. My run gives 0.97. Not
a bug, just sklearn/CV drift between whenever that table was captured and now — but
I should reconcile the README at some point instead of leaving a number that doesn't
reproduce.

## The thing I chased and it turned out fine

My first instinct looking at `scale_features` was "that's data leakage." It does
`StandardScaler().fit_transform` on the *entire* dataset, and then the Random Forest
gets cross-validated on that already-scaled matrix. So the scaler has seen the
held-out folds — textbook leakage.

Then I stopped and actually tested it before writing anything down, because Random
Forest is scale-invariant. Trees split on thresholds; multiplying a feature by a
constant doesn't change the split order. I ran it both ways:

```
RF f1 scaled : 0.9677
RF f1 raw    : 0.9677
identical predictions? True
```

Identical. So the "leakage" is real in the pedantic sense but completely inert for
this model. I decided *not* to rip the scaling out and pretend I fixed a bug I
didn't. The honest note is: it's a smell that would bite you the moment you swapped
in a scale-sensitive model (logistic regression, SVM, kNN), so it's worth flagging,
but it changes nothing about the current numbers. Glad I checked instead of
confidently "fixing" something.

## The thing that was actually worth fixing

The RF detector called `cross_val_predict` **twice** — once with `method="predict"`
for the flag, once with `method="predict_proba"` for the score:

```python
predictions   = cross_val_predict(model, X, y, cv=cv, method="predict")
probabilities = cross_val_predict(model, X, y, cv=cv, method="predict_proba")[:,1]
```

Two problems. One, it trains the forest twice for no reason — that's the slowest part
of the pipeline doubled. Two, and more subtle: those are two independent CV passes.
With the same random_state the fold assignments match, so on this data the flag and
the score agree. But conceptually there's nothing *forcing* `flag == (score >= 0.5)`.
If someone later tweaked the splitter or the seed handling, you could end up with a
row flagged 1 while its own score is 0.4, and nobody would notice until a confused
analyst asked why.

Fix: do one `predict_proba` pass and derive the flag from the probability.

```python
probabilities = cross_val_predict(model, X, y, cv=splitter, method="predict_proba")[:,1]
report["random_forest_score"] = probabilities.round(4)
report["random_forest_flag"]  = (probabilities >= 0.5).astype(int)
```

Half the training work, and flag/score are consistent by construction. I added a test
that asserts zero rows where `(score>=0.5) != flag`. Same metrics out the other side
(RF still 0.97), which is what I wanted — a refactor, not a behavior change.

## While I was in the RF function

Hardcoded `n_splits=5`. If you ever feed this a dataset where one class has fewer
than 5 examples, StratifiedKFold throws. Made it adaptive:
`n_splits = max(2, min(5, n_positive, n_negative))`. Added a test with only 2
positive rows that would've crashed before and now runs clean.

Also: `matplotlib.use("Agg")` before importing pyplot, same headless fix I did on the
log-analysis project. And the smoke test had the same bare-`"python"` subprocess bug
— swapped it for `sys.executable`.

## Tests

Went from 1 smoke test to 9. The new `test_detection.py` covers `normalize_label`
(all the synonym sets plus the raise-on-unknown path), the rule detector on both a
ransomware-shaped row and a benign one, the RF flag/score consistency, the ensemble
2-vote rule, and the small-imbalanced-data case. All green.

## Next time

- Reconcile the README metrics table with what actually reproduces (or pin versions).
- The scaling-leakage smell: if I add a scale-sensitive baseline, move scaling inside
  a proper CV Pipeline so the estimate stays honest.
- Sequence modeling across adjacent windows — right now every window is judged on its
  own, but ransomware is a *progression* and the ordering carries signal I'm throwing
  away.
