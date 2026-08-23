# HBBMAAD Publication-Grade RADAR Plan

**Scope:** step 1 of the portfolio's re-prioritized roadmap. This is a **plan only — no
code changed.** It is grounded in the current repo (read 2026-08-23).

## Current state (what actually exists)

- `sysmon_adapter.py` — converts raw RADAR Sysmon events to per-(host, 5-min) windows,
  deriving 10 Sysmon-recoverable features + `event_count` + `label`.
- `real_data_eval.py` — runs the comparative stack (IsolationForest, LOF, RandomForest,
  majority vote) on any labeled numeric frame. Reports F1/P/R per method + one RF AUC.
- Committed data: `data/radar_real_windows.csv` (4,283 windows: 3,740 benign / 543
  ransomware, ~13% attack), `results/radar_real_eval.json`.
- Existing headline (random 5-fold CV): RF F1 0.515 / AUC 0.818; IF 0.397; LOF 0.163;
  vote 0.482 (P 0.674 / R 0.378).
- `REAL_DATA_RESULTS.md`, `PAPER.md`, `PUBLICATION_NOTES.md`, `README.md` already
  foreground RADAR as the headline and demote synthetic to development-only — but they are
  **not fully consistent** (see gap 5).

## The blocking constraint (read before planning)

The committed `radar_real_windows.csv` columns are:
`timestamp, host, process_name, <10 features>, event_count, label`.
It has **no family / sample / run identifier** — `host` is the Windows user+machine
context, not the ransomware family. The family (Akira, BlackBasta, LockBit, ...) lives only
in the **raw per-sample RADAR CSVs**, which are not committed.

**Consequence:** the roadmap's central requirement — *strict family/session hold-out with
benign sessions from held-out periods kept out of training* — **cannot be done on the
committed windows file**. It needs the raw RADAR download and an adapter change that tags
each window with its originating family/sample/run. The raw files are gated (Zenodo DOI
`10.5281/zenodo.14564541`), so this is a real data-acquisition step.

There is a secondary, softer option: **per-host leave-one-host-out** using the existing
`host` column as a session proxy. It is weaker (host ≠ family) and not a substitute, but it
can run today on committed data and gives an interim strict-split result. The plan does
both: host-level now (no download), family-level after the raw files are obtained.

---

## Steps (in dependency order)

### 1. Freeze the RADAR preprocessing (a manifest, not code)

Create `radar_manifest.json` recording, exactly:
- raw file names + SHA-256 for every goodware/ransomware CSV used (from the download).
- window size (5 min), label rule (per-event `target-class`; ransomware CSV forced to 1),
  `--goodware-sample` (400000), feature list (the 10 + `event_count`), random seed 42.
- package versions in a `requirements-lock.txt` (currently `requirements.txt` is unpinned
  beyond the CI: the same version-drift the repo already flags).

This is the "frozen requirements and data manifest" the roadmap's common final step needs.

### 2. Adapter change: tag family / sample / run (blocking for family splits)

- Extend `sysmon_adapter.py` so each `--ransomware <file>` and the goodware source attach a
  `family` column (from the CSV filename, e.g. `Akira-...` → `Akira`; goodware → `Goodware`)
  and a `run`/`session` id. Keep the current no-metadata output path byte-identical for
  back-compat (add a `--include-metadata` flag, mirroring the network-detector pattern).
- Reproduce `data/radar_real_windows.csv` unchanged, and write a new
  `data/radar_real_windows_with_family.csv`.

### 3. Threshold/contamination tuning on an inner validation split

Current `real_data_eval.py` sets `--contamination` (0.13) from the known test prevalence —
the roadmap explicitly forbids tuning on the 13%. Replace with:
- an inner Validation split of each *training* fold; choose `contamination` (and any
  threshold / n_neighbors / RF agnostic choices) on that inner split only;
- then apply once to the untouched test split. Report the chosen value as a tuning log.

### 4. Strict-split evaluation (the main evidence)

New `radar_strict_eval.py` (or extend `real_data_eval.py` with a `--split` mode):
- **Family hold-out (post-download):** train on some families' windows (plus benign from
  non-held-out periods), test on held-out families' windows. Benign windows belonging to a
  held-out family/period are excluded from training.
- **Session/host hold-out (works today):** leave-one-host-out on the committed `host`
  column as an interim; explicit that this is a session proxy, not a family split.
- Never randomly shuffle related captures across train/test.

### 5. Real-data ablation (all comparators on the same windows)

Extend the method list to evaluate fairly on RADAR windows:
- rule-based (Sysmon event-threshold rules — must be redefined for RADAR window features,
  since `monitor.py`'s 11-feature rules do not transfer),
- IsolationForest, LOF, RandomForest,
- unweighted ensemble (majority vote),
- weighted ensemble (precision-calibrated weights, as `monitor.py`),
- progression logic **only if it can be evaluated fairly** on RADAR sequences — RADAR is
  short per-host windows, so the recon→tamper→encrypt trajectory may not fit the available
  sequence length; if it cannot be evaluated fairly, say so and omit, rather than shoehorn.

### 6. Full metric set

Report for every comparator, per held-out split and pooled:
- F1, precision, recall, ROC-AUC,
- recall at fixed false-positive rates (e.g. 1% and 10%),
- 95% confidence intervals (repeated-seed / bootstrap, as in the network-detector
  `active_learning_stats.py`),
- per-family results (post-download).

### 7. Doc consistency pass (RADAR = headline evidence)

Make every document agree that RADAR is the headline and synthetic is development-only:
- `README.md` Results table, `PAPER.md` abstract §Results, `REAL_DATA_RESULTS.md`,
  `PUBLICATION_NOTES.md`, `RESULTS_TABLE.md`.
- Fix `ARTIFACT_CHECKLIST.md` (currently stale: it documents only synthetic steps, 24 tests,
  and omits the real-data pipeline). Add the exact strict-eval reproduction command and the
  frozen manifest/requirements.
- Update the test count (the repo now has more than the 24 the checklist claims).

### 8. Anonymized 8-10 page paper

Narrow claim: **supervised detection beats unsupervised baselines on RADAR, but
performance is sensitive to family/session shift** (and, per the strict splits, the 13%
random-CV number is in-distribution-optimistic). Reuse the network-detector's anonymized
paper builder pattern. Evidence appendix: `RESULTS_STRICT_EVALUATION.md`-style tables.

---

## Review-ready gate (from the roadmap)

- [ ] Strict results reproduced from one command (`python radar_strict_eval.py`).
- [ ] Claims consistent across README / paper / results.
- [ ] Artifact checklist complete (frozen manifest, requirements-lock, data manifest).
- [ ] Three review questions answered: ("Is the claim narrow enough?", "Is the split
      protocol sound?", "What experiment would most change your confidence?")

## What I will NOT do (scope guard)

- No synthetic-generator changes; synthetic stays development-only.
- No progression-logic shoehorning if it can't be evaluated fairly on RADAR.
- No live-enterprise claims — RADAR is lab-generated malware-with-real-Sysmon and is stated
  as such.

## Immediate next action (pick one)

1. **Interim, no-download work:** add the strict host-level split + full metric set + CI on
   the *committed* windows file, producing a real strict-split result today. (Low risk.)
2. **Full family split:** download the RADAR raw files (Zenodo), tag family in the adapter,
   then run family hold-out. (Requires the gated download + ~more time.)
3. **Just doc consistency first:** the doc sweep (step 7) and stale-checklist fix can be done
   without any new experiments.
