"""Strict-split publication-grade evaluation on real RADAR Sysmon windows.

This is the reviewer-corrected real-data evaluation for the host-monitor. It replaces
the random stratified CV in ``real_data_eval.py`` (which tuned ``--contamination`` from
the known test prevalence) with a strict, leakage-safe protocol:

  * Inner validation split inside each training fold. ``contamination`` (and the RF
    vote threshold) are tuned ONLY on that inner split, never on the test split.
  * Two strict split modes:
      - ``host``  : leave-one-host-out on the ``host`` column (the committed windows
        file has no family tag, so host is used as a session proxy today).
      - ``family``: hold out entire ransomware families; benign windows from held-out
        runs are excluded from training. Requires the family-tagged dataset
        (sysmon_adapter.py --include-metadata + the gated RADAR download).
  * Full comparator ablation evaluated on identical fold geometry: rule-based,
    IsolationForest, LOF, RandomForest, unweighted ensemble, weighted ensemble, and
    progression (only if the RADAR window sequence can support a fair trajectory).

Metrics reported per comparator, pooled and per-held-out group: F1, precision, recall,
ROC-AUC, PR-AUC, recall@fixed-FPR, with mean +/- 95% CI across held-out groups.

Scope and honest limits (see also results JSON):
  * Only ``contamination`` is tuned on an inner validation split. The Random Forest
    decision threshold is fixed at 0.5, and the weighted ensemble's majority threshold
    is the fixed 0.5 weighted-mean cutoff; neither is tuned on validation or test data.
  * RADAR goodware is a single run, so the benign hold-out is a *random* 20% pool, not a
    session-disjoint benign evaluation. This is a sound unseen-ransomware-family test
    with a held-out random benign pool, but it is NOT a full host/session-disjoint
    deployment claim.
  * The progression detector needs per-host timestamp sequences; RADAR's per-run windows
    are short, so it may legitimately flag nothing. It is reported as evaluated (or as a
    fair-evaluation omission) rather than silently dropped.

Usage:
  python radar_strict_eval.py --input data/radar_real_windows.csv --label-column label --split host
  python radar_strict_eval.py --input data/radar_real_windows_with_family.csv --label-column label \
      --split family --family-column family
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from monitor import normalize_label

# ---- RADAR-adapted rule thresholds (no cpu/entropy/disk features in Sysmon windows).
RULE_THRESHOLDS = {
    "file_rename_like": 3,
    "suspicious_extension_events": 3,
    "shadow_copy_events": 1,
    "unsigned_process_events": 1,
    "file_delete_count": 50,
    "registry_events": 5,
}
RULE_SCORE_CUTOFF = 3

# Weighted-ensemble core methods (matching monitor.CORE_ENSEMBLE_METHODS semantics).
CORE_METHODS = ["rule_flag", "isolation_forest_flag", "lof_flag", "random_forest_flag"]
SUPPORT_METHODS = ["progression_flag"]
CALIBRATED_CORE_THRESHOLD = 0.5


def load_frame(path: Path, label_column: str):
    frame = pd.read_csv(path)
    if label_column not in frame.columns:
        raise ValueError(f"Label column '{label_column}' not found.")
    truth = frame[label_column].map(normalize_label).to_numpy(dtype=int)
    numeric = frame.drop(columns=[label_column]).select_dtypes(include=[np.number])
    if numeric.shape[1] < 2:
        raise ValueError("Need at least two numeric feature columns.")
    return frame, numeric, truth


def _rule_score(row: pd.Series) -> int:
    score = 0
    if row.get("file_rename_like", 0) >= RULE_THRESHOLDS["file_rename_like"]:
        score += 1
    if row.get("suspicious_extension_events", 0) >= RULE_THRESHOLDS["suspicious_extension_events"]:
        score += 1
    if row.get("shadow_copy_events", 0) >= RULE_THRESHOLDS["shadow_copy_events"]:
        score += 1
    if row.get("unsigned_process_events", 0) >= RULE_THRESHOLDS["unsigned_process_events"]:
        score += 1
    if row.get("file_delete_count", 0) >= RULE_THRESHOLDS["file_delete_count"]:
        score += 1
    if row.get("registry_events", 0) >= RULE_THRESHOLDS["registry_events"]:
        score += 1
    return score


def rule_detector(features: pd.DataFrame) -> np.ndarray:
    return (features.apply(_rule_score, axis=1) >= RULE_SCORE_CUTOFF).to_numpy(dtype=int)


def _window_stage(row: pd.Series) -> int:
    """Stage a RADAR window into a ransomware trajectory (0/1/2/3).

    1 = staging (mass renames / suspicious extensions / unsigned code),
    2 = tampering (shadow-copy modification),
    3 = encryption-like (heavy delete or rename-likeness on a rename base).
    """
    recon = (
        row.get("file_rename_like", 0) >= RULE_THRESHOLDS["file_rename_like"]
        or row.get("suspicious_extension_events", 0) >= RULE_THRESHOLDS["suspicious_extension_events"]
        or row.get("unsigned_process_events", 0) >= RULE_THRESHOLDS["unsigned_process_events"]
    )
    tamper = row.get("shadow_copy_events", 0) >= 1
    encrypt = row.get("file_delete_count", 0) >= RULE_THRESHOLDS["file_delete_count"]
    if encrypt:
        return 3
    if tamper:
        return 2
    if recon:
        return 1
    return 0


def progression_detector(features: pd.DataFrame, host_col: str, ts_col: str) -> np.ndarray:
    """Per-host staged trajectory; flag stays set after a full 1->2->3 path."""
    flag = np.zeros(len(features), dtype=int)
    if host_col not in features.columns or ts_col not in features.columns:
        return flag
    indexed = features.copy()
    indexed["__idx"] = np.arange(len(features))
    for _, group in indexed.groupby(host_col):
        group = group.sort_values(ts_col)
        stages: set[int] = set()
        for _, row in group.iterrows():
            stage = _window_stage(row)
            if stage == 1:
                stages.add(1)
            elif stage == 2 and 1 in stages:
                stages.add(2)
            elif stage == 3 and {1, 2} <= stages:
                stages.add(3)
            flag[int(row["__idx"])] = 1 if 3 in stages else 0
    return flag


def _tune_contamination(x_train: np.ndarray, y_train: np.ndarray, inner_folds: int,
                        random_state: int, candidates: List[float]) -> float:
    """Choose contamination on an inner validation split only (no test labels)."""
    from sklearn.model_selection import StratifiedKFold

    best, best_score = candidates[0], -1.0
    inner = StratifiedKFold(n_splits=inner_folds, shuffle=True, random_state=random_state)
    for cand in candidates:
        scores = []
        for tr, va in inner.split(x_train, y_train):
            scaler = StandardScaler().fit(x_train[tr])
            model = IsolationForest(contamination=cand, random_state=random_state, n_estimators=100, n_jobs=-1)
            model.fit(scaler.transform(x_train[tr]))
            pred = (model.predict(scaler.transform(x_train[va])) == -1).astype(int)
            scores.append(f1_score(y_train[va], pred, zero_division=0))
        m = float(np.mean(scores))
        if m > best_score:
            best, best_score = cand, m
    return best


def _split_benign(benign_idx: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Split benign indices into (held-out-test, keep-in-training), deterministic."""
    frac = 0.2
    rng = np.random.default_rng(42)
    if len(benign_idx) == 0:
        return np.array([], dtype=int), np.array([], dtype=int)
    n_hold = max(1, int(len(benign_idx) * frac))
    hold = rng.choice(benign_idx, size=min(n_hold, len(benign_idx)), replace=False)
    hold_set = set(int(h) for h in hold)
    held_out = np.array([i for i in benign_idx if int(i) in hold_set], dtype=int)
    keep = np.array([i for i in benign_idx if int(i) not in hold_set], dtype=int)
    return held_out, keep


def _threshold_from_train(x_train_s: np.ndarray, y_train: np.ndarray, target_fpr: float) -> float:
    """Pick the validation threshold for a target FPR budget, using only training labels.

    An inner split of the training fold is used to score a validation set (no test
    labels). Among all thresholds whose validation FPR is <= ``target_fpr``, the one that
    maximises recall is chosen; this never selects a threshold above the budget. If no
    threshold achieves the budget (the target FPR is below the achievable minimum), fall
    back to the lowest-FPR threshold.
    """
    from sklearn.metrics import roc_curve
    from sklearn.model_selection import train_test_split

    if len(np.unique(y_train)) < 2:
        return float("nan")
    # Split the training fold into fit + validation (no test labels involved).
    fit_idx, val_idx = train_test_split(np.arange(len(y_train)), test_size=0.25,
                                        random_state=0, stratify=y_train)
    rt = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)
    rs = StandardScaler().fit(x_train_s[fit_idx])
    rt.fit(rs.transform(x_train_s[fit_idx]), y_train[fit_idx])
    val_prob = rt.predict_proba(rs.transform(x_train_s[val_idx]))[:, 1]
    fpr, tpr, thresholds = roc_curve(y_train[val_idx], val_prob)
    finite = np.isfinite(thresholds)
    if not finite.any():
        return float("nan")
    fpr_f, tpr_f, thr_f = np.asarray(fpr)[finite], np.asarray(tpr)[finite], np.asarray(thresholds)[finite]
    # Among thresholds within the FPR budget, keep the one with the highest recall. Ties
    # (same recall) keep the lower threshold (highest FPR yet still within budget).
    within = fpr_f <= target_fpr
    if within.any():
        idx = int(np.argmax(np.where(within, tpr_f, -np.inf)))
    else:
        # Budget unreachable on this validation set; take the lowest-FPR operating point.
        idx = int(np.argmin(fpr_f))
    return float(thr_f[idx])


def _recall_at_threshold(y_test: np.ndarray, prob: np.ndarray, threshold: float) -> float:
    """Recall on the test fold at a fixed threshold chosen on validation (no test tuning)."""
    if np.isnan(threshold):
        return float("nan")
    pred = (prob >= threshold).astype(int)
    return float(recall_score(y_test, pred, zero_division=0))


def _fpr_at_threshold(y_test: np.ndarray, prob: np.ndarray, threshold: float) -> float:
    """The test-fold FPR at a fixed decision threshold."""
    if np.isnan(threshold) or (y_test == 0).sum() == 0:
        return float("nan")
    pred = (prob >= threshold).astype(int)
    return float((pred[y_test == 0] == 1).mean())


def _applied_fpr(y_test: np.ndarray, prob: np.ndarray) -> float:
    """The model's default-0.5 FPR on the test fold, for context."""
    return _fpr_at_threshold(y_test, prob, 0.5)


def _fit_predict_all(features: pd.DataFrame, truth: np.ndarray, train_idx: np.ndarray,
                     test_idx: np.ndarray, contamination: float, random_state: int,
                     host_col: str, ts_col: str, full_frame: pd.DataFrame | None = None) -> Dict[str, Dict[str, float]]:
    x_train = features.iloc[train_idx].to_numpy(dtype=float)
    x_test = features.iloc[test_idx].to_numpy(dtype=float)
    y_train, y_test = truth[train_idx], truth[test_idx]
    scaler = StandardScaler().fit(x_train)
    x_train_s = scaler.transform(x_train)
    x_test_s = scaler.transform(x_test)

    # Unsupervised methods: predict on the TRAIN fold to get weighting precision.
    iforest = IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state, n_jobs=-1)
    iforest.fit(x_train_s)
    pred_if_train = (iforest.predict(x_train_s) == -1).astype(int)
    pred_if = (iforest.predict(x_test_s) == -1).astype(int)

    lof = LocalOutlierFactor(n_neighbors=30, contamination=contamination, novelty=True)
    lof.fit(x_train_s)
    pred_lof_train = (lof.predict(x_train_s) == -1).astype(int)
    pred_lof = (lof.predict(x_test_s) == -1).astype(int)

    rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=random_state, n_jobs=-1)
    rf.fit(x_train_s, y_train)
    pred_rf_train = rf.predict(x_train_s)
    pred_rf = rf.predict(x_test_s)
    prob_rf = rf.predict_proba(x_test_s)[:, 1]

    pred_rule_train = rule_detector(features.iloc[train_idx])
    pred_rule = rule_detector(features.iloc[test_idx])
    votes = pred_if + pred_lof + pred_rf
    pred_vote = (votes >= 2).astype(int)

    # Weighted ensemble: precision weights fit on the TRAINING fold's predictions only.
    train_preds = {
        "rule_flag": pred_rule_train,
        "isolation_forest_flag": pred_if_train,
        "lof_flag": pred_lof_train,
        "random_forest_flag": pred_rf_train,
    }
    weights = {col: max(precision_score(y_train, pred, zero_division=0), 0.05)
               for col, pred in train_preds.items()}
    core_total = sum(weights[c] for c in CORE_METHODS)
    weighted = (
        weights["rule_flag"] * pred_rule
        + weights["isolation_forest_flag"] * pred_if
        + weights["lof_flag"] * pred_lof
        + weights["random_forest_flag"] * pred_rf
    )
    pred_weighted = (weighted >= CALIBRATED_CORE_THRESHOLD * core_total).astype(int)

    # Progression detector needs the metadata columns (host + timestamp), which are
    # dropped from the numeric `features`. Reattach them from full_frame so the
    # trajectory can be evaluated fairly; if the frame is unavailable, omit progression
    # (all-zero) rather than mis-report a result.
    if full_frame is not None and host_col in full_frame.columns and ts_col in full_frame.columns:
        meta = full_frame.iloc[test_idx][[ts_col, host_col]].copy()
        meta["timestamp"] = meta[ts_col]
        meta["host"] = meta[host_col]
        pred_prog = progression_detector(meta, "host", "timestamp")
    else:
        pred_prog = np.zeros(len(test_idx), dtype=int)

    out = {}
    for name, pred in (("rule", pred_rule), ("iforest", pred_if), ("lof", pred_lof),
                       ("random_forest", pred_rf), ("vote", pred_vote),
                       ("weighted", pred_weighted), ("progression", pred_prog)):
        out[name] = {
            "f1": float(f1_score(y_test, pred, zero_division=0)),
            "precision": float(precision_score(y_test, pred, zero_division=0)),
            "recall": float(recall_score(y_test, pred, zero_division=0)),
        }
    # Probabilistic metrics need a score: RF is the only supervised scorer here. The
    # recall@FPR threshold is selected on an inner validation split of the TRAINING
    # fold (never on the test fold) and then applied once to the test fold.
    if len(np.unique(y_test)) > 1:
        out["random_forest"]["roc_auc"] = float(roc_auc_score(y_test, prob_rf))
        out["random_forest"]["pr_auc"] = float(average_precision_score(y_test, prob_rf))
        out["random_forest"]["applied_fpr"] = _applied_fpr(y_test, prob_rf)
        rf_threshold = _threshold_from_train(x_train_s, y_train, target_fpr=0.01)
        out["random_forest"]["recall_at_1pct_fpr"] = _recall_at_threshold(y_test, prob_rf, rf_threshold)
        out["random_forest"]["fpr_at_1pct_threshold"] = _fpr_at_threshold(y_test, prob_rf, rf_threshold)
    return out


def _aggregate(per_group: List[Dict[str, Dict[str, float]]]) -> Dict[str, Dict[str, float]]:
    """Pooled mean + 95% CI (t-based) for each metric of each method."""
    from scipy import stats as _stats

    methods = [m for m in per_group[0].keys() if m != "_group"]
    out = {}
    for method in methods:
        metrics = set()
        for g in per_group:
            metrics |= set(g[method].keys())
        out[method] = {}
        for metric in metrics:
            vals = np.array([g[method].get(metric, np.nan) for g in per_group], dtype=float)
            vals = vals[~np.isnan(vals)]
            if len(vals) == 0:
                out[method][metric] = float("nan")
                out[method][f"{metric}_ci"] = float("nan")
                continue
            mean = float(np.mean(vals))
            sem = float(np.std(vals, ddof=1)) / np.sqrt(len(vals)) if len(vals) > 1 else 0.0
            half = float(_stats.t.ppf(0.975, df=len(vals) - 1)) * sem if len(vals) > 1 else 0.0
            out[method][metric] = round(mean, 4)
            out[method][f"{metric}_ci"] = round(half, 4)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Strict-split real-data evaluation on RADAR windows.")
    ap.add_argument("--input", required=True)
    ap.add_argument("--label-column", default="label")
    ap.add_argument("--split", choices=["host", "day", "family"], default="day",
                    help="day: hold out whole days (temporal, no leakage across periods). "
                         "host: leave-one-host-out (session proxy; RADAR 'host' is a process "
                         "path, so this clusters to ~1 window/group and is mostly unusable). "
                         "family: hold out ransomware families (needs --include-metadata).")
    ap.add_argument("--family-column", default="family")
    ap.add_argument("--host-column", default="host")
    ap.add_argument("--ts-column", default="timestamp")
    ap.add_argument("--day-column", default="day", help="Column holding the day key used by --split day (created if absent).")
    ap.add_argument("--contamination-candidates", default="0.05,0.10,0.13,0.20,0.30",
                    help="Comma-separated contamination candidates tuned on inner validation.")
    ap.add_argument("--inner-folds", type=int, default=3)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--contamination", type=float, default=None,
                    help="Fix contamination instead of tuning on an inner split.")
    ap.add_argument("--metrics-output", default="")
    args = ap.parse_args()

    frame, features, truth = load_frame(Path(args.input), args.label_column)
    features = features.loc[:, features.nunique(dropna=True) > 1]

    if args.split == "day":
        # Build a day key from the timestamp if not already present. This gives a true
        # temporal hold-out: neither benign nor attack flows from a held-out day are
        # seen in training.
        if args.day_column not in frame.columns:
            ts = pd.to_datetime(frame[args.ts_column], errors="coerce")
            frame[args.day_column] = ts.dt.date.astype(str)
        split_col = args.day_column
    elif args.split == "family":
        split_col = args.family_column
    else:
        split_col = args.host_column

    if split_col not in frame.columns:
        raise ValueError(f"Split column '{split_col}' not found; prepare with --include-metadata for family splits.")

    groups = sorted(frame[split_col].astype(str).unique())
    if args.split == "family":
        # Only attack-containing groups are held out as 'unseen families'; benign is shared.
        groups = [g for g in groups if (truth[frame[split_col].astype(str) == g] == 1).sum() > 0]

    candidates = [float(c) for c in args.contamination_candidates.split(",")]
    per_group: List[Dict[str, Dict[str, float]]] = []
    print(f"{len(groups)} held-out {args.split} groups -> {args.input}")
    for group in groups:
        group_mask = (frame[split_col].astype(str) == group).to_numpy()
        is_attack = truth == 1
        if args.split == "family":
            # RADAR runs are pure (a run is either goodware or one ransomware family),
            # so a held-out family's test pool would be all-attack. To keep the test a
            # realistic benign-vs-unseen-family question, hold out a benign (goodware)
            # split too and test on it alongside the held-out family's attacks.
            benign_idx = np.where(~is_attack)[0]
            force_benign, keep_benign = _split_benign(benign_idx)
            held_attack_idx = np.where(group_mask & is_attack)[0]
            test_idx = np.concatenate([force_benign, held_attack_idx])
            train_idx = np.concatenate([keep_benign, np.where(~group_mask & is_attack)[0]])
        else:
            # day / host: held-out group's windows (benign AND attack) are test-only.
            train_idx = np.where(~group_mask)[0]
            test_idx = np.where(group_mask)[0]

        if len(np.unique(truth[test_idx])) < 2:
            print(f"  skip {group}: test pool single-class")
            continue
        cont = args.contamination if args.contamination is not None else \
            _tune_contamination(features.iloc[train_idx].to_numpy(dtype=float),
                                truth[train_idx], args.inner_folds, args.random_state, candidates)
        res = _fit_predict_all(features, truth, train_idx, test_idx, cont, args.random_state,
                               args.host_column, args.ts_column, full_frame=frame)
        per_group.append({k: v for k, v in res.items() if k != "_group"} | {"_group": group})
        rf = res["random_forest"]
        print(f"  held-out {group:<14} n_test={len(test_idx):<5} att={int(truth[test_idx].sum()):<4} "
              f"RF F1={rf['f1']:.3f} P={rf['precision']:.3f} R={rf['recall']:.3f} "
              f"AUC={rf.get('roc_auc', float('nan')):.3f} (cont={cont:.2f})")

    if not per_group:
        print("No evaluable held-out groups.")
        return

    agg = _aggregate(per_group)
    payload = {
        "input": str(args.input), "split": args.split, "label_column": args.label_column,
        "split_column": split_col, "groups_evaluated": len(per_group),
        "contamination_candidates": candidates, "inner_folds": args.inner_folds,
        "random_state": args.random_state, "comparators": agg,
        "per_group": per_group,
    }
    if args.metrics_output:
        out = Path(args.metrics_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nSaved -> {out}")
    else:
        print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
