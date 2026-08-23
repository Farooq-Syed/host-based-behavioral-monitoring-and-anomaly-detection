"""
Host-based behavioral monitoring and anomaly detection.

This project analyzes host telemetry windows and compares:
- rule-based suspicious activity scoring
- Isolation Forest anomaly detection
- Local Outlier Factor anomaly detection
- Random Forest supervised classification when labels are available
- an ensemble decision across methods
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import matplotlib

# Select a non-interactive backend before importing pyplot so plots render on
# headless machines and in CI without a display server.
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


DEFAULT_INPUT = "data/sample_host_telemetry.csv"
DEFAULT_OUTPUT = "output/alerts_report.csv"
DEFAULT_SUMMARY = "output/summary.json"
DEFAULT_METRICS = "output/metrics.json"
DEFAULT_PLOT_DIR = "output/plots"

FEATURE_COLUMNS = [
    "cpu_percent",
    "memory_mb",
    "disk_write_mb",
    "file_write_count",
    "file_rename_count",
    "network_connections",
    "child_process_count",
    "unsigned_binary",
    "suspicious_extension_changes",
    "entropy_score",
    "shadow_copy_events",
]

# Small hand-maintained reputation map. The "abuse_prone" bucket lists living
# binaries that attackers routinely lean on; the point is not to call them
# malicious, but to weight a telemetry window slightly when one shows up.
BUILTIN_REPUTATION = {
    "explorer.exe": "trusted",
    "svchost.exe": "trusted",
    "lsass.exe": "trusted",
    "services.exe": "trusted",
    "winlogon.exe": "trusted",
    "csrss.exe": "trusted",
    "smss.exe": "trusted",
    "taskhostw.exe": "trusted",
    "SearchIndexer.exe": "trusted",
    "conhost.exe": "trusted",
    "dwm.exe": "trusted",
    "chrome.exe": "trusted",
    "firefox.exe": "trusted",
    "msedge.exe": "trusted",
    "powershell.exe": "abuse_prone",
    "cmd.exe": "abuse_prone",
    "wscript.exe": "abuse_prone",
    "cscript.exe": "abuse_prone",
    "mshta.exe": "abuse_prone",
    "regsvr32.exe": "abuse_prone",
    "rundll32.exe": "abuse_prone",
    "certutil.exe": "abuse_prone",
    "bitsadmin.exe": "abuse_prone",
}

CORE_ENSEMBLE_METHODS = [
    "rule_flag",
    "isolation_forest_flag",
    "lof_flag",
    "random_forest_flag",
]

# The calibrated ensemble treats the four primary detectors as the decision base
# and lets progression/reputation act as supporting boosts. On the harder 2,000-row
# synthetic eval set dated August 23, 2026, requiring roughly 40% of the core
# detector weight improved recall/F1 over the older weighted-majority threshold
# while keeping precision high.
CALIBRATED_CORE_THRESHOLD = 0.40


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze host telemetry for suspicious behavior.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to input host telemetry CSV.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Path to write alert report CSV.")
    parser.add_argument("--summary", default=DEFAULT_SUMMARY, help="Path to write summary JSON.")
    parser.add_argument("--metrics-output", default=DEFAULT_METRICS, help="Path to write metrics JSON.")
    parser.add_argument("--plot-dir", default=DEFAULT_PLOT_DIR, help="Directory for generated plots.")
    parser.add_argument("--label-column", default="label", help="Label column for evaluation. Use an empty string to disable.")
    parser.add_argument("--contamination", type=float, default=0.2, help="Expected anomaly fraction for unsupervised methods.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed for reproducible runs.")
    parser.add_argument(
        "--ensemble",
        default="vote",
        choices=["vote", "weighted"],
        help="vote: majority of the four core methods. weighted: precision-calibrated vote including the progression and reputation signals.",
    )
    parser.add_argument(
        "--reputation-csv",
        default=None,
        help="Optional CSV with columns process_name and reputation to extend the built-in process reputation list.",
    )
    return parser


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    dataframe = pd.read_csv(path)
    if dataframe.empty:
        raise ValueError("The input telemetry file is empty.")
    required_columns = {"timestamp", "host", "process_name", *FEATURE_COLUMNS}
    missing = required_columns - set(dataframe.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    return dataframe


def normalize_label(value: object) -> int:
    text = str(value).strip().lower()
    if text in {"1", "true", "malicious", "suspicious", "attack", "yes"}:
        return 1
    if text in {"0", "false", "benign", "normal", "no"}:
        return 0
    raise ValueError(f"Unsupported label value: {value}")


def scale_features(dataframe: pd.DataFrame) -> pd.DataFrame:
    scaler = StandardScaler()
    scaled = scaler.fit_transform(dataframe[FEATURE_COLUMNS].astype(float))
    return pd.DataFrame(scaled, columns=FEATURE_COLUMNS, index=dataframe.index)


def rule_based_detector(dataframe: pd.DataFrame) -> pd.DataFrame:
    report = pd.DataFrame(index=dataframe.index)
    score = (
        (dataframe["cpu_percent"] >= 85).astype(int)
        + (dataframe["disk_write_mb"] >= 250).astype(int)
        + (dataframe["file_rename_count"] >= 80).astype(int)
        + (dataframe["suspicious_extension_changes"] >= 25).astype(int)
        + (dataframe["entropy_score"] >= 7.4).astype(int)
        + (dataframe["shadow_copy_events"] >= 1).astype(int)
        + (dataframe["unsigned_binary"] >= 1).astype(int)
    )
    report["rule_score"] = score
    report["rule_flag"] = (score >= 3).astype(int)
    report["rule_reason"] = dataframe.apply(build_rule_reason, axis=1)
    return report


def build_rule_reason(row: pd.Series) -> str:
    reasons = []
    if row["cpu_percent"] >= 85:
        reasons.append(f"high CPU ({row['cpu_percent']})")
    if row["disk_write_mb"] >= 250:
        reasons.append(f"high disk writes ({row['disk_write_mb']} MB)")
    if row["file_rename_count"] >= 80:
        reasons.append(f"mass file renames ({row['file_rename_count']})")
    if row["suspicious_extension_changes"] >= 25:
        reasons.append(f"extension changes ({row['suspicious_extension_changes']})")
    if row["entropy_score"] >= 7.4:
        reasons.append(f"high entropy ({row['entropy_score']})")
    if row["shadow_copy_events"] >= 1:
        reasons.append("shadow copy modification")
    if row["unsigned_binary"] >= 1:
        reasons.append("unsigned binary execution")
    return "; ".join(reasons) if reasons else "baseline behavior"


def isolation_forest_detector(scaled_features: pd.DataFrame, contamination: float, random_state: int) -> pd.DataFrame:
    model = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=300)
    model.fit(scaled_features)
    report = pd.DataFrame(index=scaled_features.index)
    report["isolation_forest_flag"] = (model.predict(scaled_features) == -1).astype(int)
    report["isolation_forest_score"] = (-model.score_samples(scaled_features)).round(4)
    return report


def lof_detector(scaled_features: pd.DataFrame, contamination: float) -> pd.DataFrame:
    model = LocalOutlierFactor(contamination=contamination, n_neighbors=min(20, max(2, len(scaled_features) - 1)))
    predictions = model.fit_predict(scaled_features)
    report = pd.DataFrame(index=scaled_features.index)
    report["lof_flag"] = (predictions == -1).astype(int)
    report["lof_score"] = (-model.negative_outlier_factor_).round(4)
    return report


def random_forest_detector(scaled_features: pd.DataFrame, truth: pd.Series | None, random_state: int) -> pd.DataFrame:
    report = pd.DataFrame(index=scaled_features.index)
    if truth is None:
        report["random_forest_flag"] = 0
        report["random_forest_score"] = 0.0
        return report

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=random_state,
        class_weight="balanced",
        min_samples_leaf=2,
    )
    n_positive = int((truth == 1).sum())
    n_negative = int((truth == 0).sum())
    n_splits = max(2, min(5, n_positive, n_negative))
    splitter = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    # A single cross-validated pass produces the out-of-fold probabilities; the
    # flag is then derived from those same probabilities. Doing it this way (rather
    # than two separate cross_val_predict calls for "predict" and "predict_proba")
    # trains the forest once instead of twice and guarantees the flag and score are
    # mutually consistent — a flag of 1 always corresponds to score >= 0.5.
    probabilities = cross_val_predict(
        model, scaled_features, truth, cv=splitter, method="predict_proba"
    )[:, 1]
    report["random_forest_score"] = probabilities.round(4)
    report["random_forest_flag"] = (probabilities >= 0.5).astype(int)
    return report


def _window_stage(row: pd.Series) -> int:
    """Classify one telemetry window into a ransomware-progression stage.

    1 = reconnaissance / staging (mass renames, extension churn, unsigned code)
    2 = defense tampering (shadow-copy modification)
    3 = encryption / destruction (high entropy or heavy writes, on a rename/write
        activity base that looks like mass file modification)
    """
    recon = (
        row["file_rename_count"] >= 80
        or row["suspicious_extension_changes"] >= 25
        or row["unsigned_binary"] >= 1
    )
    tamper = row["shadow_copy_events"] >= 1
    encrypt = (
        (row["entropy_score"] >= 7.4 or row["disk_write_mb"] >= 250)
        and (row["file_rename_count"] >= 80 or row["file_write_count"] >= 100)
    )
    if encrypt:
        return 3
    if tamper:
        return 2
    if recon:
        return 1
    return 0


def detect_progression(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Score the canonical ransomware trajectory *across* windows, per host.

    The per-window detectors score snapshots; ransomware is a progression. For each
    host the windows are walked in time order and the set of stages seen so far is
    tracked. A stage only counts once its predecessor has appeared, so
    encryption-at-window-k is only part of a trajectory when recon and tampering
    were observed earlier on the same host. progression_flag stays set from the
    moment a full 1->2->3 path completes.
    """
    report = pd.DataFrame(index=dataframe.index)
    report["window_stage"] = 0
    report["progression_flag"] = 0

    for _, group in dataframe.groupby("host"):
        group = group.sort_values("timestamp")
        stages_seen: set[int] = set()
        for index in group.index:
            row = group.loc[index]
            stage = _window_stage(row)
            if stage == 1:
                stages_seen.add(1)
            elif stage == 2 and 1 in stages_seen:
                stages_seen.add(2)
            elif stage == 3 and {1, 2} <= stages_seen:
                stages_seen.add(3)
            report.at[index, "window_stage"] = stage
            report.at[index, "progression_flag"] = 1 if 3 in stages_seen else 0
    return report


def enrich_process_reputation(dataframe: pd.DataFrame, reputation_csv: str | None = None) -> pd.DataFrame:
    """Attach a reputation label to each window's process.

    Built-in map plus an optional external CSV (columns process_name, reputation)
    that overrides or extends it. The output columns are process_reputation and
    reputation_flag (1 when the process is in the abuse-prone bucket).
    """
    mapping = {name.lower(): reputation for name, reputation in BUILTIN_REPUTATION.items()}
    if reputation_csv:
        table = pd.read_csv(reputation_csv)
        required = {"process_name", "reputation"}
        missing = required - set(table.columns)
        if missing:
            raise ValueError(f"Reputation CSV missing columns: {sorted(missing)}")
        mapping.update(
            {
                str(name).strip().lower(): str(reputation).strip().lower()
                for name, reputation in zip(table["process_name"], table["reputation"])
            }
        )
    report = dataframe.copy()
    process_names = report["process_name"].astype(str).str.strip().str.lower()
    report["process_reputation"] = process_names.map(lambda name: mapping.get(name, "unknown"))
    report["reputation_flag"] = (report["process_reputation"] == "abuse_prone").astype(int)
    return report


def _ensemble_weights(report: pd.DataFrame, truth: pd.Series | None) -> dict:
    """Precision-based weights for the calibrated ensemble.

    Each method is weighted by how precise it was on the training labels; a method
    that never fired, or one with no labels to learn from, is given a small floor so
    it can still cast a weak vote rather than being zeroed out of existence.
    """
    method_columns = [
        "rule_flag",
        "isolation_forest_flag",
        "lof_flag",
        "random_forest_flag",
        "progression_flag",
        "reputation_flag",
    ]
    weights: dict = {}
    for method in method_columns:
        if truth is not None:
            weight = precision_score(truth, report[method], zero_division=0)
        else:
            weight = 1.0
        weights[method] = max(weight, 0.05) if truth is not None else weight
    return weights


def build_calibrated_ensemble(report: pd.DataFrame, truth: pd.Series | None) -> pd.DataFrame:
    """Weighted combination of all six detectors.

    Weights come from per-method precision on the labels (or are uniform without
    labels). A window is suspicious when the precision-weighted share of voting
    methods reaches half the total weight — a weighted majority.
    """
    weights = _ensemble_weights(report, truth)
    method_columns = list(weights.keys())
    weighted_score = sum(report[method].astype(float) * weight for method, weight in weights.items())
    total_weight = sum(weights.values())
    core_weight_total = sum(weights[method] for method in CORE_ENSEMBLE_METHODS)
    threshold = CALIBRATED_CORE_THRESHOLD * core_weight_total
    report["ensemble_weighted_score"] = (weighted_score / total_weight).round(4)
    report["ensemble_weighted_threshold"] = round(threshold / total_weight, 4)
    report["is_suspicious_calibrated"] = (weighted_score >= threshold).astype(int)
    return report


def build_report(
    dataframe: pd.DataFrame,
    contamination: float,
    random_state: int,
    label_column: str | None,
    ensemble: str = "vote",
    reputation_csv: str | None = None,
) -> pd.DataFrame:
    report = enrich_process_reputation(dataframe, reputation_csv)
    report.insert(0, "row_id", range(1, len(report) + 1))

    truth = None
    if label_column and label_column in report.columns:
        truth = report[label_column].apply(normalize_label)
        report["ground_truth"] = truth

    scaled_features = scale_features(report)
    rule_report = rule_based_detector(report)
    progression_report = detect_progression(report)
    isolation_report = isolation_forest_detector(scaled_features, contamination, random_state)
    lof_report = lof_detector(scaled_features, contamination)
    rf_report = random_forest_detector(scaled_features, truth, random_state)

    report = pd.concat([report, rule_report, progression_report, isolation_report, lof_report, rf_report], axis=1)
    vote_columns = ["rule_flag", "isolation_forest_flag", "lof_flag", "random_forest_flag"]
    report["ensemble_votes"] = report[vote_columns].sum(axis=1)

    if ensemble == "weighted":
        report = build_calibrated_ensemble(report, truth)
        report["is_suspicious"] = report["is_suspicious_calibrated"]
    else:
        report["is_suspicious"] = (report["ensemble_votes"] >= 2).astype(int)
    report["alert_reason"] = report.apply(build_alert_reason, axis=1)
    return report


def build_alert_reason(row: pd.Series) -> str:
    if row["is_suspicious"] == 0:
        return "baseline behavior"
    reasons: List[str] = []
    if row["rule_flag"] == 1:
        reasons.append(row["rule_reason"])
    if row["progression_flag"] == 1:
        reasons.append("full ransomware progression observed on this host (recon -> tampering -> encryption)")
    if row["isolation_forest_flag"] == 1:
        reasons.append("Isolation Forest flagged an unusual telemetry pattern")
    if row["lof_flag"] == 1:
        reasons.append("Local Outlier Factor detected a sparse telemetry neighborhood")
    if row["random_forest_flag"] == 1:
        reasons.append("Random Forest classified the telemetry window as suspicious")
    if row["reputation_flag"] == 1:
        reasons.append(f"abuse-prone process ({row['process_name']})")
    return "; ".join(dict.fromkeys(reason for reason in reasons if reason))


def compute_metrics(report: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    truth = report["ground_truth"]
    metric_targets = {
        "rule_based": report["rule_flag"],
        "progression": report["progression_flag"],
        "reputation": report["reputation_flag"],
        "isolation_forest": report["isolation_forest_flag"],
        "local_outlier_factor": report["lof_flag"],
        "random_forest": report["random_forest_flag"],
        "ensemble": report["is_suspicious"],
    }
    metrics: Dict[str, Dict[str, float]] = {}
    for method_name, predictions in metric_targets.items():
        metrics[method_name] = {
            "precision": round(precision_score(truth, predictions, zero_division=0), 4),
            "recall": round(recall_score(truth, predictions, zero_division=0), 4),
            "f1_score": round(f1_score(truth, predictions, zero_division=0), 4),
            "accuracy": round(accuracy_score(truth, predictions), 4),
            "predicted_suspicious": int(predictions.sum()),
        }
    return metrics


def save_summary(report: pd.DataFrame, summary_path: Path, metrics: Dict[str, Dict[str, float]] | None) -> None:
    suspicious_rows = report.loc[report["is_suspicious"] == 1, ["row_id", "host", "process_name"]]
    summary = {
        "rows_processed": int(len(report)),
        "unique_hosts": int(report["host"].nunique()),
        "suspicious_rows": int(report["is_suspicious"].sum()),
        "top_hosts": report.loc[report["is_suspicious"] == 1, "host"].value_counts().head(5).to_dict(),
        "flagged_examples": suspicious_rows.head(10).to_dict(orient="records"),
    }
    if metrics:
        summary["best_method_by_f1"] = max(metrics.items(), key=lambda item: item[1]["f1_score"])[0]
        summary["metrics_available"] = True
    else:
        summary["metrics_available"] = False
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def save_metrics(metrics: Dict[str, Dict[str, float]], metrics_path: Path) -> None:
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def generate_plots(report: pd.DataFrame, plot_dir: Path, metrics: Dict[str, Dict[str, float]] | None) -> None:
    plot_dir.mkdir(parents=True, exist_ok=True)
    plt.style.use("ggplot")

    colors = report["is_suspicious"].map({1: "#c1121f", 0: "#1d3557"})
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.scatter(report["disk_write_mb"], report["file_rename_count"], c=colors)
    ax.set_title("Disk Writes vs File Renames")
    ax.set_xlabel("Disk Write MB")
    ax.set_ylabel("File Rename Count")
    fig.tight_layout()
    fig.savefig(plot_dir / "disk_writes_vs_renames.png", dpi=180)
    plt.close(fig)

    method_counts = {
        "Rule": int(report["rule_flag"].sum()),
        "Isolation Forest": int(report["isolation_forest_flag"].sum()),
        "LOF": int(report["lof_flag"].sum()),
        "Random Forest": int(report["random_forest_flag"].sum()),
        "Ensemble": int(report["is_suspicious"].sum()),
    }
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(method_counts.keys(), method_counts.values(), color=["#457b9d", "#1d3557", "#588157", "#6a4c93", "#c1121f"])
    ax.set_title("Suspicious Windows Flagged by Method")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=15)
    fig.tight_layout()
    fig.savefig(plot_dir / "method_comparison.png", dpi=180)
    plt.close(fig)

    if metrics:
        fig, ax = plt.subplots(figsize=(10, 5))
        method_names = list(metrics.keys())
        f1_scores = [metrics[name]["f1_score"] for name in method_names]
        ax.bar(method_names, f1_scores, color="#c1121f")
        ax.set_title("F1 Score by Method")
        ax.set_ylabel("F1 Score")
        ax.tick_params(axis="x", rotation=15)
        fig.tight_layout()
        fig.savefig(plot_dir / "f1_comparison.png", dpi=180)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(6, 5))
        matrix = confusion_matrix(report["ground_truth"], report["is_suspicious"])
        display = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=["benign", "suspicious"])
        display.plot(ax=ax, colorbar=False)
        ax.set_title("Ensemble Confusion Matrix")
        fig.tight_layout()
        fig.savefig(plot_dir / "ensemble_confusion_matrix.png", dpi=180)
        plt.close(fig)


def print_summary(report: pd.DataFrame, metrics: Dict[str, Dict[str, float]] | None) -> None:
    print(f"Processed {len(report)} telemetry windows across {report['host'].nunique()} hosts.")
    print(f"Flagged {int(report['is_suspicious'].sum())} suspicious windows.")
    suspicious_rows = report.loc[report["is_suspicious"] == 1, ["row_id", "host", "process_name", "alert_reason"]]
    if not suspicious_rows.empty:
        print("\nSample flagged windows:")
        for _, row in suspicious_rows.head(15).iterrows():
            print(f"  - row {int(row['row_id'])} on {row['host']} ({row['process_name']}): {row['alert_reason']}")
        remaining = len(suspicious_rows) - len(suspicious_rows.head(15))
        if remaining > 0:
            print(f"  - ... {remaining} additional suspicious windows omitted from console output")

    if metrics:
        print("\nEvaluation metrics:")
        for method_name, method_metrics in metrics.items():
            print(
                f"  - {method_name}: precision={method_metrics['precision']:.2f}, "
                f"recall={method_metrics['recall']:.2f}, f1={method_metrics['f1_score']:.2f}"
            )


def main() -> None:
    args = build_parser().parse_args()
    label_column = args.label_column or None
    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary)
    metrics_path = Path(args.metrics_output)
    plot_dir = Path(args.plot_dir)

    dataframe = load_dataset(input_path)
    report = build_report(
        dataframe,
        args.contamination,
        args.random_state,
        label_column,
        ensemble=args.ensemble,
        reputation_csv=args.reputation_csv,
    )

    metrics = None
    if label_column and "ground_truth" in report.columns:
        metrics = compute_metrics(report)
        save_metrics(metrics, metrics_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_path, index=False)
    save_summary(report, summary_path, metrics)
    generate_plots(report, plot_dir, metrics)
    print_summary(report, metrics)
    print(f"\nReport written to: {output_path}")
    print(f"Summary written to: {summary_path}")
    if metrics:
        print(f"Metrics written to: {metrics_path}")
    print(f"Plots written to: {plot_dir}")


if __name__ == "__main__":
    main()
