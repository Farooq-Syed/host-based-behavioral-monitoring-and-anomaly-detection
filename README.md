# Host-Based Behavioral Monitoring and Anomaly Detection

This project analyzes host telemetry windows to detect suspicious behavior associated with ransomware-style activity, destructive scripting, and resource abuse. It combines rule-based detection with machine learning to compare how different methods behave on the same telemetry stream.

## Results at a glance

![Results panel](assets/results_panel.png)

Four detectors score each telemetry window and vote. On the sample the ensemble
recovers recall (0.80) over any single unsupervised method (0.53) while holding
precision at 1.00. See [PAPER.md](PAPER.md) for the method and [JOURNAL.md](JOURNAL.md)
for the development notes.

## Features

- host telemetry monitoring from CSV
- rule-based suspicious activity scoring
- `Isolation Forest` anomaly detection
- `Local Outlier Factor` anomaly detection
- `Random Forest` supervised classification when labels are available
- ensemble voting across methods
- metrics, plots, and notebook-based analysis

## Project Structure

```text
.
|-- monitor.py
|-- requirements.txt
|-- .gitignore
|-- LICENSE
|-- data/
|   `-- sample_host_telemetry.csv
|-- assets/
|   |-- disk_writes_vs_renames_sample.png
|   |-- method_comparison_sample.png
|   |-- f1_comparison_sample.png
|   `-- ensemble_confusion_matrix_sample.png
|-- results/
|   |-- sample_metrics.json
|   `-- sample_summary.json
`-- notebooks/
    `-- host_behavior_analysis.ipynb
```

## Installation

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run the sample dataset:

```powershell
python monitor.py
```

Use a different anomaly fraction:

```powershell
python monitor.py --contamination 0.15
```

## Output

The script writes:

- `output/alerts_report.csv`
- `output/summary.json`
- `output/metrics.json`
- `output/plots/disk_writes_vs_renames.png`
- `output/plots/method_comparison.png`
- `output/plots/f1_comparison.png`
- `output/plots/ensemble_confusion_matrix.png`

## Telemetry Features

The sample dataset includes:

- CPU usage
- memory usage
- disk write volume
- file write count
- file rename count
- network connection count
- child process count
- unsigned binary execution
- suspicious extension changes
- entropy score
- shadow copy activity

## Detection Logic

### Rule-Based Detection

The rule-based method flags windows with a combination of high CPU, heavy disk writes, mass file renames, extension changes, high entropy, shadow copy tampering, and unsigned binaries.

### Isolation Forest and LOF

These models are used to detect anomalous host behavior without relying on exact signatures.

### Random Forest

When labels are available, the supervised model is evaluated with cross-validated predictions to estimate how well the telemetry separates benign and suspicious activity.

### Ensemble

The final alert uses a simple vote across the rule-based detector and the three ML methods.

## Sample Results

The included sample dataset is synthetic and meant to simulate benign activity, ransomware-like behavior, destructive scripting, and high-resource abuse. It is useful for validating the pipeline and showing how different methods compare.

Metrics from `results/sample_metrics.json`:

| Method | Precision | Recall | F1-score | Accuracy |
| --- | --- | --- | --- | --- |
| Rule-based | 1.00 | 0.53 | 0.70 | 0.83 |
| Isolation Forest | 1.00 | 0.53 | 0.70 | 0.83 |
| Local Outlier Factor | 1.00 | 0.53 | 0.70 | 0.83 |
| Random Forest | 1.00 | 1.00 | 1.00 | 1.00 |
| Ensemble | 1.00 | 0.80 | 0.89 | 0.93 |

These results show a useful pattern for the project:

- unsupervised and rule-based methods catch the strongest suspicious windows
- the supervised model separates the synthetic sample more cleanly
- the ensemble improves recall over the unsupervised methods while keeping precision high

## Sample Visuals

Disk writes vs file renames:

![Disk writes vs renames](assets/disk_writes_vs_renames_sample.png)

Method comparison:

![Method comparison](assets/method_comparison_sample.png)

F1 comparison:

![F1 comparison](assets/f1_comparison_sample.png)

Ensemble confusion matrix:

![Confusion matrix](assets/ensemble_confusion_matrix_sample.png)

## Why This Project Matters

This project is meant to look more like host-based detection engineering than a basic system monitor. It focuses on security-relevant resource and file activity patterns, which makes it useful for ransomware-style early warning and suspicious process monitoring.

## Next Steps

- replace the synthetic sample with larger endpoint telemetry
- add time-series sequence modeling across adjacent windows
- add process reputation or signer enrichment
- adapt the input pipeline to Sysmon-style telemetry
