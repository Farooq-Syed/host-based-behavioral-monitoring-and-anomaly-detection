# Data notes

## The two datasets in this repo

| File | Rows | Purpose |
|------|------|---------|
| `data/sample_host_telemetry.csv` | 40 | Tiny, hand-built sample for a quick pipeline smoke test |
| `data/synthetic_host_telemetry.csv` | 2,000 (regenerate any size) | Larger synthetic set for metrics with more statistical weight |

Both are **synthetic**. They are modeled on the qualitative shape of real endpoint
telemetry but the numbers are drawn from hand-specified distributions in
`generate_telemetry.py`, not measured from real machines. They are for pipeline
development and teaching, not as a benchmark. Metrics on synthetic data validate that
the code works and that the methods behave sensibly relative to each other; they do
**not** estimate real-world detection rates.

## Why the larger set is designed the way it is

A 40-row sample makes every method look near-perfect, which is misleading. The
generator deliberately makes the problem harder and more realistic:

- **Overlapping distributions.** Benign and attack rows share ranges on generic
  resource features (CPU, memory, network), so no single feature separates them. The
  attacks separate only on their characteristic combinations — ransomware on renames
  and entropy, cryptominers on sustained CPU, exfiltration on connection count.
- **Label noise.** A few percent of labels are flipped, so the classes are not
  perfectly clean, which keeps supervised accuracy realistic rather than a suspicious
  1.00.
- **Five behavior archetypes** (benign, ransomware, destructive scripting,
  cryptomining, exfiltration) rather than a single "attack" blob.

On the 2,000-row set the methods land where you would hope: rule-based and Isolation
Forest around F1 0.6–0.7, LOF weaker, a supervised Random Forest strong but not
perfect (~0.95), and the ensemble in between. That spread is the point.

Regenerate with a different size or seed:

```bash
python generate_telemetry.py --rows 5000 --seed 7 --output data/synthetic_host_telemetry.csv
```

## Moving to real telemetry

For results that estimate real detection performance, replace the synthetic input
with exported endpoint telemetry. Two practical sources:

- **Sysmon** (Windows System Monitor) event logs, exported to CSV, aggregated into
  fixed time windows per host. The features here (process/file/network counts, entropy
  of written files, shadow-copy events) map onto Sysmon event types.
- **Public EDR / host-intrusion datasets** such as those derived from the
  [DARPA Transparent Computing](https://www.darpa.mil/program/transparent-computing)
  program, or endpoint captures released with academic host-IDS papers.

The input pipeline expects the columns listed in the README's *Telemetry Features*
section; adapting a real source is a matter of aggregating raw events into those
per-window features.
