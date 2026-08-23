"""Sysmon -> windowed-telemetry adapter for real ransomware/goodware data.

Real Sysmon/ECS event data (e.g. CSU/RADAR raw logs) carry one row per event, not the
windowed per-host aggregate that monitor.py consumes. This adapter aggregates real Sysmon
events into per-(host, time-window) rows and derives the windowed features that ARE
recoverable from Sysmon:

  process_create_count, file_create_count, file_delete_count, file_rename_like,
  network_connections, registry_events, module_loads, unsigned_process_events,
  suspicious_extension_events, shadow_copy_events, event_count, label

Honest scope (documented in the README): Sysmon does NOT capture CPU/Memory/raw file
entropy, so those monitor.py features are not derivable here; the ML comparison is run on
the Sysmon-recoverable features instead (via real_data_eval.py). This is real ransomware
vs. real goodware telemetry, not a synthetic generator.

Usage (reproduce the committed real-data run):
  python sysmon_adapter.py --goodware <goodware-logs.csv> \
      --ransomware Akira-xxx.csv BlackBasta-xxx.csv ... \
      --window-minutes 5 --host-limit <n> --output data/radar_real_windows.csv
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd

RANSOM_EXTS = (
    ".lockbit", ".locked", ".enc", ".encrypted", ".crypt", ".ryuk", ".conti",
    ".akira", ".blackbasta", ".medusa", ".lynx", ".cybervolk", ".meow",
)

FEATURE_ORDER = [
    "process_create_count",
    "file_create_count",
    "file_delete_count",
    "file_rename_like",
    "network_connections",
    "registry_events",
    "module_loads",
    "unsigned_process_events",
    "suspicious_extension_events",
    "shadow_copy_events",
    "event_count",
]


def _parse_timestamp(series: pd.Series) -> pd.Series:
    """Parse RADAR's ECS timestamp like 'Oct 14 | 2024 @ 22:15:45.190'."""
    cleaned = series.astype(str).str.replace("|", " ").str.replace("@", " ", regex=False)
    cleaned = cleaned.str.replace(r"\s+", " ", regex=True).str.strip()
    parsed = pd.to_datetime(cleaned, errors="coerce", format="%b %d %Y %H:%M:%S.%f")
    fallback = pd.to_datetime(cleaned, errors="coerce")  # tolerate other formats
    return parsed.fillna(fallback)


def _ext(key: str, value: object) -> object:
    if key == "event.code":
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None
    return value


def load_sysmon(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, low_memory=False)
    if "@timestamp" not in frame.columns:
        raise ValueError(f"{path.name}: missing '@timestamp' (not an ECS/Sysmon export?)")
    frame["ts"] = _parse_timestamp(frame["@timestamp"])
    frame["host"] = (frame["user.domain"].fillna("").astype(str) + "\\" +
                     frame["user.name"].fillna("").astype(str)).str.strip("\\")
    if "event.code" in frame.columns:
        frame["event_code"] = pd.to_numeric(frame["event.code"], errors="coerce").fillna(0).astype(int)
    else:
        frame["event_code"] = 0
    if "target-class" in frame.columns:
        frame["label"] = pd.to_numeric(frame["target-class"], errors="coerce").fillna(0).astype(int)
    else:
        frame["label"] = 1  # ransomware CSV has no column; caller splits goodware/ransom
    return frame


def _window_rows(frame: pd.DataFrame, window_minutes: int) -> pd.DataFrame:
    frame = frame.dropna(subset=["ts"]).copy()
    if frame.empty:
        return pd.DataFrame(columns=FEATURE_ORDER + ["timestamp", "host", "process_name", "label"])
    frame["window"] = frame["ts"].dt.floor(f"{window_minutes}min")

    def agg(group: pd.DataFrame) -> dict:
        code = group["event_code"]
        feats = {
            "process_create_count": int((code == 1).sum()),
            "file_create_count": int(code.isin([2, 11]).sum()),
            "file_delete_count": int((code == 23).sum()),
            "network_connections": int((code == 3).sum()),
            "registry_events": int(code.isin([12, 13, 14]).sum()),
            "module_loads": int((code == 7).sum()),
            "event_count": int(len(group)),
        }
        # file renames / suspicious extensions: file.path carries the extension or new name
        file_paths = group["file.path"].astype(str) if "file.path" in group else pd.Series(dtype=str)
        feats["file_rename_like"] = int(file_paths.str.contains(r"[.](?:lockbit|locked|enc|crypt|ryuk|conti|akira|blackbasta|medusa|lynx|cybervolk|meow)$", case=False).sum())
        feats["suspicious_extension_events"] = int(file_paths.str.contains("|".join(r"[.]" + e.lstrip(".") for e in RANSOM_EXTS), case=False).sum())
        # unsigned binary: Sysmon 'Signed' == 'false' / SignatureStatus not 'Valid'
        signed = group["winlog.event_data.Signed"].astype(str) if "winlog.event_data.Signed" in group else pd.Series(dtype=str)
        feats["unsigned_process_events"] = int(signed.str.lower().eq("false").sum())
        # shadow copy: process.name / executable is vssadmin or path contains 'shadow'
        exe = group["process.executable"].astype(str) if "process.executable" in group else pd.Series(dtype=str)
        feats["shadow_copy_events"] = int(exe.str.contains(r"vssadmin|shadowcopy", case=False).sum())
        feats["process_name"] = ""
        feats["label"] = int(group["label"].max())
        return feats

    rows = []
    for (host_key, window_key), group in frame.groupby(["host", "window"], sort=False):
        feats = agg(group)
        feats["timestamp"] = window_key
        feats["host"] = host_key
        rows.append(feats)
    out = pd.DataFrame(rows)
    out[FEATURE_ORDER] = out[FEATURE_ORDER].apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)
    return out[["timestamp", "host", "process_name"] + FEATURE_ORDER + ["label"]]


def _family_from_name(name: str) -> str:
    """Derive a family tag from a raw CSV filename, e.g. 'Akira-...csv' -> 'Akira'."""
    stem = Path(name).stem
    for fam in ("BlackBasta", "CyberVolk", "Akira", "LockBit", "Medusa", "Lynx", "Meow"):
        if fam.lower() in stem.lower():
            return fam
    return "Goodware"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--goodware", required=True)
    ap.add_argument("--ransomware", nargs="+", default=[], help="Ransomware Sysmon CSVs (each labeled ransomware).")
    ap.add_argument("--window-minutes", type=int, default=5)
    ap.add_argument("--goodware-sample", type=int, default=0, help="Cap goodware rows (0 = all).")
    ap.add_argument("--output", required=True)
    ap.add_argument("--include-metadata", action="store_true",
                    help="Attach a 'family' column (from the source CSV filename) and a "
                         "'run' id so strict family/session hold-out evaluation is possible. "
                         "Off by default to keep outputs byte-identical to the committed file.")
    args = ap.parse_args()

    good = load_sysmon(Path(args.goodware))
    if args.goodware_sample and len(good) > args.goodware_sample:
        good = good.sample(args.goodware_sample, random_state=42)
    windows = _window_rows(good, args.window_minutes)
    if args.include_metadata:
        windows["family"] = "Goodware"
        windows["run"] = f"goodware:{_family_from_name(args.goodware)}"

    for path in args.ransomware:
        rw = load_sysmon(Path(path))
        rw["label"] = 1
        fam = _family_from_name(path)
        block = _window_rows(rw, args.window_minutes)
        if args.include_metadata:
            block["family"] = fam
            block["run"] = f"ran:{fam}:{Path(path).stem}"
        windows = pd.concat([windows, block], ignore_index=True)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    windows.to_csv(out, index=False)
    print(f"Wrote {len(windows)} real Sysmon windows -> {out}")
    print(f"  benign windows: {(windows['label'] == 0).sum()}  ransomware windows: {(windows['label'] == 1).sum()}")
    if args.include_metadata:
        print(f"  families: {windows['family'].value_counts().to_dict()}")
    print(f"  features: {FEATURE_ORDER}")


if __name__ == "__main__":
    main()
