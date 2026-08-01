import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


class HostMonitoringSmokeTests(unittest.TestCase):
    def test_sample_run_produces_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_csv = tmp_path / "alerts.csv"
            summary_json = tmp_path / "summary.json"
            metrics_json = tmp_path / "metrics.json"
            plot_dir = tmp_path / "plots"

            # Use sys.executable, not a bare "python", so the subprocess runs the
            # same interpreter/environment as the test rather than whichever
            # "python" happens to be first on PATH.
            subprocess.run(
                [
                    sys.executable,
                    "monitor.py",
                    "--input",
                    "data/sample_host_telemetry.csv",
                    "--output",
                    str(output_csv),
                    "--summary",
                    str(summary_json),
                    "--metrics-output",
                    str(metrics_json),
                    "--plot-dir",
                    str(plot_dir),
                ],
                cwd=PROJECT_DIR,
                check=True,
            )

            self.assertTrue(output_csv.exists())
            self.assertTrue(summary_json.exists())
            self.assertTrue(metrics_json.exists())
            self.assertTrue((plot_dir / "disk_writes_vs_renames.png").exists())


if __name__ == "__main__":
    unittest.main()
