import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import run_scan


class RunScanTests(unittest.TestCase):
    def test_build_local_command_uses_rules_and_files(self) -> None:
        command = run_scan.build_local_command("rules", ["src/app.py", "src/auth.js"])

        self.assertEqual(command[:6], ["semgrep", "scan", "--config", "rules", "--json", "--quiet"])
        self.assertEqual(command[-3:], ["--error", "src/app.py", "src/auth.js"])

    def test_build_cloud_command_uses_baseline_and_output_path(self) -> None:
        command = run_scan.build_cloud_command("abc123", Path("/tmp/semgrep.json"))

        self.assertEqual(
            command,
            ["semgrep", "ci", "--baseline-commit", "abc123", "--json-output", "/tmp/semgrep.json"],
        )

    def test_run_local_scan_normalizes_output(self) -> None:
        fake_result = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=1,
            stdout='{"results":[{"check_id":"rule-1"}],"errors":[]}',
            stderr="",
        )

        with patch("scanner.run_scan.subprocess.run", return_value=fake_result):
            payload = run_scan.run_local_scan("rules", ["src/app.py"], ["src/app.py"], "base123", "head456")

        self.assertEqual(payload["metadata"]["scanner"], "semgrep")
        self.assertEqual(payload["metadata"]["reason"], "Scan completed.")
        self.assertEqual(payload["metadata"]["base_sha"], "base123")
        self.assertEqual(payload["metadata"]["head_sha"], "head456")
        self.assertEqual(payload["paths"]["scanned"], ["src/app.py"])
        self.assertEqual(payload["paths"]["changed"], ["src/app.py"])
        self.assertEqual(payload["results"][0]["check_id"], "rule-1")

    def test_run_cloud_scan_requires_token(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(SystemExit) as context:
                run_scan.run_cloud_scan("abc123", "def456", ["src/app.py"])

        self.assertIn("SEMGREP_APP_TOKEN", str(context.exception))

    def test_run_cloud_scan_reads_json_output_file(self) -> None:
        def fake_run(command: list[str], capture_output: bool, text: bool) -> subprocess.CompletedProcess[str]:
            Path(command[-1]).write_text('{"results":[{"check_id":"cloud-rule"}],"errors":[]}', encoding="utf-8")
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

        with patch.dict("os.environ", {"SEMGREP_APP_TOKEN": "token"}, clear=True):
            with patch("scanner.run_scan.subprocess.run", side_effect=fake_run):
                payload = run_scan.run_cloud_scan("abc123", "def456", ["src/app.py"])

        self.assertEqual(payload["metadata"]["scanner"], "semgrep-cloud")
        self.assertEqual(payload["metadata"]["base_sha"], "abc123")
        self.assertEqual(payload["metadata"]["head_sha"], "def456")
        self.assertEqual(payload["paths"]["scanned"], [])
        self.assertEqual(payload["results"][0]["check_id"], "cloud-rule")


if __name__ == "__main__":
    unittest.main()
