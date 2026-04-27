import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import terrain


SAMPLE_PAYLOAD = {
    "summary": {
        "total": 3,
        "counts": {"critical": 1, "high": 1, "medium": 1, "low": 0},
        "has_critical": True,
    },
    "findings": [
        {
            "rule_id": "rule-1",
            "severity": "critical",
            "file": "caretrack/support_tools.py",
            "line": 12,
            "finding": "Command injection risk in helper script.",
            "lines": "subprocess.run(cmd, shell=True)",
            "cwe": "CWE-78",
            "fix_suggestion": "Avoid passing unsanitized user input into shell commands.",
        },
        {
            "rule_id": "rule-2",
            "severity": "high",
            "file": "caretrack/db.py",
            "line": 44,
            "finding": "SQL injection risk in query builder.",
            "lines": 'query = "SELECT * FROM users WHERE id = " + user_id',
            "cwe": "CWE-89",
            "fix_suggestion": "Use parameterized queries.",
        },
        {
            "rule_id": "rule-3",
            "severity": "medium",
            "file": "caretrack/db.py",
            "line": 61,
            "finding": "Unsafe HTML rendering.",
            "lines": "return render_template_string(template)",
            "cwe": "CWE-79",
            "fix_suggestion": "Escape untrusted values before rendering.",
        },
    ],
    "source": {
        "scanner": "semgrep-cloud",
        "changed_files": ["caretrack/support_tools.py", "caretrack/db.py"],
        "scanned_files": ["caretrack/support_tools.py", "caretrack/db.py"],
        "reason": "Scan completed.",
        "base_sha": "base123",
        "head_sha": "head456",
    },
}

SAMPLE_DOMAIN_CONTEXT = {
    "generated": True,
    "app_domain": "healthcare scheduling",
    "data_sensitivity": "PHI",
    "regulatory_context": ["HIPAA"],
    "user_types": ["patients", "clinicians"],
    "deployment": "containerized web app",
    "risk_tier": "high",
}


class TerrainTests(unittest.TestCase):
    def test_no_provider_passthrough_keeps_original_findings(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            output = terrain.synthesize_terrain(SAMPLE_PAYLOAD, Path("."))

        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])

    def test_empty_findings_skip_generation(self) -> None:
        payload = dict(SAMPLE_PAYLOAD)
        payload["findings"] = []

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.terrain.generate_file_terrain") as generate_mock:
                output = terrain.synthesize_terrain(payload, Path("."), SAMPLE_DOMAIN_CONTEXT)

        generate_mock.assert_not_called()
        self.assertEqual(output["findings"], [])

    def test_collect_added_lines_parses_git_diff_hunks(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git", "diff"],
            returncode=0,
            stdout="@@ -10,0 +11,2 @@\n+line one\n+line two\n@@ -20 +25 @@\n+line three\n",
            stderr="",
        )

        with patch("scanner.terrain.subprocess.run", return_value=completed):
            added_lines = terrain.collect_added_lines(Path("."), "caretrack/db.py", "base123", "head456")

        self.assertEqual(added_lines, {11, 12, 25})

    def test_successful_generation_classifies_findings_and_adds_taint_path(self) -> None:
        terrain_map_by_file = {
            "caretrack/support_tools.py": {
                "sources": [{"line": 10, "description": "HTTP query parameter"}],
                "sinks": [{"line": 12, "description": "subprocess.run shell execution"}],
            },
            "caretrack/db.py": {
                "sources": [{"line": 30, "description": "user-controlled database parameter"}],
                "sinks": [
                    {"line": 44, "description": "cursor.execute string interpolation"},
                    {"line": 61, "description": "template rendering sink"},
                ],
            },
        }

        def fake_generate(
            provider: dict[str, str],
            file_path: str,
            file_content: str,
            findings: list[dict[str, object]],
            domain_context: dict[str, object] | None,
        ) -> dict[str, list[dict[str, object]]]:
            self.assertIn("fake source", file_content)
            self.assertIs(domain_context, SAMPLE_DOMAIN_CONTEXT)
            return terrain_map_by_file[file_path]

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.terrain.read_changed_file", return_value="fake source\nfake sink\n"):
                with patch(
                    "scanner.terrain.collect_added_lines",
                    side_effect=[{10}, set()],
                ):
                    with patch("scanner.terrain.generate_file_terrain", side_effect=fake_generate):
                        output = terrain.synthesize_terrain(SAMPLE_PAYLOAD, Path("."), SAMPLE_DOMAIN_CONTEXT)

        first, second, third = output["findings"]
        self.assertEqual(first["origin"], "introduced")
        self.assertEqual(first["source_line"], 10)
        self.assertEqual(first["sink_line"], 12)
        self.assertIn("HTTP query parameter", first["taint_path"])

        self.assertEqual(second["origin"], "pre-existing")
        self.assertEqual(second["source_line"], 30)
        self.assertEqual(second["sink_line"], 44)

        self.assertEqual(third["origin"], "pre-existing")
        self.assertEqual(third["sink_line"], 61)

    def test_per_file_failure_marks_only_failed_file_unknown(self) -> None:
        def fake_generate(
            provider: dict[str, str],
            file_path: str,
            file_content: str,
            findings: list[dict[str, object]],
            domain_context: dict[str, object] | None,
        ) -> dict[str, list[dict[str, object]]]:
            if file_path == "caretrack/support_tools.py":
                raise RuntimeError("boom")
            return {
                "sources": [{"line": 30, "description": "user-controlled database parameter"}],
                "sinks": [{"line": 44, "description": "cursor.execute string interpolation"}],
            }

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.terrain.read_changed_file", return_value="fake file content"):
                with patch("scanner.terrain.collect_added_lines", return_value={30}):
                    with patch("scanner.terrain.generate_file_terrain", side_effect=fake_generate):
                        output = terrain.synthesize_terrain(SAMPLE_PAYLOAD, Path("."), SAMPLE_DOMAIN_CONTEXT)

        failed = output["findings"][0]
        recovered = output["findings"][1]
        self.assertEqual(failed["origin"], "unknown")
        self.assertNotIn("taint_path", failed)
        self.assertEqual(recovered["origin"], "introduced")
        self.assertIn("taint_path", recovered)

    def test_build_user_prompt_includes_domain_summary_file_findings_and_content(self) -> None:
        prompt = terrain.build_user_prompt(
            "caretrack/support_tools.py",
            "first line\nsecond line\n",
            [SAMPLE_PAYLOAD["findings"][0]],
            SAMPLE_DOMAIN_CONTEXT,
        )

        self.assertIn("app_domain=healthcare scheduling", prompt)
        self.assertIn("caretrack/support_tools.py", prompt)
        self.assertIn('"rule_id": "rule-1"', prompt)
        self.assertIn("1: first line", prompt)
        self.assertIn("2: second line", prompt)

    def test_main_writes_output_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "triaged-findings.json"
            output_path = Path(temp_dir) / "terrain-findings.json"
            context_path = Path(temp_dir) / "domain_context.json"
            input_path.write_text(json.dumps(SAMPLE_PAYLOAD), encoding="utf-8")
            context_path.write_text(json.dumps(SAMPLE_DOMAIN_CONTEXT), encoding="utf-8")

            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "sys.argv",
                    [
                        "terrain.py",
                        "--input",
                        str(input_path),
                        "--context",
                        str(context_path),
                        "--output",
                        str(output_path),
                    ],
                ):
                    exit_code = terrain.main()

            written = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(written["findings"], SAMPLE_PAYLOAD["findings"])


if __name__ == "__main__":
    unittest.main()
