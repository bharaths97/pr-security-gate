import json
import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import comment


BASE_PAYLOAD = {
    "summary": {
        "total": 1,
        "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        "has_critical": True,
    },
    "findings": [
        {
            "rule_id": "rule-1",
            "severity": "critical",
            "file": "caretrack/support_tools.py",
            "line": 21,
            "finding": "Command injection risk in support helper.",
            "cwe": "CWE-78",
            "fix_suggestion": "Validate input and avoid shell=True.",
        }
    ],
    "source": {
        "scanner": "semgrep-cloud",
        "changed_files": ["caretrack/support_tools.py"],
        "scanned_files": ["caretrack/support_tools.py"],
        "reason": "Scan completed.",
    },
    "narrative": None,
}


class CommentTests(unittest.TestCase):
    def test_build_comment_body_renders_narrative_blockquote(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["narrative"] = "This PR introduces an immediately exploitable command execution path."

        body = comment.build_comment_body(payload)

        self.assertIn("> This PR introduces an immediately exploitable command execution path.", body)
        self.assertIn("Status: failing because at least one critical finding was detected.", body)

    def test_build_comment_body_omits_narrative_when_missing(self) -> None:
        body = comment.build_comment_body(BASE_PAYLOAD)

        self.assertNotIn("> This PR introduces", body)
        self.assertIn("## PR Security Gate Results", body)

    def test_build_comment_body_omits_narrative_when_no_findings(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = []
        payload["summary"] = {
            "total": 0,
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "has_critical": False,
        }
        payload["narrative"] = "This text should not render."

        body = comment.build_comment_body(payload)

        self.assertNotIn("This text should not render.", body)
        self.assertIn("No security findings were detected in the changed files.", body)

    def test_build_table_prefers_enriched_fields_when_present(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "enriched_finding": "Attacker-controlled input reaches a shell execution path.",
                "enriched_fix": "Validate the helper input and remove shell=True from the subprocess call.",
            }
        ]

        body = comment.build_comment_body(payload)

        self.assertIn("Attacker-controlled input reaches a shell execution path.", body)
        self.assertIn("remove shell=True", body)
        self.assertNotIn("Command injection risk in support helper.", body)

    def test_build_comment_body_renders_origin_badges_taint_column_and_pre_existing_details(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "origin": "introduced",
                "taint_path": "HTTP query parameter (line 10) -> subprocess.run shell execution (line 21)",
            },
            {
                **BASE_PAYLOAD["findings"][0],
                "file": "caretrack/legacy.py",
                "line": 9,
                "origin": "pre-existing",
                "taint_path": "config value (line 3) -> exec sink (line 9)",
            },
        ]
        payload["summary"] = {
            "total": 2,
            "counts": {"critical": 2, "high": 0, "medium": 0, "low": 0},
            "has_critical": True,
        }

        body = comment.build_comment_body(payload)
        main_section, details_section = body.split("<details>", maxsplit=1)

        self.assertIn("| Taint Path |", body)
        self.assertIn("CRITICAL<br>NEW", main_section)
        self.assertNotIn("caretrack/legacy.py", main_section)
        self.assertIn("<summary>Pre-existing findings (1)</summary>", body)
        self.assertIn("CRITICAL<br>PRE-EXISTING", details_section)
        self.assertIn("caretrack/legacy.py", details_section)

    def test_build_comment_body_appends_sustained_adversarial_note_in_main_table(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "verdict": "sustained",
                "counter_argument": "The input is partially validated, but user-controlled data still reaches shell execution.",
            }
        ]

        body = comment.build_comment_body(payload)

        self.assertIn("Adversarial review: sustained", body)
        self.assertIn("partially validated", body)

    def test_build_comment_body_moves_downgraded_high_findings_to_challenged_details(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["summary"] = {
            "total": 2,
            "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0},
            "has_critical": True,
        }
        payload["findings"] = [
            BASE_PAYLOAD["findings"][0],
            {
                "rule_id": "rule-2",
                "severity": "high",
                "file": "caretrack/db.py",
                "line": 44,
                "finding": "SQL injection risk in query builder.",
                "cwe": "CWE-89",
                "fix_suggestion": "Use parameterized queries.",
                "verdict": "downgraded",
                "counter_argument": "The query string is assembled from an internal enum and not user input.",
            },
        ]

        body = comment.build_comment_body(payload)
        main_section, details_section = body.split("<details>", maxsplit=1)

        self.assertNotIn("caretrack/db.py", main_section)
        self.assertIn("<summary>Challenged findings (1)</summary>", body)
        self.assertIn("internal enum", details_section)

    def test_build_comment_body_keeps_downgraded_critical_findings_in_main_table(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "verdict": "downgraded",
                "counter_argument": "The command list is fixed and the shell is not invoked in the reachable code path.",
            }
        ]

        body = comment.build_comment_body(payload)

        self.assertIn("caretrack/support_tools.py", body)
        self.assertIn("Adversarial review: downgraded", body)
        self.assertNotIn("Challenged findings (1)", body)

    def test_build_comment_body_omits_origin_badge_when_origin_missing(self) -> None:
        body = comment.build_comment_body(BASE_PAYLOAD)

        self.assertNotIn("<br>NEW", body)
        self.assertNotIn("PRE-EXISTING", body)

    def test_dry_run_with_critical_findings_returns_failing_exit_code(self) -> None:
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "narrative-findings.json"
            input_path.write_text(json.dumps(BASE_PAYLOAD), encoding="utf-8")

            with patch("sys.argv", ["comment.py", "--input", str(input_path), "--dry-run"]):
                with patch("sys.stdout", new=StringIO()):
                    exit_code = comment.main()

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
