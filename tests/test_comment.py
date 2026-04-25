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
