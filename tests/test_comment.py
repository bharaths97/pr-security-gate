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
    def test_build_comment_body_renders_narrative_as_plain_text_after_status(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["narrative"] = "In a healthcare application handling patient records, 1 CRITICAL finding(s) in caretrack/support_tools.py - replace shell=True before merge."

        body = comment.build_comment_body(payload)

        self.assertIn("Status: failing - 1 CRITICAL finding(s) detected", body)
        self.assertIn(payload["narrative"], body)
        self.assertNotIn("> In a healthcare application", body)

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

    def test_build_comment_body_renders_fixed_four_column_table_with_taint_in_finding_cell(self) -> None:
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

        self.assertIn("| Badge | Finding | Severity | Fix Suggestion |", body)
        self.assertNotIn("| Taint Path |", body)
        self.assertIn("NEW", main_section)
        self.assertIn("Taint path:", main_section)
        self.assertNotIn("caretrack/legacy.py", main_section)
        self.assertIn("<summary>Pre-existing findings (1)</summary>", body)
        self.assertIn("PRE-EXISTING", details_section)
        self.assertIn("caretrack/legacy.py", details_section)

    def test_build_comment_body_appends_sustained_adversarial_note_in_main_table(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["summary"] = {
            "total": 1,
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "has_critical": False,
        }
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "severity": "high",
                "verdict": "sustained",
                "rationale": "The input is partially validated, but user-controlled data still reaches shell execution.",
            }
        ]

        body = comment.build_comment_body(payload)

        self.assertIn("AI auditor: sustained", body)
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
                "rationale": "The visible path appears constrained before the sink.",
                "counter_argument": "The query string is assembled from an internal enum and not user input.",
            },
        ]

        body = comment.build_comment_body(payload)
        main_section, details_section = body.split("<details>", maxsplit=1)

        self.assertNotIn("caretrack/db.py", main_section)
        self.assertIn("<summary>Challenged findings (1)</summary>", body)
        self.assertIn("AI auditor challenge", details_section)
        self.assertIn("internal enum", details_section)

    def test_build_comment_body_routes_downgraded_critical_findings_to_auditor_notes(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "verdict": "downgraded",
                "rationale": "The command list appears fixed in the reachable path.",
                "counter_argument": "The command list is fixed and the shell is not invoked in the reachable code path.",
            }
        ]

        body = comment.build_comment_body(payload)
        main_section, details_section = body.split("<details>", maxsplit=1)

        self.assertIn("caretrack/support_tools.py", main_section)
        self.assertNotIn("Adversarial review: downgraded", body)
        self.assertIn("AI auditor notes — does not affect gate decision", body)
        self.assertIn("downgraded", details_section)
        self.assertIn("shell is not invoked", details_section)
        self.assertNotIn("Challenged findings (1)", body)

    def test_build_comment_body_keeps_insufficient_evidence_in_main_table_with_uncertain_badge(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["summary"] = {
            "total": 1,
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "has_critical": False,
        }
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "severity": "high",
                "verdict": "insufficient_evidence",
                "rationale": "The diff does not include the helper implementation needed to judge exploitability.",
            }
        ]

        body = comment.build_comment_body(payload)
        main_section = body.split("<details>", maxsplit=1)[0]

        self.assertIn("? Uncertain", main_section)
        self.assertIn("AI auditor: uncertain", main_section)
        self.assertIn("helper implementation needed", main_section)
        self.assertIn("caretrack/support_tools.py", main_section)
        self.assertNotIn("Challenged findings (1)", body)

    def test_build_comment_body_keeps_sustained_critical_findings_out_of_main_table_notes(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["findings"] = [
            {
                **BASE_PAYLOAD["findings"][0],
                "verdict": "sustained",
                "rationale": "User input still reaches the sink after partial validation.",
            }
        ]

        body = comment.build_comment_body(payload)
        main_section, details_section = body.split("<details>", maxsplit=1)

        self.assertIn("caretrack/support_tools.py", main_section)
        self.assertNotIn("AI auditor: sustained", main_section)
        self.assertIn("AI auditor notes — does not affect gate decision", body)
        self.assertIn("sustained", details_section)
        self.assertIn("partial validation", details_section)

    def test_build_comment_body_renders_cross_file_chains_in_extended_analysis_only(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["summary"] = {
            "total": 2,
            "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "has_critical": True,
            "cross_file_chains": 1,
        }
        payload["findings"] = [
            BASE_PAYLOAD["findings"][0],
            {
                "rule_id": "cross-file-chain",
                "severity": "info",
                "file": "caretrack/support_tools.py",
                "line": 21,
                "finding": "Cross-file taint chain detected.",
                "cwe": "N/A",
                "fix_suggestion": "Review downstream usage.",
                "origin": "cross-file",
                "confidence": "low",
                "chain": "parse_user_request() [changed] -> db_manager.search_users() [unchanged] -> cursor.execute() [sink]",
                "hops": 1,
            },
        ]

        body = comment.build_comment_body(payload)
        main_section, details_section = body.split("<details>", maxsplit=1)

        self.assertNotIn("cross-file-chain", main_section)
        self.assertNotIn("cursor.execute()", main_section)
        self.assertIn("<summary>Extended Analysis (1)</summary>", body)
        self.assertIn("Low-confidence cross-file chains", details_section)
        self.assertIn("| Confidence | Chain |", details_section)
        self.assertIn("cursor.execute()", details_section)

    def test_build_comment_body_omits_origin_badge_when_origin_missing(self) -> None:
        body = comment.build_comment_body(BASE_PAYLOAD)

        self.assertIn("| - |", body)
        self.assertNotIn("PRE-EXISTING", body)

    def test_render_comment_status_vocabulary_matches_conditions(self) -> None:
        failing = comment.render_comment(
            {
                "summary": {"total": 1, "counts": {"critical": 1}, "has_critical": True},
                "findings": [{"rule_id": "r", "file": "f.py", "line": 1, "severity": "CRITICAL", "finding": "m", "fix_suggestion": "fix", "cwe": "CWE-1"}],
            },
            has_critical=True,
        )
        self.assertIn("Status: failing - 1 CRITICAL finding(s) detected", failing)

        passing_high = comment.render_comment(
            {
                "summary": {"total": 2, "counts": {"high": 2}, "has_critical": False},
                "findings": [
                    {"rule_id": "r", "file": "f.py", "line": 1, "severity": "HIGH", "finding": "m", "fix_suggestion": "fix", "cwe": "CWE-1"},
                    {"rule_id": "r2", "file": "f.py", "line": 2, "severity": "HIGH", "finding": "m2", "fix_suggestion": "fix2", "cwe": "CWE-1"},
                ],
            },
            has_critical=False,
        )
        self.assertIn("Status: passing - 2 HIGH finding(s) require review before merge", passing_high)

        passing_none = comment.render_comment(
            {"summary": {"total": 0, "counts": {}, "has_critical": False}, "findings": []},
            has_critical=False,
        )
        self.assertIn("Status: passing - no findings detected", passing_none)

    def test_build_comment_body_caps_finding_and_fix_to_one_sentence_and_strips_location_repetition(self) -> None:
        payload = dict(BASE_PAYLOAD)
        payload["summary"] = {
            "total": 1,
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "has_critical": False,
        }
        payload["findings"] = [
            {
                "rule_id": "rule-2",
                "severity": "high",
                "file": "caretrack/support_tools.py",
                "line": 15,
                "finding": (
                    "Untrusted input can result in command injection vulnerabilities due to direct execution of OS commands "
                    "with user-provided data in caretrack/support_tools.py at line 15. This is a very dangerous pattern."
                ),
                "cwe": "CWE-78",
                "fix_suggestion": (
                    "Replace the subprocess call in caretrack/support_tools.py at line 15 with subprocess.run(['ping', host], "
                    "shell=False) and add input validation. Also ensure you are logging all invocations."
                ),
            }
        ]

        body = comment.build_comment_body(payload)

        self.assertIn("Untrusted input can result in command injection vulnerabilities due to direct execution of OS commands with user-provided data in.", body)
        self.assertNotIn("This is a very dangerous pattern.", body)
        self.assertNotIn("caretrack/support_tools.py at line 15", body)
        self.assertNotIn("Also ensure you are logging all invocations.", body)

    def test_dry_run_with_critical_findings_returns_failing_exit_code(self) -> None:
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "narrative-findings.json"
            input_path.write_text(json.dumps(BASE_PAYLOAD), encoding="utf-8")

            with patch("sys.argv", ["comment.py", "--input", str(input_path), "--dry-run"]):
                with patch("sys.stdout", new=StringIO()):
                    exit_code = comment.main()

        self.assertEqual(exit_code, 1)

    def test_dry_run_with_only_cross_file_findings_keeps_passing_exit_code(self) -> None:
        payload = {
            "summary": {
                "total": 1,
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "has_critical": False,
                "cross_file_chains": 1,
            },
            "findings": [
                {
                    "rule_id": "cross-file-chain",
                    "severity": "info",
                    "file": "caretrack/support_tools.py",
                    "line": 21,
                    "finding": "Cross-file taint chain detected.",
                    "cwe": "N/A",
                    "fix_suggestion": "Review downstream usage.",
                    "origin": "cross-file",
                    "confidence": "low",
                    "chain": "parse_user_request() [changed] -> db_manager.search_users() [unchanged] -> cursor.execute() [sink]",
                    "hops": 1,
                }
            ],
            "source": dict(BASE_PAYLOAD["source"]),
            "narrative": None,
        }

        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "narrative-findings.json"
            input_path.write_text(json.dumps(payload), encoding="utf-8")

            with patch("sys.argv", ["comment.py", "--input", str(input_path), "--dry-run"]):
                with patch("sys.stdout", new=StringIO()):
                    exit_code = comment.main()

        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
