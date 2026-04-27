import unittest

from scanner import triage


class TriageTests(unittest.TestCase):
    def test_normalize_severity_supports_semgrep_aliases(self) -> None:
        self.assertEqual(triage.normalize_severity("ERROR"), "high")
        self.assertEqual(triage.normalize_severity("WARNING"), "medium")
        self.assertEqual(triage.normalize_severity("INFO"), "low")
        self.assertEqual(triage.normalize_severity("CRITICAL"), "critical")

    def test_normalize_cwe_handles_lists(self) -> None:
        value = [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
            "CWE-88: Argument Injection or Modification",
        ]

        self.assertEqual(
            triage.normalize_cwe(value),
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command, CWE-88: Argument Injection or Modification",
        )

    def test_normalize_finding_handles_cloud_metadata(self) -> None:
        finding = triage.normalize_finding(
            {
                "check_id": "rule-1",
                "path": "src/app.py",
                "start": {"line": 14},
                "extra": {
                    "message": "Security finding detected.",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-79: Cross-site Scripting"],
                    },
                },
            }
        )

        self.assertEqual(finding["severity"], "high")
        self.assertNotIn("score", finding)
        self.assertEqual(finding["cwe"], "CWE-79: Cross-site Scripting")

    def test_normalize_finding_passes_through_lines(self) -> None:
        finding = triage.normalize_finding(
            {
                "check_id": "rule-2",
                "path": "src/config.py",
                "start": {"line": 9},
                "extra": {
                    "message": "Hardcoded secret.",
                    "lines": 'API_KEY = "hardcoded"',
                    "metadata": {},
                },
            }
        )

        self.assertEqual(finding["lines"], 'API_KEY = "hardcoded"')

    def test_dedup_findings_collapses_same_file_and_line(self) -> None:
        findings = [
            {
                "rule_id": "python.injection.cmd-a",
                "file": "app.py",
                "line": 15,
                "severity": "high",
                "finding": "cmd injection A",
            },
            {
                "rule_id": "python.injection.cmd-b",
                "file": "app.py",
                "line": 15,
                "severity": "medium",
                "finding": "cmd injection B",
            },
        ]

        result = triage.dedup_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "high")
        self.assertEqual(
            result[0]["rule_ids"],
            ["python.injection.cmd-a", "python.injection.cmd-b"],
        )

    def test_dedup_findings_keeps_different_lines_in_same_file(self) -> None:
        findings = [
            {"rule_id": "rule-a", "file": "app.py", "line": 15, "severity": "high"},
            {"rule_id": "rule-b", "file": "app.py", "line": 16, "severity": "medium"},
        ]

        result = triage.dedup_findings(findings)

        self.assertEqual(len(result), 2)

    def test_dedup_findings_keeps_same_line_in_different_files(self) -> None:
        findings = [
            {"rule_id": "rule-a", "file": "app.py", "line": 15, "severity": "high"},
            {"rule_id": "rule-b", "file": "utils.py", "line": 15, "severity": "medium"},
        ]

        result = triage.dedup_findings(findings)

        self.assertEqual(len(result), 2)

    def test_deduplicate_findings_keeps_highest_severity_per_location(self) -> None:
        results = [
            {
                "check_id": "rule-a",
                "path": "src/app.py",
                "start": {"line": 22},
                "extra": {
                    "message": "Lower severity finding.",
                    "severity": "WARNING",
                    "metadata": {},
                },
            },
            {
                "check_id": "rule-b",
                "path": "src/app.py",
                "start": {"line": 22},
                "extra": {
                    "message": "Higher severity finding.",
                    "severity": "ERROR",
                    "metadata": {},
                },
            },
        ]

        result = triage.deduplicate_findings(results)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "high")
        self.assertEqual(result[0]["rule_id"], "rule-b")
        self.assertEqual(result[0]["rule_ids"], ["rule-b", "rule-a"])


if __name__ == "__main__":
    unittest.main()
