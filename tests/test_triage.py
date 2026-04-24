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
        self.assertEqual(finding["score"], 3)
        self.assertEqual(finding["cwe"], "CWE-79: Cross-site Scripting")


if __name__ == "__main__":
    unittest.main()
