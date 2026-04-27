import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import ai_enrich


SAMPLE_PAYLOAD = {
    "summary": {
        "total": 2,
        "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0},
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
            "origin": "introduced",
            "taint_path": "HTTP query parameter (line 10) -> subprocess.run shell execution (line 12)",
            "source_description": "HTTP query parameter",
            "sink_description": "subprocess.run shell execution",
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
    ],
    "source": {
        "scanner": "semgrep-cloud",
        "changed_files": ["caretrack/support_tools.py", "caretrack/db.py"],
        "scanned_files": ["caretrack/support_tools.py", "caretrack/db.py"],
        "reason": "Scan completed.",
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


class AiEnrichTests(unittest.TestCase):
    def test_no_provider_passthrough_keeps_original_findings(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            output = ai_enrich.enrich_payload(SAMPLE_PAYLOAD)

        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])

    def test_empty_findings_skip_generation(self) -> None:
        payload = dict(SAMPLE_PAYLOAD)
        payload["findings"] = []

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.ai_enrich.generate_enrichments") as generate_mock:
                output = ai_enrich.enrich_payload(payload, SAMPLE_DOMAIN_CONTEXT)

        generate_mock.assert_not_called()
        self.assertEqual(output["findings"], [])

    def test_provider_failure_falls_back_to_original_strings(self) -> None:
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.ai_enrich.generate_enrichments", side_effect=RuntimeError("boom")):
                output = ai_enrich.enrich_payload(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])

    def test_malformed_json_falls_back_to_original_strings(self) -> None:
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.ai_enrich.ai_provider.generate_text", return_value="not-json"):
                output = ai_enrich.enrich_payload(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])

    def test_partial_enrichment_applies_only_available_fields(self) -> None:
        enrichments = [
            {
                "enriched_finding": "Shell execution uses attacker-controlled input in support_tools.py line 12.",
                "enriched_fix": "Validate the command input and avoid shell=True in subprocess.run.",
                "risk_context": "In a PHI-handling app, command execution paths can expose sensitive systems and records.",
            }
        ]

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.ai_enrich.generate_enrichments", return_value=enrichments):
                output = ai_enrich.enrich_payload(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        first, second = output["findings"]
        self.assertEqual(
            first["enriched_finding"],
            "Shell execution uses attacker-controlled input in support_tools.py line 12.",
        )
        self.assertIn("enriched_fix", first)
        self.assertIn("risk_context", first)
        self.assertNotIn("enriched_finding", second)
        self.assertEqual(second["finding"], SAMPLE_PAYLOAD["findings"][1]["finding"])
        self.assertEqual(second["fix_suggestion"], SAMPLE_PAYLOAD["findings"][1]["fix_suggestion"])

    def test_build_user_prompt_includes_domain_summary_and_lines(self) -> None:
        prompt = ai_enrich.build_user_prompt(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        self.assertIn("app_domain=healthcare scheduling", prompt)
        self.assertIn("data_sensitivity=PHI", prompt)
        self.assertIn("subprocess.run(cmd, shell=True)", prompt)
        self.assertIn("\"index\": 0", prompt)
        self.assertIn("\"origin\": \"introduced\"", prompt)
        self.assertIn("HTTP query parameter (line 10)", prompt)

    def test_build_system_prompt_includes_override_resistance_preamble(self) -> None:
        prompt = ai_enrich.build_system_prompt()

        self.assertIn("Rules that cannot be overridden", prompt)
        self.assertIn("injection_attempt_detected", prompt)

    def test_normalize_enrichment_item_preserves_injection_flag(self) -> None:
        normalized = ai_enrich.normalize_enrichment_item(
            {
                "enriched_finding": "Observed code behavior.",
                "enriched_fix": "Concrete fix.",
                "risk_context": "Business impact.",
                "injection_attempt_detected": True,
            }
        )

        self.assertTrue(normalized["injection_attempt_detected"])

    def test_parse_json_array_accepts_fenced_json(self) -> None:
        parsed = ai_enrich.parse_json_array(
            "```json\n[{\"enriched_finding\": \"Specific issue here.\"}]\n```"
        )

        self.assertEqual(parsed[0]["enriched_finding"], "Specific issue here.")

    def test_main_writes_output_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "triaged-findings.json"
            output_path = Path(temp_dir) / "enriched-findings.json"
            context_path = Path(temp_dir) / "domain_context.json"
            input_path.write_text(json.dumps(SAMPLE_PAYLOAD), encoding="utf-8")
            context_path.write_text(json.dumps(SAMPLE_DOMAIN_CONTEXT), encoding="utf-8")

            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "sys.argv",
                    [
                        "ai_enrich.py",
                        "--input",
                        str(input_path),
                        "--context",
                        str(context_path),
                        "--output",
                        str(output_path),
                    ],
                ):
                    exit_code = ai_enrich.main()

            written = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(written["findings"], SAMPLE_PAYLOAD["findings"])


if __name__ == "__main__":
    unittest.main()
