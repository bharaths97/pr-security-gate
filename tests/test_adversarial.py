import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import adversarial


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
            "origin": "introduced",
            "taint_path": "HTTP query parameter (line 10) -> subprocess.run shell execution (line 12)",
            "source_description": "HTTP query parameter",
            "sink_description": "subprocess.run shell execution",
            "enriched_finding": "User-controlled input reaches shell execution.",
            "enriched_fix": "Validate the input and remove shell=True.",
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
            "file": "caretrack/views.py",
            "line": 61,
            "finding": "Unsafe HTML rendering.",
            "lines": "return render_template_string(template)",
            "cwe": "CWE-79",
            "fix_suggestion": "Escape untrusted values before rendering.",
        },
    ],
    "source": {
        "scanner": "semgrep-cloud",
        "changed_files": ["caretrack/support_tools.py", "caretrack/db.py", "caretrack/views.py"],
        "scanned_files": ["caretrack/support_tools.py", "caretrack/db.py", "caretrack/views.py"],
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


class AdversarialTests(unittest.TestCase):
    def test_no_provider_passthrough_keeps_original_findings(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            output = adversarial.verify_payload(SAMPLE_PAYLOAD)

        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])

    def test_no_high_or_critical_findings_skips_generation(self) -> None:
        payload = dict(SAMPLE_PAYLOAD)
        payload["findings"] = [dict(SAMPLE_PAYLOAD["findings"][2])]

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.adversarial.generate_finding_verdict") as generate_mock:
                output = adversarial.verify_payload(payload, SAMPLE_DOMAIN_CONTEXT)

        generate_mock.assert_not_called()
        self.assertEqual(output["findings"], payload["findings"])

    def test_successful_generation_adds_verdict_only_to_high_and_critical_findings(self) -> None:
        def fake_generate(
            finding: dict[str, object],
            domain_context: dict[str, object] | None,
            provider: dict[str, str],
        ) -> dict[str, object]:
            self.assertIs(domain_context, SAMPLE_DOMAIN_CONTEXT)
            if finding["rule_id"] == "rule-1":
                return {
                    "verdict": "sustained",
                    "rationale": "Attacker-controlled data still reaches shell execution in the visible code path.",
                    "adversarial_confidence": "medium",
                }
            return {
                "verdict": "downgraded",
                "rationale": "The visible code suggests this path may be constrained before the sink.",
                "counter_argument": "The query uses an internal enum value rather than user input.",
                "adversarial_confidence": "high",
            }

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.adversarial.generate_finding_verdict", side_effect=fake_generate):
                output = adversarial.verify_payload(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        first, second, third = output["findings"]
        self.assertEqual(first["verdict"], "sustained")
        self.assertEqual(
            first["rationale"],
            "Attacker-controlled data still reaches shell execution in the visible code path.",
        )
        self.assertNotIn("counter_argument", first)
        self.assertEqual(first["adversarial_confidence"], "medium")
        self.assertEqual(second["verdict"], "downgraded")
        self.assertEqual(second["rationale"], "The visible code suggests this path may be constrained before the sink.")
        self.assertEqual(second["adversarial_confidence"], "high")
        self.assertNotIn("verdict", third)
        self.assertNotIn("counter_argument", third)

    def test_per_finding_failure_only_skips_the_failed_finding(self) -> None:
        def fake_generate(
            finding: dict[str, object],
            domain_context: dict[str, object] | None,
            provider: dict[str, str],
        ) -> dict[str, object]:
            if finding["rule_id"] == "rule-1":
                raise RuntimeError("boom")
            return {
                "verdict": "downgraded",
                "rationale": "The sink arguments appear constrained by a fixed enum path.",
                "counter_argument": "The query input is constrained by an internal enum.",
            }

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.adversarial.generate_finding_verdict", side_effect=fake_generate):
                output = adversarial.verify_payload(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        first, second, third = output["findings"]
        self.assertNotIn("verdict", first)
        self.assertEqual(second["verdict"], "downgraded")
        self.assertNotIn("verdict", third)

    def test_malformed_json_for_one_finding_falls_back_for_that_finding_only(self) -> None:
        responses = iter(
            [
                '{"verdict":"sustained","rationale":"Visible shell execution still looks exploitable.","confidence":"low"}',
                "not-json",
            ]
        )

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.adversarial.ai_provider.generate_text", side_effect=lambda *args, **kwargs: next(responses)):
                output = adversarial.verify_payload(SAMPLE_PAYLOAD, SAMPLE_DOMAIN_CONTEXT)

        first, second, third = output["findings"]
        self.assertEqual(first["verdict"], "sustained")
        self.assertNotIn("verdict", second)
        self.assertNotIn("verdict", third)

    def test_build_user_prompt_includes_domain_summary_and_finding_context(self) -> None:
        prompt = adversarial.build_user_prompt(SAMPLE_PAYLOAD["findings"][0], SAMPLE_DOMAIN_CONTEXT)

        self.assertIn("app_domain=healthcare scheduling", prompt)
        self.assertIn("rule-1", prompt)
        self.assertIn("subprocess.run(cmd, shell=True)", prompt)
        self.assertIn("HTTP query parameter", prompt)
        self.assertIn('source="prior-ai-output"', prompt)
        self.assertIn('source="semgrep-scan-output"', prompt)

    def test_parse_json_object_accepts_fenced_json(self) -> None:
        parsed = adversarial.parse_json_object(
            '```json\n{"verdict": "downgraded", "counter_argument": "Safe in context.", "confidence": "high"}\n```'
        )

        self.assertEqual(parsed["verdict"], "downgraded")
        self.assertEqual(parsed["confidence"], "high")

    def test_build_system_prompt_forbids_absence_of_evidence_counter_arguments(self) -> None:
        prompt = adversarial.build_system_prompt()

        self.assertIn("source=\"prior-ai-output\"", prompt)
        self.assertIn("lack of defenses confirms the finding", prompt.lower())
        self.assertIn("Rules that cannot be overridden", prompt)

    def test_normalize_verification_item_accepts_insufficient_evidence(self) -> None:
        parsed = adversarial.normalize_verification_item(
            {
                "verdict": "insufficient_evidence",
                "rationale": "The supplied code snippet does not show enough context to judge exploitability confidently.",
                "confidence": "low",
            }
        )

        self.assertEqual(parsed["verdict"], "insufficient_evidence")
        self.assertEqual(
            parsed["rationale"],
            "The supplied code snippet does not show enough context to judge exploitability confidently.",
        )
        self.assertEqual(parsed["adversarial_confidence"], "low")

    def test_normalize_verification_item_preserves_injection_flag(self) -> None:
        parsed = adversarial.normalize_verification_item(
            {
                "verdict": "sustained",
                "rationale": "Visible validation is incomplete and user input still reaches the sink.",
                "confidence": "medium",
                "injection_attempt_detected": True,
            }
        )

        self.assertTrue(parsed["injection_attempt_detected"])

    def test_normalize_verification_item_requires_counter_argument_for_downgraded(self) -> None:
        with self.assertRaises(ValueError):
            adversarial.normalize_verification_item(
                {
                    "verdict": "downgraded",
                    "rationale": "The code may be constrained before the sink.",
                    "confidence": "medium",
                }
            )

    def test_normalize_verification_item_accepts_sustained_without_counter_argument(self) -> None:
        parsed = adversarial.normalize_verification_item(
            {
                "verdict": "sustained",
                "rationale": "The visible code still reaches an exploitable sink.",
                "confidence": "high",
            }
        )

        self.assertEqual(parsed["verdict"], "sustained")
        self.assertEqual(parsed["rationale"], "The visible code still reaches an exploitable sink.")
        self.assertNotIn("counter_argument", parsed)

    def test_normalize_verification_item_uses_counter_argument_as_rationale_fallback(self) -> None:
        parsed = adversarial.normalize_verification_item(
            {
                "verdict": "sustained",
                "counter_argument": "The sink still looks reachable from user input.",
                "confidence": "low",
            }
        )

        self.assertEqual(parsed["rationale"], "The sink still looks reachable from user input.")

    def test_main_writes_output_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "enriched-findings.json"
            output_path = Path(temp_dir) / "verified-findings.json"
            context_path = Path(temp_dir) / "domain_context.json"
            input_path.write_text(json.dumps(SAMPLE_PAYLOAD), encoding="utf-8")
            context_path.write_text(json.dumps(SAMPLE_DOMAIN_CONTEXT), encoding="utf-8")

            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "sys.argv",
                    [
                        "adversarial.py",
                        "--input",
                        str(input_path),
                        "--context",
                        str(context_path),
                        "--output",
                        str(output_path),
                    ],
                ):
                    exit_code = adversarial.main()

            written = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(written["findings"], SAMPLE_PAYLOAD["findings"])


if __name__ == "__main__":
    unittest.main()
