import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import threat_model


SAMPLE_DOMAIN_CONTEXT = {
    "generated": True,
    "app_domain": "healthcare scheduling",
    "data_sensitivity": "PHI",
    "regulatory_context": ["HIPAA"],
    "user_types": ["patients", "clinicians"],
    "deployment": "containerized web app",
    "risk_tier": "high",
}

SAMPLE_TERRAIN = {
    "findings": [
        {
            "file": "caretrack/routes/export.py",
            "line": 48,
            "origin": "introduced",
            "source_line": 18,
            "source_description": "HTTP GET /export route parameter",
            "sink_line": 48,
            "sink_description": "bulk record export response",
        },
        {
            "file": "caretrack/db.py",
            "line": 81,
            "origin": "pre-existing",
            "source_line": 40,
            "source_description": "database search parameter",
            "sink_line": 81,
            "sink_description": "cursor.execute string interpolation",
        },
    ],
    "source": {
        "changed_files": ["caretrack/routes/export.py", "caretrack/db.py"],
        "scanned_files": ["caretrack/routes/export.py", "caretrack/db.py"],
    },
}

SAMPLE_TRIAGE = {
    "summary": {
        "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0},
    },
    "findings": [
        {
            "severity": "high",
            "file": "caretrack/routes/export.py",
            "line": 48,
            "finding": "Export endpoint may expose patient records.",
        },
        {
            "severity": "medium",
            "file": "caretrack/db.py",
            "line": 81,
            "finding": "Query building remains fragile.",
        },
    ],
}


class ThreatModelTests(unittest.TestCase):
    def test_build_user_prompt_omits_pr_description_when_blank(self) -> None:
        prompt = threat_model.build_user_prompt(
            SAMPLE_DOMAIN_CONTEXT,
            SAMPLE_TERRAIN,
            SAMPLE_TRIAGE,
            "Add patient export route",
            "",
        )

        self.assertIn("Add patient export route", prompt)
        self.assertNotIn("PR description:", prompt)
        self.assertIn("entry_points_added", prompt)
        self.assertIn("reachable_sinks", prompt)

    def test_successful_generation_returns_normalized_output(self) -> None:
        ai_response = json.dumps(
            {
                "pr_title": "Add patient export route",
                "domain_summary": "healthcare scheduling with PHI access",
                "entry_points_added": [
                    {
                        "file": "caretrack/routes/export.py",
                        "line": 18,
                        "description": "HTTP GET /export route parameter",
                    }
                ],
                "assets_at_risk": ["patient records", "session tokens", "patient records"],
                "threat_actors": [
                    "unauthenticated external users",
                    "authenticated low-privilege users",
                    "support staff",
                    "extra actor that should be trimmed",
                ],
                "blast_radius": "An attacker could trigger bulk patient record export through the new route. Additional sentence.",
                "mitigations_present": ["admin role check"],
                "mitigations_absent": ["download rate limiting"],
                "domain_risks": ["HIPAA exposure if exploited"],
                "generated": True,
            }
        )

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.threat_model.ai_provider.generate_text", return_value=ai_response):
                output = threat_model.build_threat_model_output(
                    SAMPLE_DOMAIN_CONTEXT,
                    SAMPLE_TERRAIN,
                    SAMPLE_TRIAGE,
                    "Add patient export route",
                    "Adds a new /export route for admins.",
                )

        self.assertTrue(output["generated"])
        self.assertEqual(output["pr_title"], "Add patient export route")
        self.assertEqual(len(output["entry_points_added"]), 1)
        self.assertEqual(output["assets_at_risk"], ["patient records", "session tokens"])
        self.assertEqual(len(output["threat_actors"]), 3)
        self.assertEqual(
            output["blast_radius"],
            "An attacker could trigger bulk patient record export through the new route.",
        )

    def test_provider_failure_falls_back_to_generated_false(self) -> None:
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch("scanner.threat_model.ai_provider.generate_text", side_effect=RuntimeError("boom")):
                output = threat_model.build_threat_model_output(
                    SAMPLE_DOMAIN_CONTEXT,
                    SAMPLE_TERRAIN,
                    SAMPLE_TRIAGE,
                    "Add patient export route",
                    "Adds a new /export route for admins.",
                )

        self.assertEqual(output, {"generated": False})

    def test_generated_false_passthrough_is_preserved(self) -> None:
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
            with patch(
                "scanner.threat_model.ai_provider.generate_text",
                return_value='{"generated": false}',
            ):
                output = threat_model.build_threat_model_output(
                    SAMPLE_DOMAIN_CONTEXT,
                    SAMPLE_TERRAIN,
                    SAMPLE_TRIAGE,
                    "Add patient export route",
                    None,
                )

        self.assertEqual(output, {"generated": False})

    def test_main_writes_generated_false_when_input_file_missing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_path = temp_path / "threat-model.json"
            domain_context_path = temp_path / "domain_context.json"
            terrain_path = temp_path / "terrain-findings.json"
            domain_context_path.write_text(json.dumps(SAMPLE_DOMAIN_CONTEXT), encoding="utf-8")
            terrain_path.write_text(json.dumps(SAMPLE_TERRAIN), encoding="utf-8")

            with patch(
                "sys.argv",
                [
                    "threat_model.py",
                    "--domain-context",
                    str(domain_context_path),
                    "--terrain",
                    str(terrain_path),
                    "--triage",
                    str(temp_path / "triaged-findings.json"),
                    "--pr-title",
                    "Add patient export route",
                    "--output",
                    str(output_path),
                ],
            ):
                exit_code = threat_model.main()

            written = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(written, {"generated": False})


if __name__ == "__main__":
    unittest.main()
