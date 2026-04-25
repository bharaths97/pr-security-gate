import json
import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import domain_context


class DomainContextTests(unittest.TestCase):
    def test_collect_context_files_uses_safe_top_level_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "README.md").write_text("# CareTrack\nHealthcare scheduling app.", encoding="utf-8")
            (repo_root / "Dockerfile").write_text("FROM python:3.11", encoding="utf-8")
            (repo_root / ".env.example").write_text("DATABASE_URL=", encoding="utf-8")
            (repo_root / ".env").write_text("SECRET=real", encoding="utf-8")
            (repo_root / "app.py").write_text("print('source')", encoding="utf-8")
            (repo_root / "scan-results.json").write_text("{}", encoding="utf-8")
            (repo_root / "triaged-findings.json").write_text("{}", encoding="utf-8")
            (repo_root / "narrative-findings.json").write_text("{}", encoding="utf-8")
            (repo_root / "domain_context.json").write_text("{}", encoding="utf-8")
            (repo_root / "enriched-findings.json").write_text("{}", encoding="utf-8")
            (repo_root / ".pr-security-gate").mkdir()
            (repo_root / ".pr-security-gate" / "README.md").write_text("scanner docs", encoding="utf-8")

            files = domain_context.collect_context_files(repo_root)

        self.assertEqual([path.name for path in files], [".env.example", "Dockerfile", "README.md"])

    def test_no_provider_writes_unknown_context(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "README.md").write_text("# Demo app", encoding="utf-8")

            with patch.dict("os.environ", {}, clear=True):
                context = domain_context.generate_domain_context(repo_root)

        self.assertFalse(context["generated"])
        self.assertEqual(context["reason"], "no_provider")
        self.assertEqual(context["risk_tier"], "unknown")
        self.assertEqual(context["source_files"], ["README.md"])

    def test_no_context_files_writes_unknown_context(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "app.py").write_text("print('source')", encoding="utf-8")

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                context = domain_context.generate_domain_context(repo_root)

        self.assertFalse(context["generated"])
        self.assertEqual(context["reason"], "no_context_files")

    def test_provider_failure_writes_unknown_context(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "README.md").write_text("# Demo app", encoding="utf-8")

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                with patch("scanner.domain_context.ai_provider.generate_text", side_effect=RuntimeError("boom")):
                    context = domain_context.generate_domain_context(repo_root)

        self.assertFalse(context["generated"])
        self.assertEqual(context["reason"], "provider_failed")

    def test_malformed_prompt_falls_back_to_unknown_context(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "README.md").write_text("# Demo app", encoding="utf-8")

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                with patch(
                    "scanner.domain_context.prompt_loader.render",
                    side_effect=tomllib.TOMLDecodeError("bad prompt", "x", 0),
                ):
                    context = domain_context.generate_domain_context(repo_root)

        self.assertFalse(context["generated"])
        self.assertEqual(context["reason"], "provider_failed")

    def test_successful_generation_normalizes_context(self) -> None:
        response = json.dumps(
            {
                "app_domain": "healthcare scheduling",
                "data_sensitivity": "PHI",
                "regulatory_context": ["HIPAA"],
                "user_types": ["patients", "clinicians"],
                "deployment": "containerized web app",
                "risk_tier": "high",
            }
        )

        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "README.md").write_text("# CareTrack\nPatient appointments.", encoding="utf-8")

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                with patch("scanner.domain_context.ai_provider.generate_text", return_value=response):
                    context = domain_context.generate_domain_context(repo_root)

        self.assertTrue(context["generated"])
        self.assertEqual(context["app_domain"], "healthcare scheduling")
        self.assertEqual(context["data_sensitivity"], "PHI")
        self.assertEqual(context["regulatory_context"], ["HIPAA"])
        self.assertEqual(context["risk_tier"], "high")
        self.assertEqual(context["source_files"], ["README.md"])

    def test_main_writes_output_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            repo_root.mkdir()
            (repo_root / "README.md").write_text("# Demo app", encoding="utf-8")
            output_path = Path(temp_dir) / "domain_context.json"

            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "sys.argv",
                    [
                        "domain_context.py",
                        "--repo-root",
                        str(repo_root),
                        "--output",
                        str(output_path),
                    ],
                ):
                    exit_code = domain_context.main()

            written = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertFalse(written["generated"])
        self.assertEqual(written["reason"], "no_provider")

    def test_build_system_prompt_mentions_user_controlled_strings(self) -> None:
        prompt = domain_context.build_system_prompt()

        self.assertIn("may contain user-controlled strings", prompt)


if __name__ == "__main__":
    unittest.main()
