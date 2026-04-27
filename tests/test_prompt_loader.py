import shutil
import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import prompt_loader


class PromptLoaderTests(unittest.TestCase):
    def tearDown(self) -> None:
        prompt_loader._PROMPT_CACHE.clear()

    def test_render_rejects_unexpected_variables(self) -> None:
        with self.assertRaises(ValueError):
            prompt_loader.render(
                "narrative",
                "user_template",
                github_repository="org/repo",
                pr_title="Title",
                pr_branch="branch",
                critical=1,
                high=0,
                medium=0,
                low=0,
                scanned_files=1,
                changed_files=1,
                findings_block="- HIGH | app.py:1 | test",
                injected="nope",
            )

    def test_render_strips_control_characters_and_nulls(self) -> None:
        rendered = prompt_loader.render(
            "domain_context",
            "user_template",
            files_block="README\x00.md\r\nValue:\x07 None field => " + str(None),
        )

        self.assertNotIn("\x00", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("README.md\nValue: None field => None", rendered)

    def test_render_replaces_none_with_unknown(self) -> None:
        rendered = prompt_loader.render(
            "domain_context",
            "user_template",
            files_block=None,
        )

        self.assertIn("unknown", rendered)

    def test_render_truncates_large_values(self) -> None:
        with patch.object(prompt_loader, "MAX_INJECT_BYTES", 5):
            rendered = prompt_loader.render(
                "domain_context",
                "user_template",
                files_block="abcdefghij",
            )

        self.assertIn("abcde", rendered)
        self.assertNotIn("abcdef", rendered)

    def test_load_raises_for_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            prompt_loader.load("missing-prompt")

    def test_load_raises_for_malformed_toml(self) -> None:
        with TemporaryDirectory() as temp_dir:
            prompt_dir = Path(temp_dir)
            (prompt_dir / "domain_context.toml").write_text("[meta]\nphase =\n", encoding="utf-8")

            with patch.object(prompt_loader, "PROMPT_DIR", prompt_dir):
                with self.assertRaises(tomllib.TOMLDecodeError):
                    prompt_loader.load("domain_context")

    def test_load_caches_prompts(self) -> None:
        with TemporaryDirectory() as temp_dir:
            prompt_dir = Path(temp_dir)
            shutil.copy(
                Path(prompt_loader.PROMPT_DIR) / "narrative.toml",
                prompt_dir / "narrative.toml",
            )

            with patch.object(prompt_loader, "PROMPT_DIR", prompt_dir):
                first = prompt_loader.load("narrative")
                second = prompt_loader.load("narrative")

        self.assertIs(first, second)

    def test_render_terrain_prompt_accepts_phase4_variables(self) -> None:
        rendered = prompt_loader.render(
            "terrain",
            "user_template",
            domain_summary="risk_tier=high",
            file_path="caretrack/support_tools.py",
            file_findings='{"findings": []}',
            file_content="1: print('hello')",
        )

        self.assertIn("caretrack/support_tools.py", rendered)
        self.assertIn("risk_tier=high", rendered)

    def test_render_adversarial_prompt_accepts_phase5_variables(self) -> None:
        rendered = prompt_loader.render(
            "adversarial",
            "user_template",
            domain_summary="risk_tier=high",
            finding_block='{"rule_id": "rule-1"}',
        )

        self.assertIn('{"rule_id": "rule-1"}', rendered)
        self.assertIn("risk_tier=high", rendered)

    def test_render_prompt_returns_system_and_user_sections(self) -> None:
        rendered = prompt_loader.render_prompt(
            "adversarial",
            {
                "domain_summary": "risk_tier=high",
                "finding_block": '{"rule_id": "rule-1"}',
            },
        )

        self.assertIn("system", rendered)
        self.assertIn("user", rendered)
        self.assertIn("insufficient_evidence", rendered["user"])

    def test_render_call_graph_prompt_accepts_phase6_variables(self) -> None:
        rendered = prompt_loader.render(
            "call_graph",
            "user_template",
            domain_summary="risk_tier=high",
            max_depth=2,
            changed_function_block='{"name": "parse_user_request"}',
            chain_block='{"functions": [{"name": "search_users"}]}',
        )

        self.assertIn('{"name": "parse_user_request"}', rendered)
        self.assertIn('{"functions": [{"name": "search_users"}]}', rendered)
        self.assertIn("risk_tier=high", rendered)


if __name__ == "__main__":
    unittest.main()
