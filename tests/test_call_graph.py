import os
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner import call_graph


SAMPLE_PAYLOAD = {
    "summary": {
        "total": 1,
        "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        "has_critical": True,
    },
    "findings": [
        {
            "rule_id": "rule-1",
            "severity": "critical",
            "file": "app/views.py",
            "line": 5,
            "finding": "Command injection risk in request parsing.",
            "cwe": "CWE-78",
            "fix_suggestion": "Validate input before invoking command execution.",
        }
    ],
    "source": {
        "scanner": "semgrep-cloud",
        "changed_files": ["app/views.py"],
        "scanned_files": ["app/views.py"],
        "reason": "Scan completed.",
        "base_sha": "",
        "head_sha": "",
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


class CallGraphTests(unittest.TestCase):
    def test_no_provider_passthrough_keeps_original_findings(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            self.write_file(
                repo_root / "app/views.py",
                """
                from app.db import search_users

                def parse_user_request(user_id):
                    return search_users(user_id)
                """,
            )
            self.write_file(
                repo_root / "app/db.py",
                """
                def search_users(user_id):
                    return cursor.execute(user_id)
                """,
            )

            with patch.dict("os.environ", {}, clear=True):
                output = call_graph.append_cross_file_findings(SAMPLE_PAYLOAD, repo_root)

        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])
        self.assertNotIn("cross_file_chains", output["summary"])

    def test_successful_generation_appends_cross_file_chain(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            self.write_file(
                repo_root / "app/views.py",
                """
                from app.db import search_users

                def parse_user_request(user_id):
                    cleaned = user_id.strip()
                    return search_users(cleaned)
                """,
            )
            self.write_file(
                repo_root / "app/db.py",
                """
                def search_users(user_id):
                    query = "SELECT * FROM users WHERE id = " + user_id
                    return cursor.execute(query)
                """,
            )

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                with patch(
                    "scanner.call_graph.ai_provider.generate_text",
                    return_value=(
                        '{"reaches_sink": true, "sink_description": "database query execution", '
                        '"chain": "parse_user_request() [changed] -> search_users() [unchanged] -> cursor.execute() [sink]"}'
                    ),
                ):
                    output = call_graph.append_cross_file_findings(
                        SAMPLE_PAYLOAD,
                        repo_root,
                        domain_context=SAMPLE_DOMAIN_CONTEXT,
                    )

        self.assertEqual(output["summary"]["cross_file_chains"], 1)
        self.assertEqual(output["summary"]["total"], 2)
        appended = output["findings"][-1]
        self.assertEqual(appended["rule_id"], "cross-file-chain")
        self.assertEqual(appended["origin"], "cross-file")
        self.assertEqual(appended["confidence"], "low")
        self.assertEqual(appended["hops"], 1)
        self.assertIn("cursor.execute()", appended["chain"])

    def test_changed_function_with_no_outbound_calls_emits_no_cross_file_chains(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            self.write_file(
                repo_root / "app/views.py",
                """
                def parse_user_request(user_id):
                    cleaned = user_id.strip()
                    return cleaned
                """,
            )

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                with patch("scanner.call_graph.ai_provider.generate_text") as generate_mock:
                    output = call_graph.append_cross_file_findings(SAMPLE_PAYLOAD, repo_root)

        generate_mock.assert_not_called()
        self.assertEqual(output["summary"]["cross_file_chains"], 0)
        self.assertEqual(output["findings"], SAMPLE_PAYLOAD["findings"])

    def test_depth_limit_prevents_longer_chain_until_limit_is_raised(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            self.write_file(
                repo_root / "app/views.py",
                """
                def parse_user_request(user_id):
                    return normalize_then_search(user_id)

                def normalize_then_search(user_id):
                    return search_users(user_id.strip())
                """,
            )
            self.write_file(
                repo_root / "app/search.py",
                """
                def search_users(user_id):
                    return cursor.execute(user_id)
                """,
            )
            payload = {
                **SAMPLE_PAYLOAD,
                "findings": [{**SAMPLE_PAYLOAD["findings"][0], "line": 2}],
                "source": {
                    **SAMPLE_PAYLOAD["source"],
                    "changed_files": ["app/views.py"],
                    "scanned_files": ["app/views.py"],
                },
            }

            with patch.dict(
                "os.environ",
                {"OPENAI_API_KEY": "test-key", "CALL_GRAPH_MAX_DEPTH": "1"},
                clear=True,
            ):
                with patch("scanner.call_graph.ai_provider.generate_text") as generate_mock:
                    limited_output = call_graph.append_cross_file_findings(payload, repo_root)

            with patch.dict(
                "os.environ",
                {"OPENAI_API_KEY": "test-key", "CALL_GRAPH_MAX_DEPTH": "2"},
                clear=True,
            ):
                with patch(
                    "scanner.call_graph.ai_provider.generate_text",
                    return_value=(
                        '{"reaches_sink": true, "sink_description": "database query execution", '
                        '"chain": "parse_user_request() [changed] -> normalize_then_search() [changed] -> search_users() [unchanged] -> cursor.execute() [sink]"}'
                    ),
                ):
                    expanded_output = call_graph.append_cross_file_findings(payload, repo_root)

        generate_mock.assert_not_called()
        self.assertEqual(limited_output["summary"]["cross_file_chains"], 0)
        self.assertEqual(expanded_output["summary"]["cross_file_chains"], 1)
        self.assertEqual(expanded_output["findings"][-1]["hops"], 2)

    def test_per_chain_failure_only_skips_failed_chain(self) -> None:
        with TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            self.write_file(
                repo_root / "app/views.py",
                """
                from app.db import search_users
                from app.shell import run_support_tool

                def parse_user_request(user_id):
                    return search_users(user_id)

                def parse_support_command(cmd):
                    return run_support_tool(cmd)
                """,
            )
            self.write_file(
                repo_root / "app/db.py",
                """
                def search_users(user_id):
                    return cursor.execute(user_id)
                """,
            )
            self.write_file(
                repo_root / "app/shell.py",
                """
                def run_support_tool(cmd):
                    return subprocess.run(cmd, shell=True)
                """,
            )
            payload = {
                **SAMPLE_PAYLOAD,
                "summary": {
                    "total": 2,
                    "counts": {"critical": 2, "high": 0, "medium": 0, "low": 0},
                    "has_critical": True,
                },
                "findings": [
                    {**SAMPLE_PAYLOAD["findings"][0], "line": 5},
                    {
                        **SAMPLE_PAYLOAD["findings"][0],
                        "rule_id": "rule-2",
                        "line": 8,
                        "finding": "Command execution risk in support helper.",
                    },
                ],
            }

            def fake_analyze(
                root_function: call_graph.FunctionDef,
                chain_functions: list[call_graph.FunctionDef],
                sink_description: str,
                max_depth: int,
                domain_context: dict[str, object] | None,
                provider: dict[str, str],
            ) -> dict[str, object]:
                if chain_functions[0].name == "search_users":
                    raise RuntimeError("boom")
                return {
                    "reaches_sink": True,
                    "sink_description": sink_description,
                    "chain": "parse_support_command() [changed] -> run_support_tool() [unchanged] -> subprocess.run() [sink]",
                }

            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}, clear=True):
                with patch("scanner.call_graph.analyze_chain", side_effect=fake_analyze):
                    output = call_graph.append_cross_file_findings(payload, repo_root)

        self.assertEqual(output["summary"]["cross_file_chains"], 1)
        self.assertEqual(len(output["findings"]), 3)
        self.assertIn("run_support_tool()", output["findings"][-1]["chain"])

    def test_build_user_prompt_includes_domain_summary_and_changed_function_context(self) -> None:
        root_function = call_graph.FunctionDef(
            name="parse_user_request",
            file_path="app/views.py",
            start_line=10,
            end_line=12,
            body="def parse_user_request(user_id):\n    return search_users(user_id)\n",
            language="python",
        )
        callee = call_graph.FunctionDef(
            name="search_users",
            file_path="app/db.py",
            start_line=4,
            end_line=6,
            body="def search_users(user_id):\n    return cursor.execute(user_id)\n",
            language="python",
        )

        prompt = call_graph.build_user_prompt(
            root_function,
            [callee],
            "database query execution",
            2,
            SAMPLE_DOMAIN_CONTEXT,
        )

        self.assertIn("app_domain=healthcare scheduling", prompt)
        self.assertIn('"name": "parse_user_request"', prompt)
        self.assertIn('"name": "search_users"', prompt)
        self.assertIn("database query execution", prompt)

    @staticmethod
    def write_file(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
