import unittest
from unittest.mock import patch

from scanner import ai_provider


class AiProviderTests(unittest.TestCase):
    def test_auto_provider_prefers_anthropic_when_both_keys_exist(self) -> None:
        with patch.dict(
            "os.environ",
            {"ANTHROPIC_API_KEY": "anthropic-key", "OPENAI_API_KEY": "openai-key"},
            clear=True,
        ):
            provider = ai_provider.select_provider()

        self.assertEqual(provider["name"], "anthropic")
        self.assertEqual(provider["api_key"], "anthropic-key")
        self.assertEqual(provider["model"], ai_provider.DEFAULT_ANTHROPIC_MODEL)

    def test_forced_openai_provider_uses_openai_even_when_anthropic_key_exists(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AI_PROVIDER": "openai",
                "ANTHROPIC_API_KEY": "anthropic-key",
                "OPENAI_API_KEY": "openai-key",
                "OPENAI_MODEL": "gpt-4o-mini",
            },
            clear=True,
        ):
            provider = ai_provider.select_provider()

        self.assertEqual(provider["name"], "openai")
        self.assertEqual(provider["api_key"], "openai-key")
        self.assertEqual(provider["model"], "gpt-4o-mini")

    def test_forced_provider_without_matching_key_skips_generation(self) -> None:
        with patch.dict(
            "os.environ",
            {"AI_PROVIDER": "anthropic", "OPENAI_API_KEY": "openai-key"},
            clear=True,
        ):
            provider = ai_provider.select_provider()

        self.assertIsNone(provider)

    def test_ai_provider_none_disables_generation(self) -> None:
        with patch.dict(
            "os.environ",
            {"AI_PROVIDER": "none", "ANTHROPIC_API_KEY": "anthropic-key"},
            clear=True,
        ):
            provider = ai_provider.select_provider()

        self.assertIsNone(provider)


if __name__ == "__main__":
    unittest.main()
