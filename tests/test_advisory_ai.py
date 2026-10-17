import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from advisory_ai import build_advisory_prompt, generate_advisory


class TestAdvisoryPrompt(unittest.TestCase):

    def test_prompt_includes_vulnerability_facts(self):
        prompt = build_advisory_prompt(
            cve_id="CVE-2024-3400",
            description="Example vulnerability description",
            cvss_score=[{"version": "3.1", "score": 10.0}],
            kev_status="LISTED",
            epss_score=0.99,
            priority="P1 - URGENT REVIEW",
            reasons=["Listed in CISA KEV"],
        )

        self.assertIn("CVE-2024-3400", prompt)
        self.assertIn("P1 - URGENT REVIEW", prompt)
        self.assertIn("LISTED", prompt)

    def test_prompt_restricts_unsupported_mitigations(self):
        prompt = build_advisory_prompt(
            cve_id="CVE-2024-3400",
            description="Example description",
            cvss_score=[],
            kev_status="UNKNOWN",
            epss_score=None,
            priority="REVIEW",
            reasons=[],
        )

        self.assertIn("Do not invent", prompt)
        self.assertIn("official vendor security advisory", prompt)
        self.assertIn("does not make the triage decision", prompt)


class TestGenerateAdvisory(unittest.TestCase):

    @patch("advisory_ai.urlopen")
    def test_successful_response(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": "Review the affected version."
        }).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = generate_advisory("Test prompt")

        self.assertEqual(result, "Review the affected version.")
        mock_urlopen.assert_called_once()

    @patch("advisory_ai.urlopen")
    def test_connection_failure_raises_runtime_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")

        with self.assertRaisesRegex(
            RuntimeError,
            "Could not connect to Ollama",
        ):
            generate_advisory("Test prompt")

    @patch("advisory_ai.urlopen")
    def test_empty_response_raises_runtime_error(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": "   "
        }).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_response

        with self.assertRaisesRegex(
            RuntimeError,
            "empty advisory",
        ):
            generate_advisory("Test prompt")


if __name__ == "__main__":
    unittest.main()
