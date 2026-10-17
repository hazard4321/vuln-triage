import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from io import BytesIO
from contextlib import redirect_stdout
from io import StringIO

from cli import (
    is_valid_cve,
    determine_priority,
    generate_markdown_report,
    generate_json_report,
    fetch_cve,
)

class TestCVEValidation(unittest.TestCase):
    """Test CVE identifier format validation."""

    def test_valid_cve(self):
        self.assertTrue(is_valid_cve("CVE-2024-3400"))

    def test_valid_cve_with_long_id(self):
        self.assertTrue(is_valid_cve("CVE-2024-12345"))

    def test_invalid_cve_prefix(self):
        self.assertFalse(is_valid_cve("XYZ-2024-3400"))

    def test_invalid_cve_year(self):
        self.assertFalse(is_valid_cve("CVE-ABC-3400"))

    def test_invalid_cve_missing_digits(self):
        self.assertFalse(is_valid_cve("CVE-2024-ABC"))

    def test_invalid_cve_missing_identifier(self):
        self.assertFalse(is_valid_cve("CVE-2024-"))


class TestPriorityRules(unittest.TestCase):
    """Test the initial rule-based triage priority."""

    def make_cve(self, score=None):
        """Create a minimal CVE record for testing."""
        metrics = []

        if score is not None:
            metrics = [
                {
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": score,
                        "baseSeverity": (
                            "CRITICAL" if score >= 9.0
                            else "HIGH" if score >= 7.0
                            else "MEDIUM"
                        ),
                    },
                    "source": "test@example.com",
                    "type": "Primary",
                }
            ]

        return {
            "id": "CVE-2024-3400",
            "metrics": {"cvssMetricV31": metrics},
        }

    def make_kev(self, status="NOT LISTED"):
        return {"status": status, "details": None}

    def make_epss(self, score=0.1):
        return {"status": "AVAILABLE", "score": score}

    def test_kev_listed_is_urgent(self):
        priority, reasons = determine_priority(
            self.make_cve(5.0),
            self.make_kev("LISTED"),
            self.make_epss(0.1),
        )

        self.assertEqual(priority, "P1 - URGENT REVIEW")
        self.assertTrue(reasons)

    def test_critical_cvss_is_high_priority(self):
        priority, reasons = determine_priority(
            self.make_cve(9.8),
            self.make_kev(),
            self.make_epss(0.1),
        )

        self.assertEqual(priority, "P2 - HIGH PRIORITY")
        self.assertTrue(reasons)

    def test_high_cvss_is_standard_priority(self):
        priority, reasons = determine_priority(
            self.make_cve(8.0),
            self.make_kev(),
            self.make_epss(0.1),
        )

        self.assertEqual(priority, "P3 - STANDARD PRIORITY")
        self.assertTrue(reasons)

    def test_high_epss_triggers_high_priority(self):
        priority, reasons = determine_priority(
            self.make_cve(5.0),
            self.make_kev(),
            self.make_epss(0.8),
        )

        self.assertEqual(priority, "P2 - HIGH PRIORITY")
        self.assertTrue(reasons)

    def test_unknown_kev_requires_review(self):
        priority, reasons = determine_priority(
            self.make_cve(5.0),
            self.make_kev("UNKNOWN"),
            self.make_epss(0.1),
        )

        self.assertEqual(priority, "REVIEW - INSUFFICIENT DATA")
        self.assertTrue(reasons)

    def test_missing_cvss_requires_review(self):
        priority, reasons = determine_priority(
            self.make_cve(),
            self.make_kev(),
            self.make_epss(0.1),
        )

        self.assertEqual(priority, "REVIEW - INSUFFICIENT DATA")
        self.assertTrue(reasons)

    def test_missing_epss_requires_review(self):
        priority, reasons = determine_priority(
            self.make_cve(5.0),
            self.make_kev(),
            {"status": "UNKNOWN", "score": None},
        )

        self.assertEqual(priority, "REVIEW - INSUFFICIENT DATA")
        self.assertTrue(reasons)

    def test_asset_context_is_included_in_reasons(self):
        cve = self.make_cve(score=5.0)
        kev = self.make_kev(status="NOT LISTED")
        epss = self.make_epss(score=0.1)
    
        priority, reasons = determine_priority(
            cve,
            kev,
            epss,
            internet_facing=True,
            asset_criticality="critical",
            affected_version_confirmed=True,
        )
    
        self.assertEqual(priority, "P3 - STANDARD PRIORITY")
        self.assertIn(
            "The affected asset is internet-facing.",
            reasons,
        )
        self.assertIn("Asset criticality: critical.", reasons)
        self.assertIn(
            "The affected software version is confirmed.",
            reasons,
        )

class TestMarkdownReport(unittest.TestCase):
    """Test Markdown report generation."""

    def test_report_contains_expected_information(self):
        cve = {
            "id": "CVE-2024-3400",
            "published": "2024-04-12T00:00:00.000",
            "lastModified": "2024-04-19T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A test vulnerability description.",
                }
            ],
            "metrics": {},
        }

        kev = {
            "status": "NOT LISTED",
            "catalog_version": "test-version",
            "details": None,
        }

        epss = {
            "status": "AVAILABLE",
            "score": 0.25,
            "percentile": 0.80,
            "date": "2026-10-16",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"

            with patch("cli.Path", wraps=Path) as mocked_path:
                mocked_path.side_effect = (
                    lambda value: reports_dir
                    if value == "reports"
                    else Path(value)
                )
                with redirect_stdout(StringIO()):
                    generate_markdown_report(
                        cve,
                        kev,
                        epss,
                        "P3 - STANDARD PRIORITY",
                        ["Test triage reason."],
                    )

            report_path = reports_dir / "CVE-2024-3400.md"
            self.assertTrue(report_path.exists())

            report = report_path.read_text(encoding="utf-8")

            self.assertIn("CVE-2024-3400", report)
            self.assertIn("A test vulnerability description.", report)
            self.assertIn("P3 - STANDARD PRIORITY", report)
            self.assertIn("Test triage reason.", report)
            self.assertIn("0.25000", report)
            self.assertIn("nvd.nist.gov", report)

    def test_report_handles_unavailable_epss(self):
        cve = {
            "id": "CVE-2024-3400",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A test vulnerability description.",
                }
            ],
            "metrics": {},
        }

        kev = {
            "status": "NOT LISTED",
            "catalog_version": None,
            "details": None,
        }

        epss = {
            "status": "UNKNOWN",
            "score": None,
            "percentile": None,
            "date": None,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"

            with patch("cli.Path", wraps=Path) as mocked_path:
                mocked_path.side_effect = (
                    lambda value: reports_dir
                    if value == "reports"
                    else Path(value)
                )
                with redirect_stdout(StringIO()):
                    generate_markdown_report(
                        cve,
                        kev,
                        epss,
                        "REVIEW - INSUFFICIENT DATA",
                        ["EPSS data was unavailable."],
                    )

            report_path = reports_dir / "CVE-2024-3400.md"
            report = report_path.read_text(encoding="utf-8")

            self.assertIn("EPSS data is currently unavailable.", report)
            self.assertIn("REVIEW - INSUFFICIENT DATA", report)
            self.assertNotIn("None%", report)

class TestJSONReport(unittest.TestCase):
    """Test JSON report generation."""

    def make_test_data(self):
        """Create sample vulnerability data without network requests."""
        cve = {
            "id": "CVE-2024-3400",
            "published": "2024-04-12T00:00:00.000",
            "lastModified": "2024-04-19T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A test vulnerability description.",
                }
            ],
            "metrics": {},
        }

        kev = {
            "status": "LISTED",
            "catalog_version": "test-version",
            "details": None,
        }

        epss = {
            "status": "AVAILABLE",
            "score": 0.8,
            "percentile": 0.95,
            "date": "2026-10-16",
        }

        return cve, kev, epss

    def test_json_report_contains_expected_information(self):
        cve, kev, epss = self.make_test_data()

        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"

            with patch("cli.Path", wraps=Path) as mocked_path:
                mocked_path.side_effect = (
                    lambda value: reports_dir
                    if value == "reports"
                    else Path(value)
                )

                with redirect_stdout(StringIO()):
                    generate_json_report(
                        cve,
                        kev,
                        epss,
                        "P1 - URGENT REVIEW",
                        ["Listed in CISA KEV."],
                    )

            report_path = reports_dir / "CVE-2024-3400.json"
            self.assertTrue(report_path.exists())

            report = json.loads(
                report_path.read_text(encoding="utf-8")
            )

            self.assertEqual(report["cve_id"], "CVE-2024-3400")
            self.assertEqual(
                report["triage"]["priority"],
                "P1 - URGENT REVIEW",
            )
            self.assertEqual(report["cisa_kev"]["status"], "LISTED")
            self.assertEqual(report["epss"]["score"], 0.8)
            self.assertEqual(
                report["asset_context"]["criticality"],
                "medium",
            )
            self.assertIn("nvd", report["sources"])

    def test_json_report_is_valid_json(self):
        cve, kev, epss = self.make_test_data()

        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"

            with patch("cli.Path", wraps=Path) as mocked_path:
                mocked_path.side_effect = (
                    lambda value: reports_dir
                    if value == "reports"
                    else Path(value)
                )

                with redirect_stdout(StringIO()):
                    generate_json_report(
                        cve,
                        kev,
                        epss,
                        "P1 - URGENT REVIEW",
                        ["Listed in CISA KEV."],
                    )

            report_path = reports_dir / "CVE-2024-3400.json"
            report_text = report_path.read_text(encoding="utf-8")

            parsed_report = json.loads(report_text)

            self.assertIsInstance(parsed_report, dict)

class TestNVDRequestHandling(unittest.TestCase):
    """Test NVD API error handling without real network requests."""

    @patch("cli.urlopen")
    def test_nvd_rate_limit(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=BytesIO(b"Rate limit reached"),
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "NVD rate limit reached",
        ):
            fetch_cve("CVE-2024-3400")

    @patch("cli.urlopen")
    def test_nvd_connection_failure(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Network is unreachable")

        with self.assertRaisesRegex(
            RuntimeError,
            "Could not connect to NVD",
        ):
            fetch_cve("CVE-2024-3400")

    @patch("cli.urlopen")
    def test_nvd_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Request timed out")

        with self.assertRaisesRegex(
            RuntimeError,
            "request to NVD timed out",
        ):
            fetch_cve("CVE-2024-3400")
if __name__ == "__main__":
    unittest.main()
