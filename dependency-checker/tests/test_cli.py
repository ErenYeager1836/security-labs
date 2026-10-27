"""
Integration and CLI unit tests for dependency-checker.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dependency_checker.cli import main
from dependency_checker.models import (
    DependencyAudit,
    Ecosystem,
    PackageDependency,
    Severity,
    Vulnerability,
)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("sys.stdout")
    @patch("dependency_checker.osv.OSVClient.query_batch")
    def test_cli_clean_manifest_exits_zero(self, mock_batch, mock_stdout):
        req_file = self.base_path / "requirements.txt"
        req_file.write_text("clean-package==1.0.0\n", encoding="utf-8")

        mock_dep = PackageDependency(
            name="clean-package",
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            file_path=str(req_file),
        )
        mock_batch.return_value = [DependencyAudit(dependency=mock_dep, vulnerabilities=[])]

        exit_code = main([str(req_file), "--fail-on", "HIGH"])
        self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    @patch("dependency_checker.osv.OSVClient.query_batch")
    def test_cli_vulnerable_manifest_exits_one(self, mock_batch, mock_stdout):
        req_file = self.base_path / "requirements.txt"
        req_file.write_text("vulnerable-pkg==0.1.0\n", encoding="utf-8")

        mock_dep = PackageDependency(
            name="vulnerable-pkg",
            version="0.1.0",
            ecosystem=Ecosystem.PYPI,
            file_path=str(req_file),
        )
        mock_vuln = Vulnerability(
            id="GHSA-test",
            summary="Test RCE",
            details="Details",
            severity=Severity.HIGH,
        )
        mock_batch.return_value = [DependencyAudit(dependency=mock_dep, vulnerabilities=[mock_vuln])]

        exit_code = main([str(req_file), "--fail-on", "HIGH"])
        self.assertEqual(exit_code, 1)

    @patch("sys.stdout")
    @patch("dependency_checker.osv.OSVClient.query_batch")
    def test_cli_markdown_and_json_output(self, mock_batch, mock_stdout):
        req_file = self.base_path / "requirements.txt"
        req_file.write_text("foo==1.0\n", encoding="utf-8")
        out_file = self.base_path / "report.md"

        mock_batch.return_value = []
        exit_code = main([str(req_file), "-f", "markdown", "-o", str(out_file), "--fail-on", "NEVER"])

        self.assertEqual(exit_code, 0)
        self.assertTrue(out_file.exists())
        self.assertIn("# Software Supply Chain Vulnerability Audit Report", out_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
