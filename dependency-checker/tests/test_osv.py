"""
Unit tests for OSVClient and vulnerability parsing.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from dependency_checker.models import Ecosystem, PackageDependency, Severity
from dependency_checker.osv import OSVClient


class TestOSVClient(unittest.TestCase):
    def setUp(self):
        self.client = OSVClient()
        self.sample_osv_vuln = {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "summary": "Log4j Remote Code Execution",
            "details": "JNDI lookup vulnerability in Log4j2 allows remote code execution.",
            "aliases": ["CVE-2021-44228"],
            "database_specific": {"severity": "CRITICAL"},
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.0.0"}, {"fixed": "2.15.0"}],
                        }
                    ]
                }
            ],
            "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
        }

    def test_parse_vulnerability_fields(self):
        vuln = self.client._parse_vulnerability(self.sample_osv_vuln)

        self.assertEqual(vuln.id, "GHSA-jfh8-c2jp-5v3q")
        self.assertEqual(vuln.display_cve, "CVE-2021-44228")
        self.assertEqual(vuln.severity, Severity.CRITICAL)
        self.assertIn("2.15.0", vuln.fixed_versions)
        self.assertEqual(len(vuln.references), 1)

    @patch("urllib.request.urlopen")
    def test_query_package_mocked(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"vulns": [self.sample_osv_vuln]}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        dep = PackageDependency(
            name="org.apache.logging.log4j:log4j-core",
            version="2.14.1",
            ecosystem=Ecosystem.MAVEN,
            file_path="pom.xml",
        )

        audit = self.client.query_package(dep)
        self.assertTrue(audit.is_vulnerable)
        self.assertEqual(audit.highest_severity, Severity.CRITICAL)
        self.assertEqual(len(audit.vulnerabilities), 1)
        self.assertEqual(audit.vulnerabilities[0].display_cve, "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
