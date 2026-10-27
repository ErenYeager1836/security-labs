"""
Automated exploit and remediation tests for vuln-app-lab.
Verifies that:
1. Exploit payloads successfully demonstrate vulnerabilities on /vulnerable endpoints.
2. The exact same exploit payloads are neutralized on /fixed endpoints.
"""

import unittest
from app import create_app
from db import reset_db


class TestVulnAppLab(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_db()

    # -------------------------------------------------------------------------
    # 1. SQL Injection Tests
    # -------------------------------------------------------------------------
    def test_sqli_vulnerable_exploit_extracts_all_users(self):
        # Exploit payload: ' OR '1'='1
        res = self.client.get("/api/sqli/vulnerable?username=%27+OR+%271%27%3D%271")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        # All 3 users (admin, alice, bob) returned
        self.assertGreaterEqual(data["results_count"], 3)
        usernames = [u["username"] for u in data["users"]]
        self.assertIn("admin", usernames)
        self.assertIn("alice", usernames)

    def test_sqli_fixed_neutralizes_exploit(self):
        # Exact same exploit payload against parameterized endpoint
        res = self.client.get("/api/sqli/fixed?username=%27+OR+%271%27%3D%271")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        # 0 users returned because no user has username literal "' OR '1'='1"
        self.assertEqual(data["results_count"], 0)

    def test_sqli_fixed_normal_lookup_works(self):
        res = self.client.get("/api/sqli/fixed?username=alice")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["results_count"], 1)
        self.assertEqual(data["users"][0]["username"], "alice")

    # -------------------------------------------------------------------------
    # 2. XSS Tests
    # -------------------------------------------------------------------------
    def test_xss_vulnerable_reflects_raw_script_tags(self):
        payload = "<script>alert('XSS')</script>"
        res = self.client.get(f"/api/xss/vulnerable?q={payload}")
        self.assertEqual(res.status_code, 200)
        # Raw unescaped script tag present in HTML response
        self.assertIn(b"<script>alert('XSS')</script>", res.data)

    def test_xss_fixed_escapes_html_and_sets_csp(self):
        payload = "<script>alert('XSS')</script>"
        res = self.client.get(f"/api/xss/fixed?q={payload}")
        self.assertEqual(res.status_code, 200)
        # Encoded as HTML entities
        self.assertIn(b"&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;", res.data)
        self.assertNotIn(b"<script>alert('XSS')</script>", res.data)
        # CSP header present
        self.assertIn("Content-Security-Policy", res.headers)
        self.assertIn("default-src 'self'", res.headers["Content-Security-Policy"])

    # -------------------------------------------------------------------------
    # 3. IDOR / Object Authorization Tests
    # -------------------------------------------------------------------------
    def test_idor_vulnerable_allows_reading_other_users_private_notes(self):
        # Alice requests note 3 (Bob's private note)
        res = self.client.get("/api/idor/vulnerable/notes/3")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["note"]["owner_id"], 3)
        self.assertTrue(data["idor_violation_occurred"])
        self.assertIn("wallet recovery", data["note"]["content"])

    def test_idor_fixed_blocks_unauthorized_access(self):
        # Alice requests note 3 (Bob's private note) on fixed endpoint -> 403 Forbidden
        res = self.client.get("/api/idor/fixed/notes/3")
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertTrue(data["authorization_enforced"])
        self.assertIn("Forbidden", data["error"])

    def test_idor_fixed_allows_access_to_owned_notes(self):
        # Alice requests note 2 (her own private note)
        res = self.client.get("/api/idor/fixed/notes/2")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["note"]["owner_id"], 2)

    # -------------------------------------------------------------------------
    # 4. SSRF Tests
    # -------------------------------------------------------------------------
    def test_ssrf_fixed_blocks_loopback_and_metadata_targets(self):
        # Loopback URL
        res = self.client.get("/api/ssrf/fixed?url=http://127.0.0.1:5000/api/ssrf/internal-admin-status")
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertTrue(data["blocked"])

        # Cloud metadata IP
        res_meta = self.client.get("/api/ssrf/fixed?url=http://169.254.169.254/latest/meta-data/")
        self.assertEqual(res_meta.status_code, 403)

        # File scheme
        res_file = self.client.get("/api/ssrf/fixed?url=file:///etc/passwd")
        self.assertEqual(res_file.status_code, 403)


if __name__ == "__main__":
    unittest.main()
