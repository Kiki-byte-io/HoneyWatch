import csv
import io
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(__file__), "dashboard"))
os.environ.setdefault("HONEYWATCH_ENABLE_LOG_WATCHER", "0")

import app as dashboard_module

BOT_STUB = {
    "assessment": "Insufficient Evidence",
    "automation_score": 0,
    "behavioral_features": {},
    "indicators": [],
}


class DashboardSecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.client = dashboard_module.app.test_client()
        bot = patch.object(dashboard_module, "get_bot_assessment", return_value=BOT_STUB)
        bot.start()
        self.addCleanup(bot.stop)


class CsvExportInjectionTests(DashboardSecurityTestCase):
    def _export_rows(self, username):
        row = {
            "session_id": "s1", "src_ip": "203.0.113.5", "dst_port": 2222,
            "start_time": "2026-11-14 01:00:00", "end_time": None,
            "duration_ms": None, "username": username, "success": 0,
        }
        with patch.object(dashboard_module.db, "execute_query", return_value=[row]):
            response = self.client.get("/api/export/csv")
        return list(csv.reader(io.StringIO(response.data.decode("utf-8"))))

    def test_formula_prefixed_username_is_neutralised(self):
        """Attackers choose the username they try on the honeypot; a value
        like =HYPERLINK(...) must not become a live spreadsheet formula."""
        for payload in ("=HYPERLINK(\"http://evil\")", "+1+1", "-2+3", "@SUM(A1)"):
            with self.subTest(payload=payload):
                rows = self._export_rows(payload)
                self.assertEqual(rows[1][6], "'" + payload)

    def test_ordinary_username_is_unchanged(self):
        rows = self._export_rows("root")
        self.assertEqual(rows[1][6], "root")


class ErrorDisclosureTests(DashboardSecurityTestCase):
    def test_pdf_failure_does_not_leak_exception_details(self):
        secret_detail = "Access denied for user 'cowrie_app'@'localhost' path=/home/x"
        with patch.object(
            dashboard_module, "generate_pdf_report", side_effect=RuntimeError(secret_detail)
        ):
            response = self.client.get("/api/report/pdf")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"cowrie_app", response.data)
        self.assertNotIn(b"/home/x", response.data)

    def test_summary_db_failure_reports_unhealthy_without_details(self):
        """A database outage must not be reported as a healthy connection,
        and the raw driver error must not reach the browser."""
        def failing_query(query, params=None, fetch="all", raise_on_error=False):
            if raise_on_error:
                raise RuntimeError("Access denied for user 'cowrie_app'@'localhost'")
            return None

        with patch.object(dashboard_module.db, "execute_query", side_effect=failing_query):
            response = self.client.get("/api/dashboard/summary")
        data = json.loads(response.data)
        self.assertFalse(data["db_connected"])
        self.assertEqual(data["status"], "error")
        self.assertNotIn("cowrie_app", json.dumps(data))


class PaginationValidationTests(DashboardSecurityTestCase):
    def setUp(self):
        super().setUp()
        q = patch.object(dashboard_module.db, "execute_query", return_value=[])
        q.start()
        self.addCleanup(q.stop)

    def test_non_integer_paging_falls_back_to_defaults(self):
        for url in ("/api/attacks?page=abc&limit=xyz", "/api/sessions?page=abc&limit=xyz"):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)

    def test_paging_values_are_clamped(self):
        response = self.client.get("/api/attacks?page=-5&limit=100000")
        data = json.loads(response.data)
        self.assertEqual(data["page"], 1)
        self.assertLessEqual(data["limit"], 200)

        response = self.client.get("/api/sessions?page=0&limit=0")
        data = json.loads(response.data)
        self.assertEqual(data["page"], 1)
        self.assertGreaterEqual(data["limit"], 1)


class HostValidationTests(DashboardSecurityTestCase):
    def test_unexpected_host_header_is_rejected(self):
        """Protects the localhost-only dashboard against DNS rebinding."""
        response = self.client.get("/", headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 400)

    def test_localhost_hosts_are_accepted(self):
        for host in ("127.0.0.1:5000", "localhost:5000", "localhost"):
            with self.subTest(host=host):
                response = self.client.get("/", headers={"Host": host})
                self.assertEqual(response.status_code, 200)


class SecurityHeaderTests(DashboardSecurityTestCase):
    def test_baseline_security_headers_are_set(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")


if __name__ == "__main__":
    unittest.main()
