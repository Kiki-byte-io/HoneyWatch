import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import report_generator
from report_generator import fetch_report_data, generate_pdf_report


def fake_execute_query(query, params=None, fetch="all", raise_on_error=False):
    if fetch == "one":
        return {"count": 0}
    return []


def make_report_data(**overrides):
    data = {
        "range_filter": "all",
        "range_label": "All Available Telemetry Data",
        "tot_sessions": 1,
        "tot_logins": 2,
        "tot_commands": 3,
        "tot_events": 6,
        "unique_ips": 1,
        "success_logins": 1,
        "failed_logins": 1,
        "top_ips": [{"src_ip": "203.0.113.10", "session_count": 1, "last_seen": "2026-11-14"}],
        "recent_sessions": [],
        "top_usernames": [],
        "top_commands": [],
        "evidence": None,
        "summary_obj": {"summary": "A plain grounded summary."},
        "mitigations": [],
        "bot_info": {
            "assessment": "Insufficient Evidence",
            "automation_score": 0,
            "behavioral_features": {},
            "indicators": [],
        },
        "generated_at": "2026-11-14 10:00:00 UTC",
        "report_date_str": "2026-11-14",
        "intelligence_scope_note": "note",
    }
    data.update(overrides)
    return data


class FetchReportDataTests(unittest.TestCase):
    def setUp(self):
        patches = [
            patch.object(report_generator.db, "execute_query", side_effect=fake_execute_query),
            patch.object(report_generator, "get_evidence", return_value=None),
            patch.object(
                report_generator,
                "generate_summary",
                return_value={"summary": "s", "assessment": "a"},
            ),
            patch.object(report_generator, "generate_mitigations", return_value=[]),
            patch.object(
                report_generator,
                "get_bot_assessment",
                return_value={
                    "assessment": "Insufficient Evidence",
                    "automation_score": 0,
                    "behavioral_features": {},
                    "indicators": [],
                },
            ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_generated_at_is_actually_utc(self):
        """The timestamp is labelled UTC, so it must BE UTC time,
        not local time with a UTC label."""
        data = fetch_report_data("all")
        stamp = datetime.strptime(
            data["generated_at"], "%Y-%m-%d %H:%M:%S UTC"
        ).replace(tzinfo=timezone.utc)
        drift = abs((datetime.now(timezone.utc) - stamp).total_seconds())
        self.assertLess(drift, 600, f"generated_at drifts {drift}s from real UTC")

    def test_intelligence_sections_declare_their_scope(self):
        """Sections built from the latest session / all telemetry must
        say so, because the headline range filter does not apply to them."""
        data = fetch_report_data("24h")
        note = data.get("intelligence_scope_note", "")
        self.assertIn("independent of the selected report range", note)

    def test_range_label_mapping(self):
        self.assertEqual(fetch_report_data("7d")["range_label"], "Last 7 Days")


class GeneratePdfTests(unittest.TestCase):
    def _pdf_for(self, data):
        with patch.object(report_generator, "fetch_report_data", return_value=data):
            return generate_pdf_report("all")

    def test_generates_valid_pdf_bytes(self):
        pdf = self._pdf_for(make_report_data())
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_markup_in_untrusted_summary_does_not_break_the_report(self):
        """Attacker-typed commands flow into the AI summary text; markup
        characters in it must not crash or style the PDF."""
        hostile = 'echo <font color="red"> & <b>unclosed <script>'
        pdf = self._pdf_for(make_report_data(summary_obj={"summary": hostile}))
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_empty_telemetry_report_renders(self):
        data = make_report_data(
            tot_sessions=0, tot_logins=0, tot_commands=0, tot_events=0,
            unique_ips=0, success_logins=0, failed_logins=0, top_ips=[],
        )
        pdf = self._pdf_for(data)
        self.assertTrue(pdf.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
