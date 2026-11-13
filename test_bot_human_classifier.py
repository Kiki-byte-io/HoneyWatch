import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from bot_human_classifier import get_bot_assessment
from db_client import db


BASE = datetime(2026, 1, 1, 10, 0, 0)


def make_session(index, ip, start_offset):
    start = BASE + timedelta(seconds=start_offset)
    return {
        "session_id": f"session-{index}",
        "src_ip": ip,
        "start_time": start.strftime("%Y-%m-%d %H:%M:%S"),
    }


def make_commands(session_id, inputs, start_offset, gaps):
    current = BASE + timedelta(seconds=start_offset)
    rows = []

    for i, command in enumerate(inputs):
        if i:
            current += timedelta(seconds=gaps[i - 1])

        rows.append({
            "session_id": session_id,
            "input": command,
            "timestamp": current.strftime("%Y-%m-%d %H:%M:%S"),
        })

    return rows


class BotHumanClassifierTests(unittest.TestCase):

    def assess(self, sessions, commands):
        # Mock both database reads: no real database connection.
        with patch.object(
            db, "execute_query", side_effect=[sessions, commands]
        ) as query:
            result = get_bot_assessment()

        self.assertEqual(query.call_count, 2)
        return result

    def test_no_sessions_returns_insufficient_evidence(self):
        result = self.assess([], [])

        self.assertEqual(result["assessment"], "Insufficient Evidence")
        self.assertEqual(result["automation_score"], 0)

    def test_strong_bot_like_behavior(self):
        sessions = [
            make_session(i, "192.0.2.10", i * 20)
            for i in range(3)
        ]

        commands = []
        sequence = ["whoami", "id", "uname -a", "pwd", "exit"]

        for i in range(3):
            commands.extend(make_commands(
                f"session-{i}", sequence, i * 20, [1, 1, 1, 1]
            ))

        result = self.assess(sessions, commands)

        self.assertEqual(result["assessment"], "Likely Automated")
        self.assertEqual(result["automation_score"], 100)
        self.assertEqual(result["component_scores"], {
            "timing": 40,
            "repetition": 40,
            "source": 0,
            "frequency": 20,
        })

    def test_moderately_suspicious_behavior(self):
        sessions = [
            make_session(0, "192.0.2.10", 0),
            make_session(1, "192.0.2.10", 3600),
            make_session(2, "192.0.2.10", 7200),
        ]

        repeated = ["whoami", "id", "uname -a", "ps aux"]
        different = ["pwd", "ls", "history", "exit"]

        commands = []
        commands.extend(make_commands(
            "session-0", repeated, 0, [1, 1, 10]
        ))
        commands.extend(make_commands(
            "session-1", repeated, 3600, [1, 1, 10]
        ))
        commands.extend(make_commands(
            "session-2", different, 7200, [10, 10, 10]
        ))

        result = self.assess(sessions, commands)

        self.assertEqual(result["assessment"], "Possibly Automated")
        self.assertEqual(result["automation_score"], 38)
        self.assertEqual(result["component_scores"], {
            "timing": 18,
            "repetition": 20,
            "source": 0,
            "frequency": 0,
        })

    def test_varied_behavior_has_no_automation_indicators(self):
        sessions = [
            make_session(0, "192.0.2.10", 0),
            make_session(1, "192.0.2.11", 3600),
            make_session(2, "192.0.2.12", 7200),
        ]

        commands = []
        commands.extend(make_commands(
            "session-0",
            ["whoami", "id", "uname -a", "ps aux"],
            0,
            [10, 10, 10],
        ))
        commands.extend(make_commands(
            "session-1",
            ["pwd", "ls -la", "cat /etc/passwd"],
            3600,
            [10, 10],
        ))
        commands.extend(make_commands(
            "session-2",
            ["netstat", "history", "exit"],
            7200,
            [10, 10],
        ))

        result = self.assess(sessions, commands)

        self.assertEqual(result["automation_score"], 0)
        self.assertEqual(result["assessment"], "Insufficient Evidence")

    def test_high_score_is_not_enough_without_minimum_evidence(self):
        sessions = [
            make_session(0, "192.0.2.10", 0),
            make_session(1, "192.0.2.10", 20),
        ]

        commands = []
        sequence = ["whoami", "id", "uname -a", "pwd", "exit"]

        for i in range(2):
            commands.extend(make_commands(
                f"session-{i}", sequence, i * 20, [1, 1, 1, 1]
            ))

        result = self.assess(sessions, commands)

        self.assertGreaterEqual(result["automation_score"], 60)
        self.assertEqual(result["assessment"], "Insufficient Evidence")

    def test_rapid_sessions_from_same_ip_without_repeated_commands(self):
        sessions = [
            make_session(0, "192.0.2.10", 0),
            make_session(1, "192.0.2.10", 20),
            make_session(2, "192.0.2.10", 40),
        ]

        sequences = [
            ["whoami", "id", "uname -a", "ps aux"],
            ["pwd", "ls -la", "cat /etc/passwd", "history"],
            ["netstat", "hostname", "ip a", "exit"],
        ]

        commands = []
        for i, sequence in enumerate(sequences):
            commands.extend(make_commands(
                f"session-{i}", sequence, i * 20, [10, 10, 10]
            ))

        result = self.assess(sessions, commands)

        self.assertEqual(result["automation_score"], 20)
        self.assertEqual(result["assessment"], "Insufficient Evidence")
        self.assertEqual(result["component_scores"], {
            "timing": 0,
            "repetition": 0,
            "source": 0,
            "frequency": 20,
        })

    def test_repeated_source_ip_is_context_only_not_scored(self):
        sessions = [
            make_session(0, "192.0.2.10", 0),
            make_session(1, "192.0.2.10", 3600),
            make_session(2, "192.0.2.10", 7200),
        ]

        sequences = [
            ["whoami", "id", "uname -a", "ps aux"],
            ["pwd", "ls -la", "cat /etc/passwd", "history"],
            ["netstat", "hostname", "ip a", "exit"],
        ]

        commands = []
        for i, sequence in enumerate(sequences):
            commands.extend(make_commands(
                f"session-{i}", sequence, i * 3600, [10, 10, 10]
            ))

        result = self.assess(sessions, commands)

        self.assertEqual(result["automation_score"], 0)
        self.assertEqual(result["assessment"], "Insufficient Evidence")
        self.assertEqual(result["component_scores"]["source"], 0)
        self.assertEqual(result["behavioral_features"]["repeated_ips"], 1)

    def test_repeated_manual_checklist_alone_does_not_trigger_automation(self):
        sessions = [
            make_session(i, "192.0.2.10", i * 3600)
            for i in range(3)
        ]

        commands = []
        checklist = ["whoami", "id", "uname -a", "pwd", "exit"]

        for i in range(3):
            commands.extend(make_commands(
                f"session-{i}", checklist, i * 3600,
                [10, 10, 10, 10]
            ))

        result = self.assess(sessions, commands)

        self.assertEqual(result["automation_score"], 40)
        self.assertEqual(result["assessment"], "Insufficient Evidence")
        self.assertEqual(result["component_scores"], {
            "timing": 0,
            "repetition": 40,
            "source": 0,
            "frequency": 0,
        })

if __name__ == "__main__":
    unittest.main()
