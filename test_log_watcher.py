import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import log_watcher
from db_client import DatabaseClient


class LogWatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.log_path = os.path.join(self.temp_dir.name, "cowrie.json")
        log_watcher.FILE_OFFSETS.clear()

        self.db_patcher = patch.object(log_watcher.db, "execute_query")
        self.mock_db = self.db_patcher.start()
        self.addCleanup(self.db_patcher.stop)

        self.glob_patcher = patch.object(
            log_watcher.glob, "glob", return_value=[self.log_path]
        )
        self.mock_glob = self.glob_patcher.start()
        self.addCleanup(self.glob_patcher.stop)

    def write_events(self, lines):
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def calls_for_insert(self, table):
        return [
            call for call in self.mock_db.call_args_list
            if f"INSERT INTO {table}" in call.args[0]
        ]

    def assert_placeholder_upsert(self, call, session_id):
        query, params = call.args
        self.assertIn("INSERT INTO sessions", query)
        self.assertIn("VALUES (%s, NULL, NULL, NULL, NULL, NULL, NULL)", query)
        self.assertIn("ON DUPLICATE KEY UPDATE", query)
        self.assertEqual(params, (session_id,))

    def test_command_event_is_inserted(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "whoami",
        }
        self.write_events([json.dumps(event)])

        count = log_watcher.poll_logs_once()

        self.assertEqual(count, 1)
        self.assertEqual(self.mock_db.call_count, 2)
        self.assert_placeholder_upsert(self.mock_db.call_args_list[0], "test-session-1")
        command_call = self.calls_for_insert("commands")[0]
        self.assertEqual(command_call.args[1], ("test-session-1", "whoami", "2026-10-10 10:00:00"))

    def test_login_without_connect_creates_placeholder_before_login(self):
        event = {
            "eventid": "cowrie.login.failed",
            "session": "login-only-session",
            "username": "root",
            "password": "guess",
            "timestamp": "2026-10-10T10:00:00Z",
        }
        self.write_events([json.dumps(event)])

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(self.mock_db.call_count, 2)
        self.assert_placeholder_upsert(self.mock_db.call_args_list[0], "login-only-session")
        login_call = self.calls_for_insert("login_attempts")[0]
        self.assertEqual(
            login_call.args[1],
            ("login-only-session", "root", "guess", 0, "2026-10-10 10:00:00"),
        )

    def test_command_without_connect_creates_placeholder_before_command(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "command-only-session",
            "input": "id",
        }
        self.write_events([json.dumps(event)])

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(self.mock_db.call_count, 2)
        self.assert_placeholder_upsert(self.mock_db.call_args_list[0], "command-only-session")
        command_call = self.calls_for_insert("commands")[0]
        self.assertEqual(command_call.args[1], ("command-only-session", "id", None))

    def test_later_connect_uses_upsert_to_enrich_placeholder(self):
        child = {
            "eventid": "cowrie.command.input",
            "session": "late-connect-session",
            "input": "whoami",
        }
        self.write_events([json.dumps(child)])
        self.assertEqual(log_watcher.poll_logs_once(), 1)

        connect = {
            "eventid": "cowrie.session.connect",
            "session": "late-connect-session",
            "src_ip": "192.0.2.12",
            "src_port": 43000,
            "dst_port": 22,
            "timestamp": "2026-10-10T10:01:00Z",
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(connect) + "\n")

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        session_calls = self.calls_for_insert("sessions")
        self.assertEqual(len(session_calls), 2)
        self.assert_placeholder_upsert(session_calls[0], "late-connect-session")
        connect_query, connect_params = session_calls[1].args
        self.assertIn(
            "ON DUPLICATE KEY UPDATE src_ip=VALUES(src_ip), src_port=VALUES(src_port), "
            "dst_port=VALUES(dst_port), start_time=VALUES(start_time)",
            connect_query,
        )
        self.assertEqual(
            connect_params,
            ("late-connect-session", "192.0.2.12", 43000, 22, "2026-10-10 10:01:00", None, None),
        )

    def test_connect_then_child_still_writes_in_order(self):
        connect = {
            "eventid": "cowrie.session.connect",
            "session": "normal-order-session",
            "src_ip": "192.0.2.13",
            "src_port": 43001,
            "dst_port": 22,
            "timestamp": "2026-10-10T10:00:00Z",
        }
        command = {
            "eventid": "cowrie.command.input",
            "session": "normal-order-session",
            "input": "whoami",
        }
        self.write_events([json.dumps(connect), json.dumps(command)])

        self.assertEqual(log_watcher.poll_logs_once(), 2)
        self.assertEqual(self.mock_db.call_count, 3)
        self.assertIn(
            "ON DUPLICATE KEY UPDATE src_ip=VALUES(src_ip), src_port=VALUES(src_port), "
            "dst_port=VALUES(dst_port), start_time=VALUES(start_time)",
            self.mock_db.call_args_list[0].args[0],
        )
        self.assert_placeholder_upsert(self.mock_db.call_args_list[1], "normal-order-session")
        self.assertIn("INSERT INTO commands", self.mock_db.call_args_list[2].args[0])

    def test_identical_complete_event_lines_are_both_processed(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "id",
        }
        line = json.dumps(event)
        self.write_events([line, line])

        count = log_watcher.poll_logs_once()

        self.assertEqual(count, 2)
        self.assertEqual(self.mock_db.call_count, 4)
        self.assertEqual(len(self.calls_for_insert("commands")), 2)

    def test_polling_twice_without_new_data_does_not_reprocess_lines(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "whoami",
        }
        self.write_events([json.dumps(event)])

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(log_watcher.poll_logs_once(), 0)
        self.assertEqual(self.mock_db.call_count, 2)

    def test_newly_appended_complete_line_is_processed(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "whoami",
        }
        self.write_events([json.dumps(event)])
        self.assertEqual(log_watcher.poll_logs_once(), 1)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({**event, "input": "id"}) + "\n")

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(self.mock_db.call_count, 4)

    def test_incomplete_final_line_is_processed_after_completion(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "whoami",
        }
        line = json.dumps(event)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(line[:len(line) // 2])

        self.assertEqual(log_watcher.poll_logs_once(), 0)
        self.assertEqual(self.mock_db.call_count, 0)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line[len(line) // 2:] + "\n")

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(self.mock_db.call_count, 2)

    def test_truncated_file_rewritten_larger_is_read_from_start_again(self):
        first = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "whoami",
        }
        self.write_events([json.dumps(first)])
        self.assertEqual(log_watcher.poll_logs_once(), 1)

        second = {**first, "input": "hostname --long replacement payload"}
        self.write_events([json.dumps(second)])
        self.assertEqual(log_watcher.poll_logs_once(), 1)

        command_calls = self.calls_for_insert("commands")
        self.assertEqual(
            [call.args[1] for call in command_calls],
            [
                ("test-session-1", "whoami", "2026-10-10 10:00:00"),
                (
                    "test-session-1",
                    "hostname --long replacement payload",
                    "2026-10-10 10:00:00",
                ),
            ],
        )

        placeholder_calls = self.calls_for_insert("sessions")
        self.assertEqual(len(placeholder_calls), 2)
        for call in placeholder_calls:
            self.assert_placeholder_upsert(call, "test-session-1")

    def test_database_error_does_not_advance_file_position(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "timestamp": "2026-10-10T10:00:00Z",
            "input": "whoami",
        }
        self.write_events([json.dumps(event)])
        self.mock_db.side_effect = RuntimeError("database unavailable")

        self.assertEqual(log_watcher.poll_logs_once(), 0)
        self.assertEqual(self.mock_db.call_count, 1)

        self.mock_db.side_effect = None
        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(self.mock_db.call_count, 3)
        self.assertEqual(len(self.calls_for_insert("commands")), 1)

    def test_failed_record_retries_before_processing_following_records(self):
        events = [
            {"eventid": "cowrie.command.input", "session": "s1", "input": command}
            for command in ("first", "second", "third")
        ]
        self.write_events([json.dumps(event) for event in events])
        failed_command = False

        def fail_first_command(query, *args, **kwargs):
            nonlocal failed_command
            if "INSERT INTO commands" in query and not failed_command:
                failed_command = True
                raise RuntimeError("temporary failure")

        self.mock_db.side_effect = fail_first_command

        self.assertEqual(log_watcher.poll_logs_once(), 0)
        self.assertEqual(self.mock_db.call_count, 2)
        self.assertEqual(self.calls_for_insert("commands")[0].args[1][1], "first")

        self.assertEqual(log_watcher.poll_logs_once(), 3)
        self.assertEqual(
            [call.args[1][1] for call in self.calls_for_insert("commands")],
            ["first", "first", "second", "third"],
        )

    def test_renamed_rotation_does_not_replay_consumed_events(self):
        original = {
            "eventid": "cowrie.command.input",
            "session": "test-session-1",
            "input": "already-consumed",
        }
        self.write_events([json.dumps(original)])
        self.assertEqual(log_watcher.poll_logs_once(), 1)

        rotated_path = self.log_path + ".1"
        os.replace(self.log_path, rotated_path)
        replacement = {**original, "input": "new-event"}
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(replacement) + "\n")
        self.mock_glob.return_value = [self.log_path, rotated_path]

        self.assertEqual(log_watcher.poll_logs_once(), 1)
        self.assertEqual(
            [call.args[1][1] for call in self.calls_for_insert("commands")],
            ["already-consumed", "new-event"],
        )

    def test_database_client_only_reraises_when_requested(self):
        client = DatabaseClient()
        connection = MagicMock()
        cursor = connection.cursor.return_value
        cursor.execute.side_effect = RuntimeError("query failed")

        with patch.object(client, "get_connection", return_value=(connection, False)):
            self.assertIsNone(client.execute_query("SELECT 1", fetch="one"))
            with self.assertRaisesRegex(RuntimeError, "query failed"):
                client.execute_query("SELECT 1", fetch="one", raise_on_error=True)

        self.assertEqual(cursor.execute.call_count, 2)
        self.assertEqual(connection.close.call_count, 2)

    def test_malformed_json_does_not_crash_polling(self):
        event = {
            "eventid": "cowrie.command.input",
            "session": "test-session-2",
            "timestamp": "2026-10-10T10:01:00Z",
            "input": "uname -a",
        }
        self.write_events(["{not valid json", json.dumps(event)])

        count = log_watcher.poll_logs_once()

        self.assertEqual(count, 1)
        self.assertEqual(self.mock_db.call_count, 2)
        self.assertEqual(len(self.calls_for_insert("commands")), 1)


if __name__ == "__main__":
    unittest.main()
