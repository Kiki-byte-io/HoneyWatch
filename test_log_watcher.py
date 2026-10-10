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
        self.mock_db.assert_called_once()
        args, kwargs = self.mock_db.call_args
        self.assertIn("INSERT INTO commands", args[0])
        self.assertEqual(args[1], ("test-session-1", "whoami", "2026-10-10 10:00:00"))

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
        self.assertEqual(self.mock_db.call_count, 2)

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
        self.assertEqual(self.mock_db.call_count, 1)

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
        self.assertEqual(self.mock_db.call_count, 2)

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
        self.assertEqual(self.mock_db.call_count, 1)

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
        self.assertEqual(self.mock_db.call_count, 2)

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
        self.assertEqual(self.mock_db.call_count, 2)

    def test_failed_record_retries_before_processing_following_records(self):
        events = [
            {"eventid": "cowrie.command.input", "session": "s1", "input": command}
            for command in ("first", "second", "third")
        ]
        self.write_events([json.dumps(event) for event in events])
        self.mock_db.side_effect = [RuntimeError("temporary failure"), None, None, None]

        self.assertEqual(log_watcher.poll_logs_once(), 0)
        self.assertEqual(self.mock_db.call_count, 1)
        self.assertEqual(self.mock_db.call_args.args[1][1], "first")

        self.assertEqual(log_watcher.poll_logs_once(), 3)
        self.assertEqual(
            [call.args[1][1] for call in self.mock_db.call_args_list],
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
            [call.args[1][1] for call in self.mock_db.call_args_list],
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
        self.mock_db.assert_called_once()


if __name__ == "__main__":
    unittest.main()
