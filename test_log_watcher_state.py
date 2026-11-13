import json
import os
import tempfile
import unittest
from unittest.mock import patch

import log_watcher


def write_events(path, events, mode="w"):
    with open(path, mode) as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def command(session, text, second):
    return {
        "eventid": "cowrie.command.input",
        "session": session,
        "input": text,
        "timestamp": f"2026-11-14T01:00:{second:02d}.000000Z",
    }


class WatcherStatePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log_path = os.path.join(self.tmp.name, "cowrie.json")
        self.state_path = os.path.join(self.tmp.name, "state", "watcher_state.json")

        log_watcher.FILE_OFFSETS.clear()
        self.addCleanup(log_watcher.FILE_OFFSETS.clear)

        for name, value in (("LOG_GLOB", self.log_path), ("LOCAL_LOG_GLOB", self.log_path)):
            p = patch.object(log_watcher, name, value)
            p.start()
            self.addCleanup(p.stop)

        db_patch = patch.object(log_watcher.db, "execute_query")
        self.mock_db = db_patch.start()
        self.addCleanup(db_patch.stop)

        write_events(self.log_path, [command("s1", "whoami", 1), command("s1", "id", 2)])

    def restart(self):
        """Simulate a new watcher process: in-memory offsets are lost."""
        log_watcher.FILE_OFFSETS.clear()

    def command_inserts(self):
        return sum(
            1 for c in self.mock_db.call_args_list if "INSERT INTO commands" in c.args[0]
        )

    def test_restart_does_not_reingest_processed_lines(self):
        self.assertEqual(log_watcher.run_single_poll(self.state_path), 2)
        self.restart()
        self.assertEqual(log_watcher.run_single_poll(self.state_path), 0)
        self.assertEqual(self.command_inserts(), 2)

    def test_lines_appended_after_restart_are_ingested(self):
        log_watcher.run_single_poll(self.state_path)
        self.restart()
        write_events(self.log_path, [command("s1", "uname -a", 3)], mode="a")
        self.assertEqual(log_watcher.run_single_poll(self.state_path), 1)
        self.assertEqual(self.command_inserts(), 3)

    def test_state_for_a_different_database_is_ignored(self):
        """Offsets recorded against the test DB must never make the watcher
        skip logs that the live DB has not received (and vice versa)."""
        with patch.object(log_watcher, "_database_identity", return_value="mysql:honeywatch_test_x"):
            log_watcher.run_single_poll(self.state_path)
        self.restart()
        with patch.object(log_watcher, "_database_identity", return_value="mysql:cowrie_logs"):
            self.assertEqual(log_watcher.run_single_poll(self.state_path), 2)

    def test_corrupt_state_file_starts_fresh_without_crashing(self):
        os.makedirs(os.path.dirname(self.state_path))
        with open(self.state_path, "w") as f:
            f.write("{not json")
        self.assertEqual(log_watcher.run_single_poll(self.state_path), 2)

    def test_rewritten_file_with_reused_identity_is_read_from_start(self):
        log_watcher.run_single_poll(self.state_path)
        self.restart()
        # Same path (and on most filesystems the same inode), new contents
        # that have already grown past the saved offset.
        write_events(self.log_path, [
            command("s2", "ls -la", 4), command("s2", "ps aux", 5), command("s2", "exit", 6),
        ])
        self.assertEqual(log_watcher.run_single_poll(self.state_path), 3)

    def test_state_file_is_written(self):
        log_watcher.run_single_poll(self.state_path)
        with open(self.state_path) as f:
            saved = json.load(f)
        self.assertIn("database", saved)
        self.assertEqual(len(saved["offsets"]), 1)


if __name__ == "__main__":
    unittest.main()
