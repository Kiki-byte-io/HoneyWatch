import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import db_client

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_isolated(code, env_overrides):
    """Import db_client in a fresh interpreter so import-time defaults are real."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("COWRIE_")}
    env.update(env_overrides)
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_DIR, env=env, capture_output=True, text=True, timeout=60,
    )
    return result.stdout.strip()


class DatabaseTypeDefaultTests(unittest.TestCase):
    def test_default_database_type_is_mysql(self):
        """SQLite must be an explicit opt-in, not a silent fallback."""
        out = run_isolated("import db_client; print(db_client.DB_TYPE)", {})
        self.assertEqual(out, "mysql")

    def test_sqlite_path_is_configurable(self):
        target = os.path.join(tempfile.gettempdir(), "hw_custom.db")
        out = run_isolated(
            "import db_client; print(db_client.SQLITE_PATH)",
            {"COWRIE_SQLITE_PATH": target},
        )
        self.assertEqual(out, target)


class FallbackBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sqlite_path = os.path.join(self.tmp.name, "fallback.db")
        for name, value in (("SQLITE_PATH", self.sqlite_path),):
            p = patch.object(db_client, name, value)
            p.start()
            self.addCleanup(p.stop)
        connect = patch.object(
            db_client.mysql.connector, "connect", side_effect=RuntimeError("unreachable")
        )
        connect.start()
        self.addCleanup(connect.stop)

    def test_mysql_mode_never_creates_a_sqlite_file(self):
        with patch.object(db_client, "DB_TYPE", "mysql"):
            result = db_client.DatabaseClient().execute_query("SELECT 1", fetch="one")
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(self.sqlite_path))

    def test_auto_mode_fallback_is_announced(self):
        with patch.object(db_client, "DB_TYPE", "auto"):
            with self.assertLogs("db_client", level="WARNING"):
                db_client.DatabaseClient().execute_query("SELECT 1", fetch="one")


if __name__ == "__main__":
    unittest.main()
