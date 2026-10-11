import re
import unittest
from pathlib import Path


SCHEMA_PATH = Path(__file__).parent / "schema" / "mysql.sql"


def load_table_definitions():
    """Read CREATE TABLE blocks for static schema-contract checks."""
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    tables = {}
    pattern = re.compile(
        r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(\w+)\s*"
        r"\((.*?)\)\s*ENGINE\s*=\s*InnoDB\b",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(sql):
        tables[match.group(1).lower()] = match.group(2)
    return tables


class MySQLSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tables = load_table_definitions()

    def require_column(self, table, column, declaration_pattern):
        self.assertIn(table, self.tables)
        self.assertRegex(
            self.tables[table],
            rf"(?im)^\s*{re.escape(column)}\s+{declaration_pattern}",
        )

    def test_schema_defines_all_watcher_tables_and_insert_columns(self):
        self.assertEqual(
            set(self.tables), {"sessions", "login_attempts", "commands"}
        )
        expected = {
            "sessions": {
                "session_id": r"VARCHAR\(191\).*NOT NULL",
                "src_ip": r"VARCHAR\(45\) NULL",
                "src_port": r"SMALLINT UNSIGNED NULL",
                "dst_port": r"SMALLINT UNSIGNED NULL",
                "start_time": r"VARCHAR\(64\) NULL",
                "end_time": r"VARCHAR\(64\) NULL",
                "duration_ms": r"BIGINT UNSIGNED NULL",
            },
            "login_attempts": {
                "id": r"BIGINT UNSIGNED NOT NULL AUTO_INCREMENT",
                "session_id": r"VARCHAR\(191\).*NOT NULL",
                "username": r"TEXT NULL",
                "password": r"TEXT NULL",
                "success": r"TINYINT UNSIGNED NOT NULL",
                "timestamp": r"VARCHAR\(64\) NULL",
            },
            "commands": {
                "id": r"BIGINT UNSIGNED NOT NULL AUTO_INCREMENT",
                "session_id": r"VARCHAR\(191\).*NOT NULL",
                "input": r"TEXT NULL",
                "timestamp": r"VARCHAR\(64\) NULL",
            },
        }
        for table, columns in expected.items():
            for column, declaration in columns.items():
                with self.subTest(table=table, column=column):
                    self.require_column(table, column, declaration)

    def test_primary_keys_and_session_upsert_unique_key(self):
        self.assertRegex(self.tables["sessions"], r"(?im)^\s*PRIMARY KEY\s*\(session_id\)")
        self.assertRegex(self.tables["login_attempts"], r"(?im)^\s*PRIMARY KEY\s*\(id\)")
        self.assertRegex(self.tables["commands"], r"(?im)^\s*PRIMARY KEY\s*\(id\)")

    def test_child_tables_reference_sessions_and_index_foreign_keys(self):
        for table, constraint, index in (
            ("login_attempts", "fk_login_attempts_session", "idx_login_attempts_session_id"),
            ("commands", "fk_commands_session", "idx_commands_session_id"),
        ):
            with self.subTest(table=table):
                self.assertRegex(
                    self.tables[table],
                    rf"(?is)CONSTRAINT\s+{constraint}\s+FOREIGN KEY\s*"
                    r"\(session_id\)\s+REFERENCES\s+sessions\s*\(session_id\)",
                )
                self.assertRegex(
                    self.tables[table],
                    rf"(?im)^\s*KEY\s+{index}\s*\(session_id\)",
                )


if __name__ == "__main__":
    unittest.main()
