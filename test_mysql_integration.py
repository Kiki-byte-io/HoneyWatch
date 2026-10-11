"""Opt-in integration test for the proposed MySQL telemetry schema.

Run in a fresh Python process with HONEYWATCH_MYSQL_INTEGRATION=1 and a
pre-provisioned disposable database whose name starts with ``honeywatch_test_``.
"""

import importlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


SCHEMA_PATH = Path(__file__).parent / "schema" / "mysql.sql"
EXPECTED_TABLES = {"sessions", "login_attempts", "commands"}
EXPECTED_COLUMNS = {
    "sessions": {
        "session_id": ("varchar(191)", "NO", True, ""),
        "src_ip": ("varchar(45)", "YES", False, ""),
        "src_port": ("smallint unsigned", "YES", False, ""),
        "dst_port": ("smallint unsigned", "YES", False, ""),
        "start_time": ("varchar(64)", "YES", False, ""),
        "end_time": ("varchar(64)", "YES", False, ""),
        "duration_ms": ("bigint unsigned", "YES", False, ""),
    },
    "login_attempts": {
        "id": ("bigint unsigned", "NO", True, "auto_increment"),
        "session_id": ("varchar(191)", "NO", False, ""),
        "username": ("text", "YES", False, ""),
        "password": ("text", "YES", False, ""),
        "success": ("tinyint unsigned", "NO", False, ""),
        "timestamp": ("varchar(64)", "YES", False, ""),
    },
    "commands": {
        "id": ("bigint unsigned", "NO", True, "auto_increment"),
        "session_id": ("varchar(191)", "NO", False, ""),
        "input": ("text", "YES", False, ""),
        "timestamp": ("varchar(64)", "YES", False, ""),
    },
}
EXPECTED_FOREIGN_KEYS = {
    ("login_attempts", "session_id", "sessions", "session_id"),
    ("commands", "session_id", "sessions", "session_id"),
}
EXPECTED_PRIMARY_KEYS = {
    ("sessions", ("session_id",)),
    ("login_attempts", ("id",)),
    ("commands", ("id",)),
}
REQUIRED_ENV = (
    "COWRIE_DB_TYPE",
    "COWRIE_DB_NAME",
    "COWRIE_DB_HOST",
    "COWRIE_DB_USER",
    "COWRIE_DB_PASSWORD",
)


def validate_existing_schema(
    table_names, engine_rows, column_rows, foreign_key_rows, index_rows
):
    """Fail closed unless existing tables satisfy the ingestion schema contract."""
    table_names = set(table_names)
    unexpected_tables = table_names - EXPECTED_TABLES
    if unexpected_tables:
        raise RuntimeError(
            "Refusing to run: disposable schema contains unexpected tables: "
            + ", ".join(sorted(unexpected_tables))
        )

    metadata_tables = (
        {table for table, *_ in engine_rows}
        | {table for table, *_ in column_rows}
        | {table for table, *_ in foreign_key_rows}
        | {table for table, *_ in index_rows}
    )
    if not metadata_tables.issubset(table_names):
        raise RuntimeError(
            "INFORMATION_SCHEMA returned inconsistent table metadata; refusing DDL"
        )

    if any(not isinstance(engine, str) for _, engine in engine_rows):
        raise RuntimeError("Could not inspect existing telemetry table engines")
    engines = {table: engine.casefold() for table, engine in engine_rows}
    if any(engines.get(table) != "innodb" for table in table_names):
        raise RuntimeError("Existing telemetry tables must use the InnoDB engine")

    child_tables = {"login_attempts", "commands"}
    if table_names & child_tables and "sessions" not in table_names:
        raise RuntimeError("Existing child tables require the sessions parent table")

    columns_by_table = {}
    for table, column, column_type, nullable, column_key, extra in column_rows:
        columns_by_table.setdefault(table, {})[column] = (
            column_type.casefold(),
            nullable,
            column_key == "PRI",
            extra.casefold(),
        )

    for table in table_names:
        actual_columns = columns_by_table.get(table, {})
        expected_columns = EXPECTED_COLUMNS[table]
        if actual_columns != expected_columns:
            raise RuntimeError(
                f"Existing table {table!r} does not match the required MySQL schema"
            )

    actual_foreign_keys = set(foreign_key_rows)
    expected_existing_foreign_keys = {
        foreign_key for foreign_key in EXPECTED_FOREIGN_KEYS
        if foreign_key[0] in table_names
    }
    actual_existing_foreign_keys = {
        foreign_key for foreign_key in actual_foreign_keys
        if foreign_key[0] in table_names
    }
    if actual_existing_foreign_keys != expected_existing_foreign_keys:
        raise RuntimeError(
            "Existing tables do not have the required session foreign-key constraints"
        )

    primary_indexes = {}
    for table, index_name, _non_unique, sequence, column in index_rows:
        if index_name == "PRIMARY":
            primary_indexes.setdefault(table, []).append((sequence, column))
    actual_primary_keys = {
        (table, tuple(column for _, column in sorted(columns)))
        for table, columns in primary_indexes.items()
        if table in table_names
    }
    expected_primary_keys = {
        key for key in EXPECTED_PRIMARY_KEYS if key[0] in table_names
    }
    if actual_primary_keys != expected_primary_keys:
        raise RuntimeError(
            "Existing tables are missing or have incorrect PRIMARY indexes"
        )


def validate_test_database_user(username):
    if username.casefold() == "cowrie_app":
        raise RuntimeError(
            "Refusing to run the MySQL integration test with the cowrie_app account"
        )


class MySQLIntegrationSafetyTests(unittest.TestCase):
    def test_rejects_cowrie_app_username_case_insensitively(self):
        for username in ("cowrie_app", "Cowrie_App", "COWRIE_APP"):
            with self.subTest(username=username):
                with self.assertRaisesRegex(RuntimeError, "cowrie_app account"):
                    validate_test_database_user(username)

    @staticmethod
    def compatible_metadata():
        tables = set(EXPECTED_TABLES)
        engines = [(table, "InnoDB") for table in tables]
        columns = [
            (
                table,
                column,
                column_type,
                nullable,
                "PRI" if primary_key else "",
                extra,
            )
            for table, table_columns in EXPECTED_COLUMNS.items()
            for column, (column_type, nullable, primary_key, extra) in table_columns.items()
        ]
        indexes = []
        for table, indexed_columns in EXPECTED_PRIMARY_KEYS:
            for sequence, column in enumerate(indexed_columns, start=1):
                indexes.append((table, "PRIMARY", 0, sequence, column))
        return tables, engines, columns, set(EXPECTED_FOREIGN_KEYS), indexes

    @staticmethod
    def metadata_for(*table_names):
        (
            tables,
            engines,
            columns,
            foreign_keys,
            indexes,
        ) = MySQLIntegrationSafetyTests.compatible_metadata()
        tables = set(table_names)
        engines = [row for row in engines if row[0] in tables]
        columns = [row for row in columns if row[0] in tables]
        foreign_keys = {
            row for row in foreign_keys if row[0] in tables
        }
        indexes = [row for row in indexes if row[0] in tables]
        return tables, engines, columns, foreign_keys, indexes

    def test_empty_schema_is_accepted(self):
        validate_existing_schema(set(), [], [], set(), [])

    def test_sessions_table_alone_is_accepted(self):
        validate_existing_schema(*self.metadata_for("sessions"))

    def test_sessions_and_one_child_table_are_accepted(self):
        validate_existing_schema(*self.metadata_for("sessions", "commands"))

    def test_child_table_without_parent_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "require the sessions parent"):
            validate_existing_schema(*self.metadata_for("commands"))

    def test_all_compatible_tables_are_accepted(self):
        validate_existing_schema(*self.compatible_metadata())

    def test_missing_primary_index_metadata_is_rejected(self):
        tables, engines, columns, foreign_keys, indexes = self.metadata_for("sessions")
        indexes = []
        with self.assertRaisesRegex(RuntimeError, "missing or have incorrect PRIMARY"):
            validate_existing_schema(tables, engines, columns, foreign_keys, indexes)

    def test_incorrect_primary_index_metadata_is_rejected(self):
        tables, engines, columns, foreign_keys, indexes = self.metadata_for("sessions")
        indexes = [("sessions", "PRIMARY", 0, 1, "src_ip")]
        with self.assertRaisesRegex(RuntimeError, "missing or have incorrect PRIMARY"):
            validate_existing_schema(tables, engines, columns, foreign_keys, indexes)

    def test_additional_unique_index_is_accepted(self):
        metadata = list(self.metadata_for("sessions"))
        metadata[4] = metadata[4] + [
            ("sessions", "redundant_unique", 0, 1, "session_id")
        ]
        validate_existing_schema(*metadata)

    def test_incomplete_metadata_is_rejected(self):
        tables, engines, columns, foreign_keys, indexes = self.metadata_for("sessions")
        columns = [row for row in columns if row[1] != "src_ip"]
        with self.assertRaisesRegex(RuntimeError, "sessions.*required MySQL schema"):
            validate_existing_schema(tables, engines, columns, foreign_keys, indexes)

    def test_metadata_for_unlisted_table_is_rejected(self):
        _, engines, columns, foreign_keys, indexes = self.metadata_for("sessions")
        with self.assertRaisesRegex(RuntimeError, "inconsistent table metadata"):
            validate_existing_schema(set(), engines, columns, foreign_keys, indexes)

    def test_unexpected_table_is_rejected(self):
        tables, engines, columns, foreign_keys, indexes = self.compatible_metadata()
        tables.add("unrelated")
        with self.assertRaisesRegex(RuntimeError, "unexpected tables"):
            validate_existing_schema(tables, engines, columns, foreign_keys, indexes)

    def test_incompatible_existing_table_is_rejected(self):
        tables, engines, columns, foreign_keys, indexes = self.compatible_metadata()
        columns = [
            (*row[:2], "varchar(32)", *row[3:]) if row[:2] == ("sessions", "session_id") else row
            for row in columns
        ]
        with self.assertRaisesRegex(RuntimeError, "sessions.*required MySQL schema"):
            validate_existing_schema(tables, engines, columns, foreign_keys, indexes)


@unittest.skipUnless(
    os.environ.get("HONEYWATCH_MYSQL_INTEGRATION") == "1",
    "Set HONEYWATCH_MYSQL_INTEGRATION=1 to opt in to the MySQL integration test",
)
class MySQLIngestionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [name for name in REQUIRED_ENV if name not in os.environ]
        if missing:
            raise RuntimeError(
                "MySQL integration test requires environment variables: "
                + ", ".join(missing)
            )
        validate_test_database_user(os.environ["COWRIE_DB_USER"])
        if os.environ["COWRIE_DB_TYPE"] != "mysql":
            raise RuntimeError("COWRIE_DB_TYPE must be exactly 'mysql'")

        cls.database_name = os.environ["COWRIE_DB_NAME"]
        if cls.database_name.casefold() == "cowrie_logs":
            raise RuntimeError("Refusing to run against the protected cowrie_logs database")
        if not cls.database_name.startswith("honeywatch_test_"):
            raise RuntimeError(
                "COWRIE_DB_NAME must start with 'honeywatch_test_'"
            )

        # db_client snapshots environment variables at import time. Import only
        # after validation, then reject a stale module configuration explicitly.
        cls.db_client = importlib.import_module("db_client")
        cls.log_watcher = importlib.import_module("log_watcher")
        expected = {
            "DB_TYPE": os.environ["COWRIE_DB_TYPE"],
            "DB_NAME": cls.database_name,
            "DB_HOST": os.environ["COWRIE_DB_HOST"],
            "DB_USER": os.environ["COWRIE_DB_USER"],
            "DB_PASSWORD": os.environ["COWRIE_DB_PASSWORD"],
        }
        stale = [
            name for name, value in expected.items()
            if getattr(cls.db_client, name) != value
        ]
        if stale:
            raise RuntimeError(
                "db_client was imported with different settings for: "
                + ", ".join(stale)
                + "; run this integration test in a fresh Python process"
            )

        # db_client currently relies on mysql.connector's default port (3306).
        # Reject a port setting it would silently ignore.
        cls.database_port = int(getattr(cls.db_client, "DB_PORT", 3306))
        configured_port = os.environ.get("COWRIE_DB_PORT")
        if configured_port is not None:
            try:
                configured_port = int(configured_port)
            except ValueError as err:
                raise RuntimeError("COWRIE_DB_PORT must be an integer") from err
            if configured_port != cls.database_port:
                raise RuntimeError(
                    "COWRIE_DB_PORT does not match db_client's configured port; "
                    "refusing to risk using different MySQL servers"
                )

        import mysql.connector

        cls.mysql_connector = mysql.connector

    def test_placeholder_command_then_connect_enrichment(self):
        connection = None
        cursor = None
        temp_dir = tempfile.TemporaryDirectory(prefix="honeywatch-mysql-test-")
        original_log_glob = self.log_watcher.LOG_GLOB
        original_local_log_glob = self.log_watcher.LOCAL_LOG_GLOB
        original_offsets = dict(self.log_watcher.FILE_OFFSETS)
        session_id = f"honeywatch-it-{uuid.uuid4().hex}"
        safe_to_clean_rows = False

        try:
            try:
                connection = self.mysql_connector.connect(
                    host=os.environ["COWRIE_DB_HOST"],
                    user=os.environ["COWRIE_DB_USER"],
                    password=os.environ["COWRIE_DB_PASSWORD"],
                    database=self.database_name,
                    port=self.database_port,
                    connect_timeout=5,
                )
            except Exception as err:
                raise RuntimeError(
                    "Could not reach the explicitly configured MySQL database; "
                    "the integration test never falls back to SQLite"
                ) from err
            cursor = connection.cursor()

            cursor.execute("SELECT DATABASE(), @@hostname, @@port")
            direct_identity = cursor.fetchone()
            selected_database = direct_identity[0]
            self.assertEqual(
                selected_database,
                self.database_name,
                "MySQL connected to a database other than COWRIE_DB_NAME",
            )

            try:
                client_identity = self.db_client.db.execute_query(
                    "SELECT DATABASE() AS database_name, "
                    "@@hostname AS server_host, @@port AS server_port",
                    fetch="one",
                    raise_on_error=True,
                )
            except Exception as err:
                raise RuntimeError(
                    "DatabaseClient could not verify its configured MySQL connection"
                ) from err
            if self.db_client.db.db_type != "mysql":
                raise RuntimeError("DatabaseClient did not use MySQL")
            self.assertEqual(
                client_identity["database_name"],
                self.database_name,
                "DatabaseClient selected a database other than COWRIE_DB_NAME",
            )
            self.assertEqual(
                (client_identity["server_host"], int(client_identity["server_port"])),
                (direct_identity[1], int(direct_identity[2])),
                "DatabaseClient and schema setup connected to different MySQL servers",
            )

            try:
                # The test account must have schema-wide visibility so an empty
                # metadata result cannot hide pre-existing tables.
                cursor.execute(
                    "SELECT TABLE_NAME, ENGINE FROM INFORMATION_SCHEMA.TABLES "
                    "WHERE TABLE_SCHEMA = %s",
                    (self.database_name,),
                )
                existing_engines = cursor.fetchall()
                existing_table_names = {row[0] for row in existing_engines}
                cursor.execute(
                    "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, "
                    "COLUMN_KEY, EXTRA FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE TABLE_SCHEMA = %s",
                    (self.database_name,),
                )
                existing_columns = cursor.fetchall()
                cursor.execute(
                    "SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, "
                    "REFERENCED_COLUMN_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE "
                    "WHERE TABLE_SCHEMA = %s AND REFERENCED_TABLE_NAME IS NOT NULL",
                    (self.database_name,),
                )
                existing_foreign_keys = cursor.fetchall()
                cursor.execute(
                    "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, "
                    "COLUMN_NAME FROM INFORMATION_SCHEMA.STATISTICS "
                    "WHERE TABLE_SCHEMA = %s",
                    (self.database_name,),
                )
                existing_indexes = cursor.fetchall()
            except Exception as err:
                raise RuntimeError(
                    "Could not inspect the disposable schema metadata; refusing DDL"
                ) from err
            try:
                validate_existing_schema(
                    existing_table_names,
                    existing_engines,
                    existing_columns,
                    existing_foreign_keys,
                    existing_indexes,
                )
            except Exception as err:
                raise RuntimeError(
                    f"Refusing schema setup: {err}"
                ) from err

            schema_lines = [
                line
                for line in SCHEMA_PATH.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("--")
            ]
            schema_statements = [
                statement.strip()
                for statement in "\n".join(schema_lines).split(";")
                if statement.strip()
            ]
            if len(schema_statements) != 3:
                raise RuntimeError(
                    "Expected exactly three MySQL CREATE TABLE statements in schema/mysql.sql"
                )
            for statement_number, statement in enumerate(schema_statements, start=1):
                try:
                    cursor.execute(statement)
                except Exception as err:
                    raise RuntimeError(
                        f"Schema statement {statement_number} failed; earlier DDL "
                        "statements may already have created tables. No tables were removed."
                    ) from err
            connection.commit()
            cursor.close()
            cursor = None

            db = self.db_client.db
            existing_session = db.execute_query(
                "SELECT session_id FROM sessions WHERE session_id = %s",
                (session_id,),
                fetch="all",
                raise_on_error=True,
            )
            self.assertEqual(existing_session, [])
            safe_to_clean_rows = True

            log_path = os.path.join(temp_dir.name, "cowrie.json")
            self.log_watcher.LOG_GLOB = log_path
            self.log_watcher.LOCAL_LOG_GLOB = log_path
            self.log_watcher.FILE_OFFSETS.clear()

            command_event = {
                "eventid": "cowrie.command.input",
                "session": session_id,
                "input": "whoami",
                "timestamp": "2026-10-10T10:00:00Z",
            }
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write(json.dumps(command_event) + "\n")

            self.assertEqual(self.log_watcher.poll_logs_once(), 1)
            sessions = db.execute_query(
                "SELECT session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms "
                "FROM sessions WHERE session_id = %s",
                (session_id,),
                fetch="all",
                raise_on_error=True,
            )
            commands = db.execute_query(
                "SELECT session_id, input, timestamp FROM commands WHERE session_id = %s",
                (session_id,),
                fetch="all",
                raise_on_error=True,
            )
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["session_id"], session_id)
            for column in ("src_ip", "src_port", "dst_port", "start_time", "end_time", "duration_ms"):
                self.assertIsNone(sessions[0][column])
            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0]["session_id"], session_id)
            self.assertEqual(commands[0]["input"], "whoami")
            self.assertEqual(commands[0]["timestamp"], "2026-10-10 10:00:00")

            connect_event = {
                "eventid": "cowrie.session.connect",
                "session": session_id,
                "src_ip": "192.0.2.25",
                "src_port": 43210,
                "dst_port": 22,
                "timestamp": "2026-10-10T10:01:00Z",
            }
            with open(log_path, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(connect_event) + "\n")

            self.assertEqual(self.log_watcher.poll_logs_once(), 1)
            sessions = db.execute_query(
                "SELECT session_id, src_ip, src_port, dst_port, start_time, end_time, duration_ms "
                "FROM sessions WHERE session_id = %s",
                (session_id,),
                fetch="all",
                raise_on_error=True,
            )
            commands = db.execute_query(
                "SELECT session_id, input, timestamp FROM commands WHERE session_id = %s",
                (session_id,),
                fetch="all",
                raise_on_error=True,
            )
            self.assertEqual(len(sessions), 1, "Connect event created a duplicate session")
            self.assertEqual(sessions[0]["src_ip"], "192.0.2.25")
            self.assertEqual(sessions[0]["src_port"], 43210)
            self.assertEqual(sessions[0]["dst_port"], 22)
            self.assertEqual(sessions[0]["start_time"], "2026-10-10 10:01:00")
            self.assertIsNone(sessions[0]["end_time"])
            self.assertIsNone(sessions[0]["duration_ms"])
            self.assertEqual(len(commands), 1, "Appending connect replayed the command")

        finally:
            original_error = sys.exc_info()[1]
            cleanup_errors = []

            def attempt_cleanup(action):
                try:
                    action()
                except Exception as err:
                    cleanup_errors.append(err)

            if safe_to_clean_rows:
                try:
                    db = self.db_client.db
                except Exception as err:
                    cleanup_errors.append(err)
                else:
                    for table in ("commands", "login_attempts", "sessions"):
                        attempt_cleanup(
                            lambda table=table: db.execute_query(
                                f"DELETE FROM {table} WHERE session_id = %s",
                                (session_id,),
                                fetch=None,
                                raise_on_error=True,
                            )
                        )

            for restore in (
                lambda: setattr(self.log_watcher, "LOG_GLOB", original_log_glob),
                lambda: setattr(self.log_watcher, "LOCAL_LOG_GLOB", original_local_log_glob),
                lambda: self.log_watcher.FILE_OFFSETS.clear(),
                lambda: self.log_watcher.FILE_OFFSETS.update(original_offsets),
            ):
                attempt_cleanup(restore)

            for resource in (cursor, connection):
                if resource is not None:
                    attempt_cleanup(resource.close)
            attempt_cleanup(temp_dir.cleanup)

            if cleanup_errors:
                message = "MySQL integration cleanup encountered: " + "; ".join(
                    str(err) for err in cleanup_errors
                )
                if original_error is not None:
                    print(message, file=sys.stderr)
                else:
                    raise RuntimeError(message) from cleanup_errors[0]


if __name__ == "__main__":
    unittest.main()
