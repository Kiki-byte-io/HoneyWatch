import os
import logging
import sqlite3
import mysql.connector

logger = logging.getLogger(__name__)

# Database Configuration from Environment
DB_HOST = os.getenv("COWRIE_DB_HOST", "localhost")
DB_USER = os.getenv("COWRIE_DB_USER", "cowrie_app")
DB_PASSWORD = os.getenv("COWRIE_DB_PASSWORD", "")
DB_NAME = os.getenv("COWRIE_DB_NAME", "cowrie_logs")
# 'mysql' (default), 'sqlite' (explicit local demo), or 'auto' (MySQL, falling
# back to SQLite with a warning). Silent fallback hid outages and wrote
# telemetry to an unexpected store, so it is no longer the default.
DB_TYPE = os.getenv("COWRIE_DB_TYPE", "mysql")

SQLITE_PATH = os.getenv(
    "COWRIE_SQLITE_PATH",
    os.path.join(os.path.dirname(__file__), "cowrie_logs.db"),
)


class DictCursor:
    """Wrapper to standardize MySQL dictionary cursor and SQLite dict output"""
    def __init__(self, cursor, is_sqlite=False):
        self.cursor = cursor
        self.is_sqlite = is_sqlite

    def execute(self, query, params=None):
        # Convert MySQL %s placeholder to SQLite ? placeholder if sqlite
        if self.is_sqlite:
            query = query.replace("%s", "?")
            # Replace MySQL specific functions if needed
            query = query.replace("COALESCE", "COALESCE")
        if params is not None:
            return self.cursor.execute(query, params)
        return self.cursor.execute(query)

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        if self.is_sqlite:
            columns = [col[0] for col in self.cursor.description]
            return dict(zip(columns, row))
        return row

    def fetchall(self):
        rows = self.cursor.fetchall()
        if not rows:
            return []
        if self.is_sqlite:
            columns = [col[0] for col in self.cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        return rows

    def close(self):
        self.cursor.close()


class DatabaseClient:
    def __init__(self):
        self.db_type = None

    def get_connection(self):
        # Try MySQL first if allowed
        if DB_TYPE in ("mysql", "auto"):
            try:
                conn = mysql.connector.connect(
                    host=DB_HOST,
                    user=DB_USER,
                    password=DB_PASSWORD,
                    database=DB_NAME,
                    connect_timeout=3
                )
                self.db_type = "mysql"
                return conn, False
            except Exception as e:
                if DB_TYPE == "mysql":
                    raise e
                logger.warning(
                    "MySQL unavailable (%s); COWRIE_DB_TYPE=auto is falling back to SQLite at %s",
                    type(e).__name__, SQLITE_PATH,
                )

        # Fallback to SQLite
        self.db_type = "sqlite"
        conn = sqlite3.connect(SQLITE_PATH)
        self.init_sqlite_schema(conn)
        return conn, True

    def init_sqlite_schema(self, conn):
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            start_time TEXT,
            end_time TEXT,
            duration_ms INTEGER
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            username TEXT,
            password TEXT,
            success INTEGER,
            timestamp TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            input TEXT,
            timestamp TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
        """)
        conn.commit()

    def execute_query(self, query, params=None, fetch="all", raise_on_error=False):
        conn = None
        try:
            conn, is_sqlite = self.get_connection()
            if is_sqlite:
                raw_cur = conn.cursor()
                cur = DictCursor(raw_cur, is_sqlite=True)
            else:
                cur = conn.cursor(dictionary=True)

            cur.execute(query, params)
            if fetch == "one":
                res = cur.fetchone()
            elif fetch == "all":
                res = cur.fetchall()
            else:
                conn.commit()
                res = None
            cur.close()
            return res
        except Exception as e:
            print(f"[DB Error] Query execution failed: {e}")
            if raise_on_error:
                raise
            if fetch == "one":
                return None
            elif fetch == "all":
                return []
            return None
        finally:
            if conn:
                conn.close()


db = DatabaseClient()
