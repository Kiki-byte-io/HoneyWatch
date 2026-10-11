-- HoneyWatch telemetry schema for MySQL/InnoDB.
-- This is a new, version-controlled schema definition. It does not assert
-- compatibility with any database that may already be deployed.
--
-- Design notes based on current writer behavior:
-- * session_id is an ASCII Cowrie identifier and the unique key required by
--   the session upserts. VARCHAR(191) keeps its utf8mb4-independent key size
--   within older InnoDB index limits; longer identifiers would need review.
-- * Event timestamps are stored as strings because parse_timestamp() returns
--   normalized timestamps or the original value when parsing fails.
-- * Child session foreign keys follow the relationships in the SQLite schema.
--   They require the session event to be present before child events.
-- * Nullable event fields reflect values the writer can pass as None.

CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    src_ip VARCHAR(45) NULL,
    src_port SMALLINT UNSIGNED NULL,
    dst_port SMALLINT UNSIGNED NULL,
    start_time VARCHAR(64) NULL,
    end_time VARCHAR(64) NULL,
    duration_ms BIGINT UNSIGNED NULL,
    PRIMARY KEY (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    username TEXT NULL,
    password TEXT NULL,
    success TINYINT UNSIGNED NOT NULL,
    timestamp VARCHAR(64) NULL,
    PRIMARY KEY (id),
    KEY idx_login_attempts_session_id (session_id),
    CONSTRAINT fk_login_attempts_session
        FOREIGN KEY (session_id) REFERENCES sessions (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS commands (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    input TEXT NULL,
    timestamp VARCHAR(64) NULL,
    PRIMARY KEY (id),
    KEY idx_commands_session_id (session_id),
    CONSTRAINT fk_commands_session
        FOREIGN KEY (session_id) REFERENCES sessions (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
