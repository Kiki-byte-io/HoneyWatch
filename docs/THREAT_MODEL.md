# HoneyWatch Threat Model and Security Audit

Audit date: 14 November 2026. Branch: `hardening/telemetry-audit`.

This document describes the security assumptions HoneyWatch is built on, the
findings from the Sprint C audit, and the risks that remain. It covers the
current lab deployment, which is a single Ubuntu VM on a VirtualBox host-only
network, not an internet-facing production service. See the last section for
the gap between the two.

## 1. What HoneyWatch is protecting

| Asset | Why it matters |
|---|---|
| Telemetry database (`cowrie_logs`) | Integrity of every count, classification and report depends on it. |
| Captured credentials (`login_attempts.password`) | Attackers sometimes try real, reused passwords. Stored for research; never returned by any API or report. |
| Database account credentials | Supplied only through environment variables (`COWRIE_DB_*`); none are committed. |
| The analyst's workstation and browser | The dashboard renders attacker-controlled text and produces CSV/PDF files the analyst opens. |
| Credibility of the reports | A report that overstates or invents findings is a security failure for a monitoring tool. |

## 2. Who might attack it

1. **Honeypot attackers (expected, untrusted).** They fully control usernames,
   passwords, command strings, client versions and timing. Every value in
   Cowrie's JSON log is attacker-supplied. This is the primary threat.
2. **A malicious web page open in the analyst's browser.** It can make requests
   to `127.0.0.1` via DNS rebinding but cannot read responses unless the server
   accepts the attacker's Host header.
3. **Local users or processes on the VM.** Out of scope for the lab. Anyone
   with a shell on the VM can read the database and logs directly.
4. **Supply-chain compromise of a Python dependency.** Considered under
   recommendations.

## 3. Trust boundaries

```text
 UNTRUSTED                         TRUST BOUNDARY                    TRUSTED (analyst)
 Attacker ──SSH──► Cowrie ──► cowrie.json ══► log_watcher.py ──► MySQL
                                (attacker-controlled fields)          │
                                                                      ▼
                         Flask API (127.0.0.1 only, no auth) ◄── analysis modules
                                │            │            │
                                ▼            ▼            ▼
                           Browser DOM    PDF report    CSV export
                                                  │
                         Local LLM (Ollama) ◄─────┘ prompt contains attacker text
```

Attacker-controlled data crosses into trusted contexts at five points. Each one
has to treat that data as inert:

| Crossing | Control | Verified by |
|---|---|---|
| JSON log → SQL | Parameterised queries only, no string-built SQL | Code review; no f-string user input in SQL |
| DB → browser DOM | `textContent` rendering, no `innerHTML` sinks | `test_dashboard_xss.js` (4 tests) |
| DB → PDF (ReportLab markup) | `xml.sax.saxutils.escape` before `Paragraph` | `test_report_generator.py` |
| DB → CSV (spreadsheet formulas) | Formula-prefixed cells quoted with `'` | `test_dashboard_security.py` |
| DB → LLM prompt | Prompt marks log content as data; output length-validated; deterministic fallback | `test_ai_summarizer.py` |

## 4. Confirmed findings

Each finding below was reproduced with a failing test or a scripted
reproduction before it was fixed.

| # | Finding | Severity (lab context) | Status |
|---|---|---|---|
| F1 | **Watcher restart duplicates data.** File offsets are kept only in memory, and `login_attempts`/`commands` have no natural unique key. Restarting the dashboard re-reads every log from byte 0 and inserts every login and command again, which inflates all counts, the classifier and reports. | **High (integrity)** | Fixed in `09bd93e` (offsets persisted per database). **Verified on the Ubuntu VM (15 Nov 2026)** against the isolated test database: the first run processed 3 events and a restart processed 0. Rows that past restarts already duplicated in `cowrie_logs` are untouched; see the read-only check below. |
| F1a | **Live impact of F1 confirmed.** On 15 Nov 2026, `cowrie_logs.commands` held 42 rows but only 12 distinct `(session_id, input, timestamp)` combinations, about 3.5 copies each. That fits repeated restart re-ingestion: older events gained more copies. | High (integrity) | Cleaned (15 Nov 2026): backup taken, dry run with `ROLLBACK`, then commit. Now 12 commands and 2 logins. |
| F10 | **Over-privileged application account.** `cowrie_app` holds `ALL PRIVILEGES` on `cowrie_logs`, including `DROP`, `ALTER` and `DELETE`. The application only needs `SELECT` and `INSERT`, plus `UPDATE` on `sessions`. | Medium | Fixed on the VM (15 Nov 2026): `SELECT, INSERT` on `commands` and `login_attempts`; `SELECT, INSERT, UPDATE` on `sessions` |
| F2 | **CSV formula injection.** Attacker-chosen usernames such as `=HYPERLINK(...)` were exported verbatim and would execute when the CSV is opened in Excel or LibreOffice. | Medium | Fixed in `ab86293` |
| F3 | **Error detail disclosure.** `/api/report/pdf` and `/api/dashboard/summary` returned raw exception text, which can include database user names and filesystem paths. | Low–Medium | Fixed in `ab86293` |
| F4 | **False database health.** The summary endpoint always reported `db_connected: true`, because query errors were swallowed and returned as empty results. An outage looked like a quiet honeypot. | Medium (monitoring integrity) | Fixed in `ab86293` |
| F5 | **Silent SQLite fallback.** With the default `COWRIE_DB_TYPE=auto`, an unreachable MySQL makes `db_client` create and use `cowrie_logs.db` beside the code without any warning. Running the test suite on a machine without MySQL creates this file. | Medium (config integrity) | Fixed: the default is now `mysql`; SQLite needs an explicit `COWRIE_SQLITE_PATH`/`COWRIE_DB_TYPE=sqlite`, and `auto` logs a warning when it falls back. |
| F6 | **Unvalidated paging.** Non-integer `page`/`limit` raised HTTP 500, and negative values returned wrong slices. | Low | Fixed in `ab86293` |
| F7 | **No Host header validation.** This allowed DNS rebinding against the unauthenticated localhost dashboard. | Low–Medium | Fixed in `ab86293` (`TRUSTED_HOSTS`) |
| F8 | **Report integrity issues.** The PDF crashed on markup in attacker text, local time was labelled as UTC, and the report didn't disclose that its intelligence sections ignore the date-range filter. | Medium | Fixed in `2382fbf` |
| F9 | **Unsupported AI conclusions.** Empty sessions were described as "successful authentication followed by reconnaissance", and unknown commands were labelled "standard". | Medium (report integrity) | Fixed in `70713d5`, `004038f` |

## 5. Checked and found sound

- **SQL injection:** all queries are parameterised. The only f-strings in SQL
  insert fixed fragments, never request data.
- **Stored XSS:** fixed in Sprint 2. The regression suite passes; the remaining
  `onclick` attributes are static and carry no data.
- **Secrets in the repository:** the full history of all branches was scanned.
  No `.env`, log, database or key file was ever committed. Every credential-like
  line in `cowrie.cfg` is byte-identical to Cowrie's upstream placeholder
  template, and only the SSH listener and JSON log output are enabled.
- **Captured passwords:** no API endpoint, CSV export or report emits the
  `password` column.
- **Debug mode:** off; the server binds to `127.0.0.1` only.
- **Integration-test isolation:** tests refuse to run unless the type is
  `mysql` and the database name starts with `honeywatch_test_`, and they
  explicitly refuse `cowrie_logs`.
- **Known dependency vulnerabilities:** `pip-audit` reported none for the
  resolved versions on the audit date.
- **Mitigations module:** advisory only. Nothing in HoneyWatch executes a
  block, firewall change or other action.

## 6. Accepted risks and assumptions

- **No authentication on the dashboard.** This is acceptable only because the
  server binds to `127.0.0.1` on a single-user lab VM. **Exposing port 5000
  beyond localhost (port forwarding, `0.0.0.0`, a reverse proxy) would expose
  all telemetry, including the CSV export, to anyone who can reach it.**
- **Captured passwords stored in plaintext.** Storing them is the point of a
  credential-capturing honeypot. Treat the database as sensitive and keep it
  on the VM.
- **Prompt injection is mitigated, not eliminated.** A small local model can
  still be steered by crafted command strings. Output is length-checked and
  rendered as text, and the deterministic summary remains the reference.
- **The single database account `cowrie_app` is used for both reading
  (dashboard) and writing (watcher).**

## 7. Recommendations

| # | Recommendation | Priority |
|---|---|---|
| R1 | Offset persistence is implemented (`09bd93e`) and its restart behaviour is verified on the VM. Remaining: run the **read-only** duplicate check on `cowrie_logs` (below) before deciding whether existing data needs cleaning, and save a baseline before the first live start. | **Next** |
| R2 | Done. Note that the watcher's `ON DUPLICATE KEY` SQL is MySQL-only, so real-time ingestion does not work in SQLite mode. SQLite serves only the demo seed data and the tests. | — |
| R3 | Split database privileges: a read-only account for the dashboard (`SELECT`) and a writer for the watcher (`SELECT, INSERT, UPDATE` on the three tables only). | Medium |
| R4 | Pin dependency versions (`requirements.txt` is unpinned) and run `pip-audit` in CI. | Medium |
| R5 | Remove the watcher's `LOCAL_LOG_GLOB` fallback, which ingests any `cowrie*.json*` file in the project directory when the main log path is empty. | Medium |
| R6 | Cap result sizes server-side: several endpoints load whole tables into memory on every request. | Low |
| R7 | Invalidate the AI summary cache when a session gains new events. | Low |

### Read-only checks for the Ubuntu VM

These only read data. Run them in the MySQL client as an account that can read
`cowrie_logs`:

```sql
-- R3: what the application account can do (expect no DROP/ALTER/GRANT).
SHOW GRANTS FOR 'cowrie_app'@'localhost';

-- F1: have restarts already duplicated rows? Any count > 1 is suspect.
SELECT session_id, input, timestamp, COUNT(*) AS copies
FROM cowrie_logs.commands
GROUP BY session_id, input, timestamp
HAVING COUNT(*) > 1
ORDER BY copies DESC
LIMIT 20;
```

Identical commands typed in the same second are legitimate distinct events, so
a duplicate count is evidence, not proof. Large uniform multiples (every row
×2, ×3) point to restart re-ingestion.

## 8. Lab deployment versus production

HoneyWatch is a portfolio-grade lab system. Before any internet-facing or
multi-user deployment, it would additionally need: authentication and roles,
TLS, a supervised watcher process (systemd) separate from the web server,
secrets management, persisted ingestion state (R1), database least privilege
(R3), rate limiting, backup and restore testing, a retention policy for
captured credentials, centralised logging and alerting, and CI with dependency
scanning. These are tracked as a separate production-readiness track, not
claimed here.
