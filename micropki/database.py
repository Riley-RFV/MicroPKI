import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .logger import log_event

logger = logging.getLogger("pki_audit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
"""


def init_db(db_path: str | Path) -> Path:
    path = Path(db_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        log_event(logger, logging.INFO, "Database initialized", db_path=str(path))
    except Exception as e:
        log_event(logger, logging.ERROR, "Database initialization failed",
                  db_path=str(path), error=str(e))
        raise
    finally:
        conn.close()
    return path


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(Path(db_path).expanduser()))
    conn.row_factory = sqlite3.Row
    return conn


def serial_exists(conn: sqlite3.Connection, serial: int) -> bool:
    from .serial import to_hex
    cur = conn.execute("SELECT 1 FROM certificates WHERE serial_hex = ?",
                       (to_hex(serial),))
    return cur.fetchone() is not None


def insert_certificate(conn: sqlite3.Connection, *, serial_hex: str, subject: str, issuer: str, not_before: str, not_after: str, cert_pem: str, 
                       status: str = "valid") -> None:
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        conn.execute(
            "INSERT INTO certificates "
            "(serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at),
        )
        conn.commit()
        log_event(logger, logging.INFO, "Certificate inserted into DB",
                  serial=serial_hex, subject=subject)
    except sqlite3.IntegrityError as e:
        conn.rollback()
        log_event(logger, logging.ERROR, "DB integrity error on insert",
                  serial=serial_hex, error=str(e))
        raise
    except Exception as e:
        conn.rollback()
        log_event(logger, logging.ERROR, "DB insert failed", error=str(e))
        raise


def get_certificate_by_serial(conn: sqlite3.Connection, serial_hex: str):
    cur = conn.execute(
        "SELECT * FROM certificates WHERE serial_hex = ?",
        (serial_hex.lower().removeprefix("0x"),),
    )
    return cur.fetchone()


def list_certificates(conn: sqlite3.Connection,
                      status: Optional[str] = None,
                      issuer: Optional[str] = None,
                      date_from: Optional[str] = None,
                      date_to: Optional[str] = None):
    query = "SELECT * FROM certificates WHERE 1=1"
    params: list = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if issuer:
        query += " AND issuer LIKE ?"
        params.append(f"%{issuer}%")
    if date_from:
        query += " AND not_before >= ?"
        params.append(date_from)
    if date_to:
        query += " AND not_after <= ?"
        params.append(date_to)
    query += " ORDER BY id ASC"
    return conn.execute(query, params).fetchall()


def update_status(conn: sqlite3.Connection, serial_hex: str, status: str,
                  reason: Optional[str] = None,
                  when: Optional[str] = None) -> None:
    when = when or datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE certificates SET status = ?, revocation_reason = ?, revocation_date = ? "
        "WHERE serial_hex = ?",
        (status, reason, when if status == "revoked" else None,
         serial_hex.lower().removeprefix("0x")),
    )
    conn.commit()
    log_event(logger, logging.INFO, "Certificate status updated",
              serial=serial_hex, status=status, reason=reason)


def list_revoked(conn: sqlite3.Connection):
    return conn.execute(
        "SELECT * FROM certificates WHERE status = 'revoked'"
    ).fetchall()
