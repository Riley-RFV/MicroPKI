import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .database import connect, get_certificate_by_serial, update_status
from .logger import log_event

logger = logging.getLogger("pki_audit")

def public_key_hash(cert_or_key) -> str:
    if isinstance(cert_or_key, x509.Certificate):
        pub = cert_or_key.public_key()
    else:
        pub = cert_or_key.public_key() if hasattr(cert_or_key, "public_key") else cert_or_key
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()

def is_key_compromised(db_path, cert_or_csr) -> bool:
    h = public_key_hash(cert_or_csr)
    conn = connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM compromised_keys WHERE public_key_hash = ?", (h,)
        ).fetchone()
    finally:
        conn.close()
    return row is not None

def mark_compromised(*, db_path, cert: x509.Certificate, reason: str) -> dict:
    serial_hex = format(cert.serial_number, "x")
    h = public_key_hash(cert)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    conn = connect(db_path)
    try:
        row = get_certificate_by_serial(conn, serial_hex)
        if row is None:
            raise ValueError(f"Certificate not found in DB: {serial_hex}")
        update_status(conn, serial_hex, "revoked", reason=reason, when=now)
        conn.execute(
            "INSERT OR IGNORE INTO compromised_keys "
            "(public_key_hash, certificate_serial, compromise_date, compromise_reason) "
            "VALUES (?, ?, ?, ?)",
            (h, serial_hex, now, reason),
        )
        conn.commit()
    finally:
        conn.close()

    log_event(logger, logging.CRITICAL,
              "Key compromise recorded", serial=serial_hex,
              public_key_hash=h, reason=reason)
    return {"serial": serial_hex, "public_key_hash": h,
            "revoked_at": now, "reason": reason}
