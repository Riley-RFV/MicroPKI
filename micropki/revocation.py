import logging
from datetime import datetime, timezone
from pathlib import Path
from .crl import normalize_reason
from .database import connect, get_certificate_by_serial, update_status
from .logger import log_event

logger = logging.getLogger("pki_audit")


def revoke_certificate(*, db_path: str | Path, serial_hex: str,
                       reason: str = "unspecified") -> dict:
    canonical = normalize_reason(reason)

    conn = connect(db_path)
    try:
        row = get_certificate_by_serial(conn, serial_hex)
        if row is None:
            log_event(logger, logging.ERROR, "Revocation failed: serial not found",
                      serial=serial_hex)
            raise ValueError(f"Certificate not found: {serial_hex}")

        if row["status"] == "revoked":
            log_event(logger, logging.WARNING,
                      "Revocation skipped: already revoked",
                      serial=serial_hex, reason=row["revocation_reason"])
            return {"already": True, "serial_hex": row["serial_hex"],
                    "subject": row["subject"]}

        when = datetime.now(timezone.utc).isoformat(timespec="seconds")
        update_status(conn, serial_hex, "revoked", reason=canonical, when=when)
        log_event(logger, logging.INFO, "Certificate revoked",
                  serial=serial_hex, reason=canonical, revoked_at=when)
        return {"already": False, "serial_hex": row["serial_hex"],
                "subject": row["subject"], "reason": canonical, "when": when}
    finally:
        conn.close()
