import logging
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("pki_audit")

def append_ct(ct_path: Path, cert: x509.Certificate) -> None:
    ct_path = Path(ct_path)
    ct_path.parent.mkdir(parents=True, exist_ok=True)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    line = (
        f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}|"
        f"{format(cert.serial_number, 'x')}|"
        f"{cert.subject.rfc4514_string()}|"
        f"{fingerprint}|"
        f"{cert.issuer.rfc4514_string()}\n"
    )
    with open(ct_path, "a", encoding="utf-8") as f:
        f.write(line)
    try:
        import os
        os.chmod(ct_path, 0o644)
    except Exception:
        pass
    logger.info("CT entry appended: serial=%s", format(cert.serial_number, "x"))

def verify_ct(ct_path: Path, serial_hex: str) -> bool:
    ct_path = Path(ct_path)
    if not ct_path.is_file():
        return False
    needle = serial_hex.lower().removeprefix("0x")
    with open(ct_path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 2 and parts[1].lower() == needle:
                return True
    return False
