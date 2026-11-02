import logging
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from .logger import log_event

logger = logging.getLogger("pki_audit")

REASON_MAP = {
    "unspecified":          x509.ReasonFlags.unspecified,
    "keycompromise":        x509.ReasonFlags.key_compromise,
    "cacompromise":         x509.ReasonFlags.ca_compromise,
    "affiliationchanged":   x509.ReasonFlags.affiliation_changed,
    "superseded":           x509.ReasonFlags.superseded,
    "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
    "certificatehold":      x509.ReasonFlags.certificate_hold,
    "removefromcrl":        x509.ReasonFlags.remove_from_crl,
    "privilegewithdrawn":   x509.ReasonFlags.privilege_withdrawn,
    "aacompromise":         x509.ReasonFlags.aa_compromise,
}

REASON_CANONICAL = {k: k for k in REASON_MAP}

def normalize_reason(reason: str) -> str:
    """Validate and canonicalize a reason string (case-insensitive)."""
    key = reason.replace("_", "").replace("-", "").lower()
    if key not in REASON_MAP:
        raise ValueError(
            f"Unsupported revocation reason: {reason!r}. "
            f"Allowed: {', '.join(sorted(REASON_MAP))}"
        )
    return key

def _signature_algorithm_for(key) -> hashes.HashAlgorithm:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return hashes.SHA256()
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return hashes.SHA384()
    raise TypeError(f"Unsupported key type: {type(key).__name__}")

def _next_crl_number(conn, ca_subject: str) -> int:
    """CRL-6 / DB-6: monotonic per-issuer counter."""
    row = conn.execute(
        "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
        (ca_subject,),
    ).fetchone()
    if row is None:
        return 1
    return int(row["crl_number"]) + 1

def _save_crl_metadata(conn, *, ca_subject: str, crl_number: int,
                       last_generated: str, next_update: str,
                       crl_path: str) -> None:
    conn.execute(
        "INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(ca_subject) DO UPDATE SET "
        "crl_number=excluded.crl_number, "
        "last_generated=excluded.last_generated, "
        "next_update=excluded.next_update, "
        "crl_path=excluded.crl_path",
        (ca_subject, crl_number, last_generated, next_update, crl_path),
    )
    conn.commit()

def build_and_save_crl(*, ca_cert: x509.Certificate, ca_key,
                       revoked_rows, db_conn,
                       out_dir: Path, ca_label: str,
                       next_update_days: int = 7,
                       out_file: Path | None = None) -> Path:
    """Build, sign, and persist a CRL for `ca_cert` (CRL-1, CRL-4, CRL-5)."""
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=next_update_days)
    issuer = ca_cert.subject

    crl_number = _next_crl_number(db_conn, issuer.rfc4514_string())

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer)
        .last_update(now)
        .next_update(next_update)
    )

    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
    except x509.ExtensionNotFound:
        log_event(logger, logging.WARNING,
                  "CA certificate has no SKI; AKI omitted from CRL",
                  ca=issuer.rfc4514_string())

    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    count = 0
    for row in revoked_rows:
        serial_int = int(row["serial_hex"], 16)
        try:
            revoked_at = datetime.fromisoformat(row["revocation_date"])
        except (TypeError, ValueError):
            revoked_at = now
        rb = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(revoked_at)
        )
        if row["revocation_reason"]:
            try:
                rb = rb.add_extension(
                    x509.CRLReason(REASON_MAP[row["revocation_reason"]]),
                    critical=False,
                )
            except KeyError:
                log_event(logger, logging.WARNING,
                          "Unknown reason in DB, omitted from CRL entry",
                          serial=row["serial_hex"],
                          reason=row["revocation_reason"])
        builder = builder.add_revoked_certificate(rb.build())
        count += 1

    crl = builder.sign(
        private_key=ca_key,
        algorithm=_signature_algorithm_for(ca_key),
        backend=default_backend(),
    )

    crl_dir = out_dir / "crl"
    crl_dir.mkdir(parents=True, exist_ok=True)
    target = out_file or (crl_dir / f"{ca_label}.crl.pem")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    _save_crl_metadata(
        db_conn,
        ca_subject=issuer.rfc4514_string(),
        crl_number=crl_number,
        last_generated=now.isoformat(timespec="seconds"),
        next_update=next_update.isoformat(timespec="seconds"),
        crl_path=str(target.relative_to(out_dir)) if target.is_relative_to(out_dir) else str(target),
    )

    log_event(logger, logging.INFO, "CRL generated",
              ca=ca_label, crl_number=crl_number, revoked_count=count,
              this_update=now.isoformat(), next_update=next_update.isoformat(),
              path=str(target))
    return target

def load_crl(path: Path) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl(path.read_bytes(), default_backend())

def crl_etag(path: Path) -> str:
    """REPO-11: cheap ETag from file contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:32]
