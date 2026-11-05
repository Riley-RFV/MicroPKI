import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.x509.oid import ExtensionOID

from .logger import log_event

logger = logging.getLogger("pki_audit")


def _load_cert(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(open(path, "rb").read(),
                                          default_backend())


def _load_crl(arg: str) -> x509.CertificateRevocationList:
    if arg.startswith(("http://", "https://")):
        with urllib.request.urlopen(arg, timeout=10) as resp:
            data = resp.read()
    else:
        data = open(arg, "rb").read()
    if b"-----BEGIN X509 CRL-----" in data:
        return x509.load_pem_x509_crl(data, default_backend())
    return x509.load_der_x509_crl(data, default_backend())


def _verify_crl_signature(crl, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(crl.signature, crl.tbs_certlist_bytes,
                   ec.ECDSA(crl.signature_hash_algorithm))
    else:
        pub.verify(crl.signature, crl.tbs_certlist_bytes,
                   padding.PKCS1v15(), crl.signature_hash_algorithm)


def check_crl(*, cert: x509.Certificate, issuer: x509.Certificate,
              crl_arg: str) -> dict:
    crl = _load_crl(crl_arg)
    _verify_crl_signature(crl, issuer)

    now = datetime.now(timezone.utc)
    next_update = getattr(crl, "next_update_utc", None) or crl.next_update.replace(tzinfo=timezone.utc)
    stale = next_update < now
    if stale:
        log_event(logger, logging.WARNING, "CRL is stale",
                  next_update=next_update.isoformat(), crl=crl_arg)

    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked is None:
        return {"status": "good", "source": "crl", "stale": stale}
    reason = None
    try:
        reason = revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        pass
    when = getattr(revoked, "revocation_date_utc", None) or revoked.revocation_date.replace(tzinfo=timezone.utc)
    return {"status": "revoked", "source": "crl", "stale": stale,
            "revoked_at": when.isoformat(), "reason": reason}


def _ocsp_url_from_aia(cert: x509.Certificate) -> Optional[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None

def _crl_url_from_cdp(cert: x509.Certificate) -> Optional[str]:
    try:
        cdp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return None
    for dp in cdp:
        if dp.full_name:
            for gn in dp.full_name:
                if isinstance(gn, x509.UniformResourceIdentifier):
                    return gn.value
    return None

def check_ocsp(*, cert: x509.Certificate, issuer: x509.Certificate,
               ocsp_url: str, nonce: bool = True) -> dict:
    builder = x509_ocsp.OCSPRequestBuilder().add_certificate(
        cert, issuer, cert.signature_hash_algorithm,
    )
    if nonce:
        import os as _os
        builder = builder.add_extension(
            x509.OCSPNonce(_os.urandom(16)), critical=False)
    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)

    r = urllib.request.Request(
        ocsp_url, data=req_der,
        headers={"Content-Type": "application/ocsp-request"},
        method="POST",
    )
    with urllib.request.urlopen(r, timeout=10) as resp:
        body = resp.read()

    ocsp_resp = x509_ocsp.load_der_ocsp_response(body)
    if ocsp_resp.response_status != x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError(f"OCSP response status: {ocsp_resp.response_status.name}")

    status = ocsp_resp.certificate_status
    if status == x509_ocsp.OCSPCertStatus.GOOD:
        return {"status": "good", "source": "ocsp"}
    if status == x509_ocsp.OCSPCertStatus.REVOKED:
        rtime = getattr(ocsp_resp, "revocation_time_utc", None)
        if rtime is None:
            naive = getattr(ocsp_resp, "revocation_time", None)
            if naive is not None:
                from datetime import timezone as _tz
                rtime = naive.replace(tzinfo=_tz.utc)
        reason = getattr(ocsp_resp, "revocation_reason", None)
        return {
            "status": "revoked",
            "source": "ocsp",
            "revoked_at": rtime.isoformat() if rtime else None,
            "reason": reason.name if reason else None,
        }
    return {"status": "unknown", "source": "ocsp"}

def check_status_with_fallback(*, leaf_path: str, ca_cert_path: str,
                               crl_arg: Optional[str] = None,
                               ocsp: bool = False,
                               ocsp_url: Optional[str] = None) -> dict:
    cert = _load_cert(leaf_path)
    issuer = _load_cert(ca_cert_path)

    if ocsp or ocsp_url:
        url = ocsp_url or _ocsp_url_from_aia(cert)
        if url:
            try:
                out = check_ocsp(cert=cert, issuer=issuer, ocsp_url=url)
                if out["status"] in ("good", "revoked"):
                    log_event(logger, logging.INFO, "OCSP status",
                              serial=format(cert.serial_number, "x"),
                              status=out["status"])
                    return out
                log_event(logger, logging.WARNING,
                          "OCSP returned unknown, falling back to CRL",
                          serial=format(cert.serial_number, "x"))
            except Exception as e:
                log_event(logger, logging.WARNING,
                          "OCSP failed, falling back to CRL",
                          error=str(e))
        else:
            log_event(logger, logging.WARNING,
                      "No OCSP URL available, falling back to CRL")

    crl_source = crl_arg or _crl_url_from_cdp(cert)
    if crl_source:
        try:
            out = check_crl(cert=cert, issuer=issuer, crl_arg=crl_source)
            log_event(logger, logging.INFO, "CRL status",
                      serial=format(cert.serial_number, "x"),
                      status=out["status"])
            return out
        except Exception as e:
            log_event(logger, logging.ERROR, "CRL check failed", error=str(e))

    return {"status": "unknown", "source": "none"}
