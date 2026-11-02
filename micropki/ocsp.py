import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import core as asn1_core
from asn1crypto import keys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.x509.oid import NameOID
from .logger import log_event

logger = logging.getLogger("pki_audit")

class ParsedOCSPRequest:
    def __init__(self, nonce: Optional[bytes], cert_ids: list[dict]):
        self.nonce = nonce
        self.cert_ids = cert_ids

def parse_ocsp_request(der: bytes) -> ParsedOCSPRequest:
    try:
        req = asn1_ocsp.OCSPRequest.load(der)
    except Exception as e:
        raise ValueError(f"Malformed OCSP request: {e}") from e

    version = req["tbs_request"]["version"].native
    if version not in ("v1", 0):
      raise ValueError(f"Unsupported OCSP request version (expected v1, got {version!r})")

    nonce = None
    req_exts = req["tbs_request"]["request_extensions"]
    if req_exts.native is not None:
        for ext in req_exts:
            if ext["extn_id"].native == "nonce":
                nonce_val = ext["extn_value"].native
                if nonce_val is not None and not isinstance(nonce_val, bytes):
                    nonce_val = bytes(nonce_val)
                nonce = nonce_val
                break

    cert_ids = []
    for single in req["tbs_request"]["request_list"]:
        cid = single["req_cert"]
        hash_alg = cid["hash_algorithm"]["algorithm"].native
        if hash_alg not in ("sha1", "sha256"):
            raise ValueError(f"Unsupported hash algorithm in CertID: {hash_alg}")
        serial = cid["serial_number"].native
        cert_ids.append({
            "hash_alg": hash_alg,
            "issuer_name_hash": cid["issuer_name_hash"].native,
            "issuer_key_hash": cid["issuer_key_hash"].native,
            "serial": serial,
        })

    if not cert_ids:
        raise ValueError("OCSP request contains no CertID entries")

    return ParsedOCSPRequest(nonce=nonce, cert_ids=cert_ids)

def _stub_cert(issuer: x509.Certificate, serial: int) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ocsp-unknown-stub")
        ]))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

def issuer_name_hash(issuer_cert: x509.Certificate, alg: str) -> bytes:
    der = issuer_cert.subject.public_bytes(default_backend())
    return hashlib.new(alg, der).digest()

def issuer_key_hash(issuer_cert: x509.Certificate, alg: str) -> bytes:
    spki = issuer_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_asn1 = keys.PublicKeyInfo.load(spki)
    bit_string = spki_asn1["public_key"].contents
    bit_string = bit_string[1:]

    return hashlib.new(alg, bit_string).digest()

def match_issuer(cert_ids: list[dict], known_issuers: list[x509.Certificate]) -> dict[int, x509.Certificate]:
    matches: dict[int, x509.Certificate] = {}
    for idx, cid in enumerate(cert_ids):
        alg = cid["hash_alg"]
        for issuer in known_issuers:
            if (issuer_name_hash(issuer, alg) == cid["issuer_name_hash"]
                    and issuer_key_hash(issuer, alg) == cid["issuer_key_hash"]):
                matches[idx] = issuer
                break
    return matches

def _signature_algorithm_for(key) -> hashes.HashAlgorithm:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return hashes.SHA256()
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return hashes.SHA384()
    raise TypeError(f"Unsupported key type: {type(key).__name__}")

def build_ocsp_response(*, request, responder_cert, responder_key,
                        issuer_for_serial, status_by_serial,
                        cache_ttl=60) -> bytes:
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(seconds=cache_ttl)

    builder = x509_ocsp.OCSPResponseBuilder()
    builder = builder.responder_id(
        x509_ocsp.OCSPResponderEncoding.HASH, responder_cert
    )

    for idx, cid in enumerate(request.cert_ids):
        issuer = issuer_for_serial.get(idx)
        info = status_by_serial.get(cid["serial"], {"status": "unknown"})
        status = info["status"]
        algorithm = _map_hash_alg(cid["hash_alg"])

        if issuer is None:
            log_event(logger, logging.WARNING,
                      "OCSP: issuer not recognized for CertID, skipped",
                      serial=cid["serial"])
            continue

        if status == "good" and "cert" in info:
            builder = builder.add_response(
                cert=info["cert"], issuer=issuer, algorithm=algorithm,
                cert_status=x509_ocsp.OCSPCertStatus.GOOD,
                this_update=now, next_update=next_update,
                revocation_time=None, revocation_reason=None,
            )
        elif status == "revoked" and "cert" in info:
            builder = builder.add_response(
                cert=info["cert"], issuer=issuer, algorithm=algorithm,
                cert_status=x509_ocsp.OCSPCertStatus.REVOKED,
                this_update=now, next_update=next_update,
                revocation_time=info["revoked_at"],
                revocation_reason=_map_reason(info.get("reason")),
            )
        else:
            stub = _stub_cert(issuer, cid["serial"])
            builder = builder.add_response(
                cert=stub, issuer=issuer, algorithm=algorithm,
                cert_status=x509_ocsp.OCSPCertStatus.UNKNOWN,
                this_update=now, next_update=next_update,
                revocation_time=None, revocation_reason=None,
            )

    if request.nonce is not None:
        n = request.nonce if isinstance(request.nonce, bytes) else bytes(request.nonce)
        builder = builder.add_extension(x509.OCSPNonce(n), critical=False)

    response = builder.sign(
        private_key=responder_key,
        algorithm=_signature_algorithm_for(responder_key),
    )
    der = response.public_bytes(serialization.Encoding.DER)
    log_event(logger, logging.INFO, "OCSP response built",
              cert_ids=len(request.cert_ids), nonce=bool(request.nonce),
              size=len(der))
    return der

def _map_hash_alg(name: str) -> hashes.HashAlgorithm:
    return hashes.SHA1() if name == "sha1" else hashes.SHA256()

def _map_reason(reason: Optional[str]):
    if not reason:
        return None
    from .crl import REASON_MAP, normalize_reason
    try:
        return REASON_MAP[normalize_reason(reason)]
    except (KeyError, ValueError):
        return None

def build_error_response(status: x509_ocsp.OCSPResponseStatus) -> bytes:
    resp = x509_ocsp.OCSPResponseBuilder.build_unsuccessful(status)
    return resp.public_bytes(serialization.Encoding.DER)
