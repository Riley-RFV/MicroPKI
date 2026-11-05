import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from .certificates import parse_subject_dn
from .logger import log_event
from .validation import validate_path

logger = logging.getLogger("pki_audit")

def _gen_key(key_type: str, key_size: int):
    if key_type == "rsa":
        if key_size not in (2048, 4096):
            raise ValueError("RSA key size must be 2048 or 4096")
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "ecc":
        curve = {256: ec.SECP256R1(), 384: ec.SECP384R1()}.get(key_size)
        if curve is None:
            raise ValueError("ECC key size must be 256 or 384")
        return ec.generate_private_key(curve)
    raise ValueError(f"Unknown key type: {key_type}")

def _sign_algorithm_for(key):
    return hashes.SHA256() if isinstance(key, rsa.RSAPrivateKey) else hashes.SHA384()

def gen_csr(*, subject: str, key_type: str, key_size: int,
            sans: list[str], out_key: str, out_csr: str) -> dict:
    key = _gen_key(key_type, key_size)
    dn = parse_subject_dn(subject)

    builder = x509.CertificateSigningRequestBuilder().subject_name(dn)

    if sans:
        gn = []
        for raw in sans:
            kind, value = raw.split(":", 1)
            kind = kind.strip().lower()
            if kind == "dns":
                gn.append(x509.DNSName(value))
            elif kind == "ip":
                import ipaddress
                gn.append(x509.IPAddress(ipaddress.ip_address(value)))
            elif kind == "email":
                gn.append(x509.RFC822Name(value))
            elif kind == "uri":
                gn.append(x509.UniformResourceIdentifier(value))
            else:
                raise ValueError(f"Unsupported SAN type: {kind}")
        builder = builder.add_extension(
            x509.SubjectAlternativeName(gn), critical=False)

    csr = builder.sign(key, _sign_algorithm_for(key), default_backend())

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = Path(out_key).expanduser()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key_pem)
    if os.name != "nt":
        os.chmod(key_path, 0o600)
    log_event(logger, logging.WARNING,
              "Client private key stored UNENCRYPTED", path=str(key_path))

    csr_path = Path(out_csr).expanduser()
    csr_path.parent.mkdir(parents=True, exist_ok=True)
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    log_event(logger, logging.INFO, "CSR generated",
              subject=dn.rfc4514_string(), key_type=key_type,
              key_path=str(key_path), csr_path=str(csr_path))
    return {"key": str(key_path), "csr": str(csr_path)}

def request_cert(*, csr_path: str, template: str, ca_url: str,
                 out_cert: str, api_key: str | None = None) -> dict:
    csr_bytes = Path(csr_path).expanduser().read_bytes()

    url = f"{ca_url.rstrip('/')}/request-cert?template={template}"
    headers = {"Content-Type": "application/x-pem-file"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(url, data=csr_bytes, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise ValueError(f"CA returned {e.code}: {body}") from e

    if code != 201:
        raise ValueError(f"Unexpected status: {code}")

    cert = x509.load_pem_x509_certificate(body, default_backend())
    out = Path(out_cert).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(body)
    log_event(logger, logging.INFO, "Certificate received",
              serial=format(cert.serial_number, "x"),
              subject=cert.subject.rfc4514_string(), path=str(out))
    return {"cert": str(out), "serial": format(cert.serial_number, "x")}

def validate(*, cert: str, untrusted: list[str], trusted: str,
             crl: str | None, ocsp: bool, mode: str,
             validation_time: str | None, as_json: bool) -> dict:
    at = None
    if validation_time:
        at = datetime.fromisoformat(validation_time)
        if at.tzinfo is None:
            at = at.replace(tzinfo=__import__("datetime").timezone.utc)

    res = validate_path(
        leaf_path=cert, untrusted_paths=untrusted, trusted_path=trusted,
        validation_time=at,
        check_revocation=(mode == "full"),
        crl_arg=crl, ocsp=ocsp,
    )
    out = res.to_dict()
    if as_json:
        print(json.dumps(out, indent=2))
    else:
        for s in out["steps"]:
            mark = "OK" if s["ok"] else "FAIL"
            print(f"[{mark}] {s['name']}: {s['message']}")
        print("VALID" if out["ok"] else f"INVALID: {out['error']}")
    return out

def check_status(*, cert: str, ca_cert: str, crl: str | None,
                 ocsp_url: str | None) -> dict:
    from .revocation_check import check_status_with_fallback
    out = check_status_with_fallback(
        leaf_path=cert, ca_cert_path=ca_cert,
        crl_arg=crl, ocsp=bool(ocsp_url), ocsp_url=ocsp_url,
    )
    print(f"status={out['status']} source={out['source']}")
    if out.get("reason"):
        print(f"reason={out['reason']}")
    if out.get("revoked_at"):
        print(f"revoked_at={out['revoked_at']}")
    return out
