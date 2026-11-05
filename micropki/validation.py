import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .logger import log_event
from .revocation_check import check_status_with_fallback

logger = logging.getLogger("pki_audit")

@dataclass
class StepResult:
    name: str
    ok: bool
    message: str = ""

@dataclass
class ValidationResult:
    ok: bool
    steps: list[StepResult] = field(default_factory=list)
    error: Optional[str] = None

    def add(self, name: str, ok: bool, message: str = "") -> None:
        self.steps.append(StepResult(name, ok, message))
        if not ok and self.error is None:
            self.error = message or name

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "error": self.error,
            "steps": [{"name": s.name, "ok": s.ok, "message": s.message}
                      for s in self.steps],
        }

def _load_pem_bundle(data: bytes) -> list[x509.Certificate]:
    certs = []
    marker = b"-----END CERTIFICATE-----"
    pos = 0
    while True:
        idx = data.find(marker, pos)
        if idx == -1:
            break
        end = idx + len(marker)
        block = data[pos:end]
        begin = block.find(b"-----BEGIN CERTIFICATE-----")
        if begin != -1:
            try:
                certs.append(x509.load_pem_x509_certificate(block[begin:end],
                                                            default_backend()))
            except Exception:
                pass
        pos = end
    return certs

def load_untrusted(paths: list[str]) -> list[x509.Certificate]:
    out = []
    for p in paths:
        out.extend(_load_pem_bundle(open(p, "rb").read()))
    return out

def load_trusted(path: str) -> list[x509.Certificate]:
    return _load_pem_bundle(open(path, "rb").read())

def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(child.signature_hash_algorithm))
    else:
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)

def _check_validity(cert, at: datetime, label: str) -> None:
    if not (cert.not_valid_before_utc <= at <= cert.not_valid_after_utc):
        raise ValueError(f"{label}: not valid at {at.isoformat()}")

def _check_ca(cert, expect_ca: bool, label: str) -> Optional[int]:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        if expect_ca:
            raise ValueError(f"{label}: CA cert without BasicConstraints")
        return None
    if bc.ca != expect_ca:
        raise ValueError(f"{label}: BasicConstraints.ca={bc.ca}, expected {expect_ca}")
    if expect_ca:
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not ku.key_cert_sign:
                raise ValueError(f"{label}: CA cert without keyCertSign")
        except x509.ExtensionNotFound:
            pass
    return bc.path_length

def build_chain(leaf: x509.Certificate,
                untrusted: list[x509.Certificate],
                trusted: list[x509.Certificate]) -> list[x509.Certificate]:
    trusted_by_subject = {c.subject.rfc4514_string(): c for c in trusted}
    pool = list(untrusted)

    chain = [leaf]
    current = leaf
    seen = {current.subject.rfc4514_string()}
    while True:
        issuer_dn = current.issuer.rfc4514_string()
        if issuer_dn in trusted_by_subject:
            chain.append(trusted_by_subject[issuer_dn])
            return chain
        candidate = next((c for c in pool
                          if c.subject.rfc4514_string() == issuer_dn), None)
        if candidate is None:
            raise ValueError(
                f"No issuer found for {current.subject.rfc4514_string()} "
                f"(issuer={issuer_dn})"
            )
        if candidate.subject.rfc4514_string() in seen:
            raise ValueError("Certificate loop detected while building chain")
        seen.add(candidate.subject.rfc4514_string())
        chain.append(candidate)
        current = candidate

def validate_path(*, leaf_path: str, untrusted_paths: list[str],
                  trusted_path: str,
                  validation_time: Optional[datetime] = None,
                  check_revocation: bool = False,
                  crl_arg: Optional[str] = None,
                  ocsp: bool = False) -> ValidationResult:
    res = ValidationResult(ok=False)
    at = validation_time or datetime.now(timezone.utc)
    
    try:
        leaf = x509.load_pem_x509_certificate(open(leaf_path, "rb").read(),
                                          default_backend())
        untrusted = load_untrusted(untrusted_paths)
        trusted = load_trusted(trusted_path)
    except Exception as e:
        res.add("load", False, str(e))
        return res

    try:
        chain = build_chain(leaf, untrusted, trusted)
        res.add("build_chain", True,
                f"path length={len(chain)}")
    except ValueError as e:
        res.add("build_chain", False, str(e))
        return res

    for i, cert in enumerate(chain[:-1]):
        issuer = chain[i + 1]
        label = f"cert[{i}] {cert.subject.rfc4514_string()}"
        try:
            _verify_signature(cert, issuer)
            res.add(f"signature[{i}]", True)
        except Exception as e:
            res.add(f"signature[{i}]", False, f"{label}: {e}")
            return res
        try:
            _check_validity(cert, at, label)
            res.add(f"validity[{i}]", True)
        except ValueError as e:
            res.add(f"validity[{i}]", False, str(e))  
            return res

    for i, cert in enumerate(chain):
        is_leaf = (i == 0)
        is_root = (i == len(chain) - 1)

        if is_root:
            res.add(f"basic_constraints[{i}]", True, "trust anchor, skipped")
            continue

        expect_ca = not is_leaf
        label = f"cert[{i}] {cert.subject.rfc4514_string()}"
        try:
            pathlen = _check_ca(cert, expect_ca=expect_ca, label=label)
            res.add(f"basic_constraints[{i}]", True)
        except ValueError as e:
            res.add(f"basic_constraints[{i}]", False, str(e))
            return res

        if expect_ca and pathlen is not None:
            subordinates = i - 1
            if subordinates > pathlen:
                res.add(f"pathlen[{i}]", False,
                        f"{label}: pathLenConstraint={pathlen}, "
                        f"subordinates={subordinates}")
                return res
            res.add(f"pathlen[{i}]", True)

    if check_revocation:
        status = check_status_with_fallback(
            leaf_path=leaf_path, ca_cert_path=untrusted_paths[0],
            crl_arg=crl_arg, ocsp=ocsp,
        )
        res.add("revocation", status["status"] == "good",
                f"status={status['status']} source={status['source']}")
        if status["status"] != "good":
            return res

    res.ok = True
    log_event(logger, logging.INFO, "Path validation succeeded",
              leaf=leaf.subject.rfc4514_string(), steps=len(res.steps))
    return res
