import logging
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .logger import log_event

logger = logging.getLogger("pki_audit")

def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(child.signature_hash_algorithm))
    else:
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)


def _check_validity(cert: x509.Certificate, label: str) -> None:
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError(f"{label} certificate is not valid at {now.isoformat()}")


def _check_ca_flag(cert: x509.Certificate, label: str, expect_ca: bool) -> int | None:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as e:
        raise ValueError(f"{label} has no BasicConstraints") from e
    if bc.ca != expect_ca:
        raise ValueError(f"{label}: BasicConstraints.ca={bc.ca}, expected {expect_ca}")
    return bc.path_length


def verify_chain(leaf_path: str, intermediate_path: str, root_path: str) -> bool:
    leaf = x509.load_pem_x509_certificate(Path(leaf_path).read_bytes(), default_backend())
    inter = x509.load_pem_x509_certificate(Path(intermediate_path).read_bytes(), default_backend())
    root = x509.load_pem_x509_certificate(Path(root_path).read_bytes(), default_backend())

    _verify_signature(leaf, inter)
    _verify_signature(inter, root)
    _check_validity(leaf, "leaf")
    _check_validity(inter, "intermediate")
    _check_validity(root, "root")

    _check_ca_flag(leaf, "leaf", expect_ca=False)
    inter_pathlen = _check_ca_flag(inter, "intermediate", expect_ca=True)
    _check_ca_flag(root, "root", expect_ca=True)

    # pathLenConstraint on intermediate must allow leaf (i.e. >= 0).
    if inter_pathlen is not None and inter_pathlen < 0:
        raise ValueError("Intermediate pathLenConstraint < 0")

    log_event(logger, logging.INFO, "Chain verified successfully",
              leaf=leaf.subject.rfc4514_string(),
              intermediate=inter.subject.rfc4514_string(),
              root=root.subject.rfc4514_string())
    return True
