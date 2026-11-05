import logging
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("pki_audit")

class PolicyViolation(ValueError):
    pass

MAX_VALIDITY = {
    "root": 3650,
    "intermediate": 1825,
    "leaf": 365,
}

def check_rsa_size(key_size: int, role: str) -> None:
    if role == "root":
        if key_size < 4096:
            raise PolicyViolation(f"Root CA RSA key must be >= 4096 bits (got {key_size})")
    elif role == "intermediate":
        if key_size < 3072:
            raise PolicyViolation(f"Intermediate CA RSA key must be >= 3072 bits (got {key_size})")
    else:
        if key_size < 2048:
            raise PolicyViolation(f"Leaf RSA key must be >= 2048 bits (got {key_size})")

def check_ecc_size(curve, role: str) -> None:
    size = getattr(curve, "key_size", None)
    if role in ("root", "intermediate"):
        if size is None or size < 384:
            raise PolicyViolation(f"{role} CA ECC curve must be >= P-384 (got {size})")
    else:
        if size is None or size < 256:
            raise PolicyViolation(f"Leaf ECC curve must be >= P-256 (got {size})")

def check_validity(days: int, role: str) -> None:
    limit = MAX_VALIDITY.get(role, 365)
    if days <= 0:
        raise PolicyViolation(f"validity_days must be positive (got {days})")
    if days > limit:
        raise PolicyViolation(
            f"{role} validity {days}d exceeds policy max {limit}d"
        )

def check_san(ext_san: x509.SubjectAlternativeName, template: str,
              *, allow_wildcard: bool = False) -> None:
    if template == "server":
        for d in ext_san.get_values_for_type(x509.DNSName):
            if "*." in d and not allow_wildcard:
                raise PolicyViolation(f"Wildcard SAN not allowed: {d}")
        for em in ext_san.get_values_for_type(x509.RFC822Name):
            raise PolicyViolation("server template: email SAN not allowed")
        for uri in ext_san.get_values_for_type(x509.UniformResourceIdentifier):
            raise PolicyViolation("server template: URI SAN not allowed")
    elif template == "client":
        emails = ext_san.get_values_for_type(x509.RFC822Name)
        if not emails:
            raise PolicyViolation("client template: at least one email SAN required")
    elif template == "code_signing":
        for d in ext_san.get_values_for_type(x509.DNSName):
            if "*." in d and not allow_wildcard:
                raise PolicyViolation(f"Wildcard SAN not allowed: {d}")
        for ip in ext_san.get_values_for_type(x509.IPAddress):
            raise PolicyViolation("code_signing template: IP SAN not allowed")
        for em in ext_san.get_values_for_type(x509.RFC822Name):
            raise PolicyViolation("code_signing template: email SAN not allowed")

def check_csr_signature_alg(csr: x509.CertificateSigningRequest) -> None:
    alg = csr.signature_hash_algorithm
    if alg is None:
        raise PolicyViolation("CSR signature algorithm missing")
    if alg.name.lower() in ("sha1", "md5"):
        raise PolicyViolation(f"CSR signature algorithm {alg.name} is not allowed")

def check_pathlen(pathlen: int, role: str) -> None:
    if role == "intermediate" and pathlen > 0:
        raise PolicyViolation(
            f"Intermediate CA pathLenConstraint must be 0 (got {pathlen}); "
            "subordinate CAs are not allowed"
        )
