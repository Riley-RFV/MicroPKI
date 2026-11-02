import logging
from typing import Iterable
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .logger import log_event
from .san import parse_san

logger = logging.getLogger("pki_audit")

VALID_TEMPLATES = {"server", "client", "code_signing", "ocsp"}

def _basic_constraints_leaf() -> x509.BasicConstraints:
    return x509.BasicConstraints(ca=False, path_length=None)

def _key_usage_for(template: str, key) -> x509.KeyUsage:
    is_rsa = isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey))
    common = dict(
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    if template == "server":
        return x509.KeyUsage(digital_signature=True, key_encipherment=is_rsa, **common)
    if template == "client":
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=not is_rsa,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(digital_signature=True, key_encipherment=False, **common)

def _key_usage_for_ocsp() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

def build_template_extensions(template: str, key, sans: list[str]) -> list[tuple[x509.ExtensionType, bool]]:
    if template not in VALID_TEMPLATES:
        raise ValueError(f"Unknown template {template!r}; allowed: {sorted(VALID_TEMPLATES)}")

    log_event(logger, logging.INFO, "Building template extensions",
              template=template, san_count=len(sans))

    san_ext = parse_san(sans, template)
    if template == "server" and san_ext is None:
        raise ValueError("Server certificate requires at least one --san (dns: or ip:)")

    eku_map = {
        "server":       ExtendedKeyUsageOID.SERVER_AUTH,
        "client":       ExtendedKeyUsageOID.CLIENT_AUTH,
        "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    }

    extensions: list[tuple[x509.ExtensionType, bool]] = [
        (_basic_constraints_leaf(), True),
        (_key_usage_for(template, key), True),
        (x509.ExtendedKeyUsage([eku_map[template]]), False),
    ]
    if san_ext is not None:
        extensions.append((san_ext, False))

    log_event(logger, logging.INFO, "Template extensions built",
              template=template, extensions=[type(e).__name__ for e, _ in extensions])
    return extensions

def build_ocsp_cert_extensions(key, sans: list[str]):
    exts = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (_key_usage_for_ocsp(), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False),
    ]
    if sans:
        gn = []
        for raw in sans:
            kind, value = raw.split(":", 1)
            kind = kind.strip().lower()
            if kind == "dns":
                gn.append(x509.DNSName(value))
            elif kind == "uri":
                gn.append(x509.UniformResourceIdentifier(value))
            else:
                raise ValueError(f"OCSP cert SAN must be dns: or uri:, got {raw!r}")
        exts.append((x509.SubjectAlternativeName(gn), False))
    return exts
