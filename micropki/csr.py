import logging
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from .serial import generate_serial

from .certificates import parse_subject_dn
from .logger import log_event

logger = logging.getLogger("pki_audit")

def signature_algorithm_for(key) -> hashes.HashAlgorithm:
    if isinstance(key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384()
    raise TypeError(f"Unsupported key type: {type(key).__name__}")

def build_intermediate_csr(subject: str, private_key, pathlen: int) -> x509.CertificateSigningRequest:
    log_event(logger, logging.INFO, "Building intermediate CSR", subject=subject, pathlen=pathlen)
    dn = parse_subject_dn(subject)

    builder = x509.CertificateSigningRequestBuilder().subject_name(dn)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True,
    )
    csr = builder.sign(private_key=private_key,
                       algorithm=signature_algorithm_for(private_key),
                       backend=default_backend())
    log_event(logger, logging.INFO, "Intermediate CSR built",
              subject=dn.rfc4514_string())
    return csr

def sign_intermediate_csr(csr, root_cert, root_key, validity_days: int, pathlen: int, serial_number: int | None = None) -> x509.Certificate:
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    now = datetime.now(timezone.utc)
    if serial_number is None:
      serial_number = generate_serial()
    serial = serial_number
    intermediate_pub = csr.public_key()

    try:
        root_ski = root_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
    except x509.ExtensionNotFound as e:
        raise ValueError("Root certificate has no SubjectKeyIdentifier") from e

    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski)
    ski = x509.SubjectKeyIdentifier.from_public_key(intermediate_pub)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_pub)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
    )
    cert = builder.sign(
        private_key=root_key,
        algorithm=signature_algorithm_for(root_key),
        backend=default_backend(),
    )
    log_event(logger, logging.INFO, "Intermediate certificate signed",
              serial=hex(serial),
              issuer=root_cert.subject.rfc4514_string(),
              subject=cert.subject.rfc4514_string())
    return cert
