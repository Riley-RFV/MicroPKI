import hashlib
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import logging
from .logger import log_event

logger = logging.getLogger("pki_audit")
OID_MAP = {
            'CN': NameOID.COMMON_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME,
}

def parse_subject_dn(dn_string: str) -> x509.Name:
    log_event(logger, logging.INFO, "Parsing Subject DN", input_dn=dn_string)
    
    if not dn_string or not dn_string.strip():
        raise ValueError("Subject DN must be a non-empty string")

    s = dn_string.strip()
    if s.startswith('/'):
      s = s[1:]
      parts = s.split('/')
    else:
        parts = s.split(',')

    attributes = []
    unknown_keys = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            raise ValueError(f"Invalid DN attribute (missing '='): {part!r}")
        key, value = part.split('=', 1)
        key = key.strip().upper()
        value = value.strip()
        if not value:
            raise ValueError(f"Empty value for DN attribute {key!r}")
        if key not in OID_MAP:
            unknown_keys.append(key)
            continue
        attributes.append(x509.NameAttribute(OID_MAP[key], value))

    if unknown_keys:
        raise ValueError(f"Unsupported DN attribute(s): {', '.join(unknown_keys)}")
    if not attributes:
        raise ValueError("No valid DN attributes found in subject string")

    seen = set()
    for attr in attributes:
        if attr.oid in seen:
            raise ValueError(f"Duplicate DN attribute: {attr.oid._name}")
        seen.add(attr.oid)

    log_event(logger, logging.INFO, "Subject DN parsing is successful",
              attributes_count=len(attributes))
    return x509.Name(attributes)

def create_rootca_cert(private_key: rsa.RSAPrivateKey, subject_dn: str, validity_days: int = 3650) -> private_key:
    log_event(logger, logging.INFO, "Building Root CA certificate", validity_days=validity_days)
    subject = parse_subject_dn(subject_dn)
    issuer = subject
    
    now = datetime.now(timezone.utc)
    not_before = now
    not_after = now + timedelta(days=validity_days)
    serial_number = x509.random_serial_number()
    log_event(logger, logging.INFO, "Certificate details prepared", serial_number=hex(serial_number),
              not_before=not_before.isoformat(), not_after=not_after.isoformat())
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(serial_number).not_valid_before(not_before).not_valid_after(not_after))

    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    log_event(logger, logging.INFO, "Extension is added: BasicConstraints (CA=True)")
    
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, 
                                                  content_commitment=False, 
                                                  key_encipherment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  key_cert_sign=True,
                                                  crl_sign=True,
                                                  encipher_only=False,
                                                  decipher_only=False), critical=True)
    log_event(logger, logging.INFO, "Added extension: KeyUsage")
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    log_event(logger, logging.INFO, "Added extension: SubjectKeyIdentifier")
    
    builder = builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    ),
    critical=False,
)    
    log_event(logger, logging.INFO, "Added extension: AuthorityKeyIdentifier")
    
    try:
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature_algorithm = hashes.SHA256()
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature_algorithm = hashes.SHA384()
        else:
            raise TypeError(f"Unsupported private key type: {type(private_key).__name__}")

        certificate = builder.sign(private_key=private_key, algorithm=signature_algorithm, backend=default_backend())
        log_event(logger, logging.INFO, "Certificate signed successfully", serial_number=hex(serial_number))
        return certificate

    except Exception as e:
        log_event(logger, logging.ERROR, "Failed to sign certificate", error=str(e))
        raise e
