import os
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

def parse_subject_dn(dn_string: str) -> x509.Name:
    attributes = []

    if dn_string.startswith('/'):
        dn_string = dn_string[1:]
    if '/' in dn_string:
        parts = dn_string.split('/')
    else:
        parts = dn_string.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            continue
        
        key, value = part.split('=', 1)
        key = key.strip().upper()
        value = value.strip()
        
        oid_map = {
            'CN': NameOID.COMMON_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME}
        
        if key in oid_map:
            attributes.append(x509.NameAttribute(oid_map[key], value))
            
    return x509.Name(attributes)

def compute_skid(pub_key) -> bytes:
    der_bytes = pub_key.public_bytes(encoding=serialization.Encoding.DER, 
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha1(der_bytes).digest()

def create_rootca_cert(private_key: rsa.RSAPrivateKey, subject_dn: str, validity_days: int = 3650) -> x509.Certificate:
    subject = parse_subject_dn(subject_dn)
    issuer = subject  # Self-signed
    
    now = datetime.now(timezone.utc)
    not_before = now
    not_after = now + timedelta(days=validity_days)
    serial_number = x509.random_serial_number()

    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(serial_number).not_valid_before(not_before).not_valid_after(not_after))

    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, 
                                                  content_commitment=False, 
                                                  key_encipherment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  key_cert_sign=True,
                                                  crl_sign=True,
                                                  encipher_only=False,
                                                  decipher_only=False), critical=True)
    skid = compute_skid(private_key.public_key())
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())), critical=False)
    
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    
    return certificate
