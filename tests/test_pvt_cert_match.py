import pytest
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path

def test_key_cert_match_sign(ca_initialized):
    from micropki.ca import RootCA
    from cryptography.hazmat.primitives import serialization
    
    ca = ca_initialized['ca']
    passphrase = ca_initialized['passphrase']
    cert_path = ca_initialized['cert_path']
    
    private_key = ca.load_key(passphrase)
    
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    from cryptography import x509
    certificate = x509.load_pem_x509_certificate(cert_data)
    public_key = certificate.public_key()
    
    test_message = b"PKI Test Message for Key-Cert Matching"
    
    signature = private_key.sign(
        test_message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    try:
        public_key.verify(
            signature,
            test_message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        assert True, "Signature verification succeeded"
    except Exception as e:
        pytest.fail(f"Signature verification failed: {e}")

def test_key_cert_modulus_match(ca_initialized):
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    
    ca = ca_initialized['ca']
    passphrase = ca_initialized['passphrase']
    cert_path = ca_initialized['cert_path']
    
    private_key = ca.load_key(passphrase)
    
    with open(cert_path, "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read())
    
    priv_pub_key = private_key.public_key()
    cert_pub_key = certificate.public_key()
    
    priv_numbers = priv_pub_key.public_numbers()
    cert_numbers = cert_pub_key.public_numbers()
    
    assert priv_numbers.n == cert_numbers.n, "RSA modulus mismatch"
    assert priv_numbers.e == cert_numbers.e, "RSA exponent mismatch"

