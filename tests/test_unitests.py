import pytest
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

def test_rsa_key_gen():
    from micropki.crypto_utils import gen_rsa_key
    
    key = gen_rsa_key(key_size=4096)
    
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 4096

def test_ecc_key_gen():
    from micropki.crypto_utils import gen_ecc_key
    
    key = gen_ecc_key(curve=ec.SECP384R1())
    
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.key_size == 384

def test_keygen():
    from micropki.crypto_utils import keygen
    
    rsa_key = keygen(key_type="rsa", key_size=4096)
    assert isinstance(rsa_key, rsa.RSAPrivateKey)
    
    ecc_key = keygen(key_type="ecc", key_size=384)
    assert isinstance(ecc_key, ec.EllipticCurvePrivateKey)

def test_parse_dn_slash():
    from micropki.certificates import parse_subject_dn
    
    dn = parse_subject_dn("/CN=Test CA/O=Test Org/C=US")
    
    assert len(dn) == 3
    assert "CN=Test CA" in dn.rfc4514_string()

def test_parse_dn_comma():
    from micropki.certificates import parse_subject_dn
    
    dn = parse_subject_dn("CN=Test CA, O=Test Org, C=US")
    
    attrs = list(dn)
    assert len(attrs) == 3

def test_key_enc_dec(temp_dir):
    from micropki.crypto_utils import gen_rsa_key, enc_pvt_key
    from cryptography.hazmat.primitives import serialization
    
    key = gen_rsa_key(4096)
    passphrase = b"TestPass123"
    
    encrypted = enc_pvt_key(key, passphrase)
    assert isinstance(encrypted, bytes)
    assert b"ENCRYPTED" in encrypted
    
    decrypted_key = serialization.load_pem_private_key(
        encrypted, password=passphrase
    )
    assert decrypted_key is not None

def test_log(temp_dir):
    from micropki.logger import setup_logger, log_event
    import logging

    log_path = temp_dir / "test_audit.log"
    logger = setup_logger(log_path=str(log_path))
    log_event(logger, logging.INFO, "test message")

    assert log_path.exists()
    assert "test message" in log_path.read_text()
