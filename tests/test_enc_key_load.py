import pytest
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path

def test_enck_load_correct_pass(ca_initialized):
    ca = ca_initialized['ca']
    passphrase = ca_initialized['passphrase']
    
    private_key = ca.load_key(passphrase)
    assert private_key is not None
    assert hasattr(private_key, 'private_numbers')

def test_enck_load_wrong_pass(ca_initialized, inv_passphrase_file):
    ca = ca_initialized['ca']
    wrong_passphrase = inv_passphrase_file.read_bytes()
    
    from cryptography.fernet import InvalidToken
    from cryptography.exceptions import UnsupportedAlgorithm
    
    with pytest.raises(Exception):
        ca.load_key(wrong_passphrase)

def test_enck_sign(ca_initialized):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    
    ca = ca_initialized['ca']
    passphrase = ca_initialized['passphrase']
    
    private_key = ca.load_key(passphrase)
    
    test_data = b"Test signing operation"
    signature = private_key.sign(
        test_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    assert len(signature) > 0
    assert isinstance(signature, bytes)
