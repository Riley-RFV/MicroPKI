import os
import stat
import warnings
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def gen_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())

def enc_pvt_key(key: rsa.RSAPrivateKey, passphrase: bytes) -> bytes:
    return key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, 
                         encryption_algorithm=serialization.BestAvailableEncryption(passphrase))

def save_file(path: Path, data: bytes, file_mode: int = 0o600):
    supports_unix_permissions = hasattr(os, 'chmod') and os.name != 'nt'

    with open(path, "wb") as f:
        f.write(data)

    if supports_unix_permissions:
        os.chmod(path, file_mode)
    else:
        warnings.warn(f"OS does not support Unix permissions. File {path} may be accessible to other users.",RuntimeWarning)

def setup_directories(out_dir: Path) -> tuple[Path, Path]:
    pvt_dir = out_dir / "private"
    certs_dir = out_dir / "certs"

    if not pvt_dir.exists():
        pvt_dir.mkdir(parents=True, mode=0o700)
        if os.name != 'nt':
            os.chmod(pvt_dir, 0o700)
    else:
        if os.name != 'nt':
            os.chmod(pvt_dir, 0o700)

    certs_dir.mkdir(parents=True, exist_ok=True)

    # Плэйсхолдер policy.txt
    policy_file = out_dir / "policy.txt"
    if not policy_file.exists():
        policy_file.write_text("Certificate Policy Document\nVersion: 1.0\n")

    return pvt_dir, certs_dir
