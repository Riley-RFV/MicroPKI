import os
import stat
import warnings
from pathlib import Path
from datetime import datetime
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def gen_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())

def gen_ecc_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(curve=ec.SECP384R1(), backend=default_backend())

def enc_pvt_key(key: rsa.RSAPrivateKey | ec.EllipticPrivateKey, passphrase: bytes) -> bytes:
    return key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, 
                         encryption_algorithm=serialization.BestAvailableEncryption(passphrase))
def keygen(key_type="rsa", key_size=4096):
    if key_type=="rsa":
        return gen_rsa_key(key_size)
    elif key_type=="ecc":
        return gen_ecc_key()
    else:
        raise ValueError("Unsupported key_type: {key_type}")

def save_file(path: Path, data: bytes, file_mode: int = 0o600):
    supports_unix_permissions = hasattr(os, 'chmod') and os.name != 'nt'

    with open(path, "wb") as f:
        f.write(data)

    if supports_unix_permissions:
        os.chmod(path, file_mode)
    else:
        warnings.warn(f"OS does not support Unix permissions. File {path} may be accessible to other users.",RuntimeWarning)

def setup_dirs(out_dir: Path) -> tuple[Path, Path]:
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
    policy_file = out_dir/"policy.txt"

    return pvt_dir, certs_dir, policy_file

def policy(policy_path: Path, ca_name: srt, serial: str, date_bf: datetime, date_af: datetime, key_type: str, key_size: int):
    if key_type.upper() == "RSA":
        key_info = f"RSA-{key_size}"
    elif key_type.upper() == "ECC":
        key_info = f"ECC-P{key_size}"
    else:
        key_info = f"{key_type.upper()}-{key_size}"
    text = f"""Certificate Policy Document
*******************************************
Version: 1.0
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CA Information
--------------
CA Name:      {ca_name}
Certificate Serial Number:    {serial}
Key Algorithm:    {key_info}
Validity Period:  {date_bf.strftime('%Y-%m-%d')} to {date_af.strftime('%Y-%m-%d')}
Valid Days:       {(date_af - date_bf).days}

Certificate Usage
-----------------
Root CA for MicroPKI demonstration!!!
"""
    with open(policy_path, "w", encoding='utf-8') as f:
        f.write(text)
