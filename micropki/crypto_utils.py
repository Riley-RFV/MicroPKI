import os
import stat
import warnings
from pathlib import Path
from datetime import datetime
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import logging
from .logger import setup_logger, log_event

logger= setup_logger()

def gen_rsa_key(key_size) -> rsa.RSAPrivateKey:
    log_event(logger, logging.INFO, "Generating RSA private key", key_size=key_size)
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        log_event(logger, logging.INFO, "RSA private key generation is successful", key_size=key_size)
        return key
    except Exeption as e:
        log_event(logger, logging.ERROR, "Failed to generate RSA key", error=str(e))
        raise e

def gen_ecc_key(ccurve) -> ec.EllipticCurvePrivateKey:
    log_event(logger, logging.INFO, "Generating ECC private key")
    try:
        key = ec.generate_private_key(ccurve, backend=default_backend())
        return key
    except Exception as e:
        log_event(logger, logging.ERROR, "Failed to generate ECC key", error=str(e))
        raise e

def enc_pvt_key(key: rsa.RSAPrivateKey | ec.EllipticPrivateKey, passphrase: bytes) -> bytes:
    log_event(logger, logging.INFO, "Encrypting private key with passphrase")
    try:
        pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.BestAvailableEncryption(passphrase))
        log_event(logger, logging.INFO, "Private key encryption is successfull")
        return pem
    except Exception as e:
        log_event(logger, logging.ERROR, "Failed to encrypt private key", error=str(e))
        raise e

def keygen(key_type="rsa", key_size=4096):
    log_event(logger, logging.INFO, "Key generation requested", key_type=key_type, key_size=key_size)
    if key_type=="rsa" and key_size == 4096:
        return gen_rsa_key(key_size)
    elif key_type=="ecc" and key_size == 384:
        return gen_ecc_key(ec.SECP384R1())
    else:
        log_event(logger, logging.ERROR, "Unsupported key_type or key_size requested", key_type=key_type)
        raise ValueError("Unappropriate key_type or key_size: type -- {key_type}, size -- {key_size}")

def save_file(path: Path, data: bytes, file_mode: int = 0o600):
    supports_unix_permissions = hasattr(os, 'chmod') and os.name != 'nt'
    log_event(logger, logging.INFO, "Saving file to disk", path=str(path), mode=oct(file_mode))

    with open(path, "wb") as f:
        f.write(data)

    if supports_unix_permissions:
        os.chmod(path, file_mode)
        log_event(logger, logging.INFO, "File permissions set", path=str(path), permissions=oct(file_mode))
    else:
        warnings.warn(f"OS does not support Unix permissions. File {path} may be accessible to other users.",RuntimeWarning)
        log_event(logger, logging.WARNING, "Could not set Unix permissions", path=str(path), os=os.name)

def setup_dirs(out_dir: Path) -> tuple[Path, Path]:
    pvt_dir = out_dir / "private"
    certs_dir = out_dir / "certs"

    log_event(logger, logging.INFO, "Setting up PKI directory structure", base_dir=str(out_dir))
    if not pvt_dir.exists():
        pvt_dir.mkdir(parents=True, mode=0o700)
        if os.name != 'nt':
            os.chmod(pvt_dir, 0o700)
        log_event(logger, logging.INFO, "Pivate directory is created", path=str(pvt_dir))
    else:
        if os.name != 'nt':
            os.chmod(pvt_dir, 0o700)
        log_event(logger, logging.INFO, "Private directory already exists", path=str(pvt_dir))

    certs_dir.mkdir(parents=True, exist_ok=True)
    log_event(logger, logging.INFO, "Certificates directory is created", path=str(certs_dir))
    policy_file = out_dir/"policy.txt"

    return pvt_dir, certs_dir, policy_file

def policy(policy_path: Path, ca_name: str, serial: str, date_bf: datetime, date_af: datetime, key_type: str, key_size: int):
    log_event(logger, logging.INFO, "Generating policy document", ca_name=ca_name, serial=serial)
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
    try:
        with open(policy_path, "w", encoding='utf-8') as f:
            f.write(text)
        log_event(logger, logging.INFO, "Policy document is saved", path=str(policy_path))
    except Exception as e:
        log_event(logger, logging.ERROR, "Failed to write policy document", error=str(e))
        raise e
