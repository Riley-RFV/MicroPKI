import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from typing import Optional
from .crypto_utils import (gen_rsa_key, enc_pvt_key, save_file, setup_dirs, keygen, policy)
from .certificates import create_rootca_cert
import logging
from .logger import log_event
from datetime import timezone

logger = logging.getLogger("pki_audit")

class RootCA:
    def __init__(self, out_dir: str):
        self.out_dir = Path(out_dir).expanduser().resolve()
        self.pvt_dir, self.certs_dir, self.policy_path = setup_dirs(self.out_dir)
        pol_path=self.policy_path
        
        self.key_path = self.pvt_dir / "ca.key.pem"
        self.cert_path = self.certs_dir / "ca.cert.pem"
        logger.info(f"RootCA instance initialized for directory: {self.out_dir}")

    def initialize(self, subject: str, key_type: str, passphrase: bytes, key_size: int = 4096, validity_days: int = 3650) -> bool:
        if self.key_path.exists() or self.cert_path.exists():
            log_event(logger, logging.WARNING, "CA initialization failed: files already exist", out_dir=str(self.out_dir))
            raise FileExistsError("CA already initialized. Remove existing files to reinitialize.")

        try:
            log_event(logger, logging.INFO, "Starting CA initialization process", 
                      key_type=key_type, key_size=key_size, subject=subject)
            pvt_key = keygen(key_type=key_type, key_size=key_size)
            log_event(logger, logging.INFO, "Private key generation is successfull")
            encd_key = enc_pvt_key(pvt_key, passphrase)
            log_event(logger, logging.INFO, "Private key encrypted and saved", 
                      key_path=str(self.key_path), permissions="0600")
            save_file(self.key_path, encd_key, file_mode=0o600)
            certificate = create_rootca_cert(private_key=pvt_key, subject_dn=subject, validity_days=validity_days)
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            save_file(self.cert_path, cert_pem, file_mode=0o644)
            log_event(logger, logging.INFO, "Root CA certificate generated and saved", 
                      cert_path=str(self.cert_path), serial_number=hex(certificate.serial_number))
            a=subject
            if "CN=" in subject:
                a = subject.split("CN=")[1].split(",")[0].split("/")[0]
            policy(policy_path=self.policy_path, ca_name=a, serial=hex(certificate.serial_number),
                   date_bf=certificate.not_valid_before_utc,
                   date_af=certificate.not_valid_after_utc,
                   key_type=key_type, key_size=pvt_key.key_size)
            log_event(logger, logging.INFO, "CA initialization is successfull", ca_name=a, validity_days=validity_days)
            return True
            
        except Exception as e:
            log_event(logger, logging.ERROR, "CA initialization failed", error_type=type(e).__name__, error_message=str(e))
            if self.key_path.exists():
                self.key_path.unlink()
            if self.cert_path.exists():
                self.cert_path.unlink()
            raise e

    def load_key(self, passphrase: bytes):
        if not self.key_path.exists():
            log_event(logger, logging.ERROR, "Failed to load key: file not found", key_path=str(self.key_path))
            raise FileNotFoundError("CA private key not found")

        try:
            with open(self.key_path, "rb") as f:
                key_data = f.read()
            key = serialization.load_pem_private_key(key_data, password=passphrase, backend=default_backend())
            log_event(logger, logging.INFO, "Private key loading is successfull")
            return key

        except Exception as e:
            log_event(logger, logging.ERROR, "Failed to decrypt orr load private key", error_message=str(e))
            raise e
