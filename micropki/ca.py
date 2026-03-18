import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from typing import Optional
from .crypto_utils import (gen_rsa_key, enc_pvt_key, save_file, setup_directories)
from .certificates import create_rootca_cert

class RootCA:
    def __init__(self, out_dir: str):
        self.out_dir = Path(out_dir).expanduser().resolve()
        self.pvt_dir, self.certs_dir = setup_directories(self.out_dir)
        
        self.key_path = self.pvt_dir / "ca.key.pem"
        self.cert_path = self.certs_dir / "ca.cert.pem"

    def initialize(self, subject: str, passphrase: bytes, validity_days: int = 3650) -> bool:
        if self.key_path.exists() or self.cert_path.exists():
            raise FileExistsError("CA already initialized. Remove existing files to reinitialize.")

        try:
            pvt_key = gen_rsa_key(4096)
            encd_key = enc_pvt_key(pvt_key, passphrase)
            save_file(self.key_path, encd_key, file_mode=0o600)
            certificate = create_rootca_cert(private_key=pvt_key, subject_dn=subject, validity_days=validity_days)
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            save_file(self.cert_path, cert_pem, file_mode=0o644)
            
            return True
            
        except Exception as e:
            raise e

    def load_key(self, passphrase: bytes):
        if not self.key_path.exists():
            raise FileNotFoundError("CA private key not found")
            
        with open(self.key_path, "rb") as f:
            key_data = f.read()
            
        return serialization.load_pem_private_key(key_data, password=passphrase, backend=default_backend())
