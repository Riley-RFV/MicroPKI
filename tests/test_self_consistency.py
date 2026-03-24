import pytest
import subprocess
from pathlib import Path

def test_cert_openssl(ca_initialized):
    cert_path = ca_initialized['cert_path']
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(cert_path), str(cert_path)],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, f"OpenSSL verify failed: {result.stderr}"
    assert "OK" in result.stdout, f"Expected 'OK' in output, got: {result.stdout}"

def test_cert_exts(ca_initialized):
    cert_path = ca_initialized['cert_path']
    
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    output = result.stdout
    
    assert "CA:TRUE" in output, "BasicConstraints CA:TRUE not found"
    assert "Certificate Sign" in output, "Key Cert Sign usage not found"
    assert "CRL Sign" in output, "CRL Sign usage not found"

