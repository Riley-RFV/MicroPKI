import pytest
import subprocess
import tempfile
from pathlib import Path

def test_cert_structure(ca_initialized):
    cert_path = ca_initialized['cert_path']

    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, f"OpenSSL cannot read certificate: {result.stderr}"
    assert "CN" in result.stdout or "subject" in result.stdout.lower()

def test_cert_serial(ca_initialized):
    cert_path = ca_initialized['cert_path']
    
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    assert "serial=" in result.stdout.lower()

def test_cert_dates(ca_initialized):
    cert_path = ca_initialized['cert_path']
    
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates"],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    assert "notBefore=" in result.stdout
    assert "notAfter=" in result.stdout

def test_openssl_vs_gened_cert_(ca_initialized):
    temp_dir = ca_initialized['out_dir']

    openssl_key = temp_dir / "openssl.key"
    openssl_cert = temp_dir / "openssl.crt"
    
    subprocess.run([
        "openssl", "genrsa",
        "-out", str(openssl_key),
        "4096"
    ], check=True, capture_output=True)
    
    subprocess.run([
        "openssl", "req",
        "-new", "-x509",
        "-key", str(openssl_key),
        "-out", str(openssl_cert),
        "-days", "365",
        "-subj", "/CN=OpenSSL Test CA"
    ], check=True, capture_output=True)
    
    our_cert = ca_initialized['cert_path']
    
    our_verify = subprocess.run(
        ["openssl", "verify", "-CAfile", str(our_cert), str(our_cert)],
        capture_output=True, text=True
    )
    
    openssl_verify = subprocess.run(
        ["openssl", "verify", "-CAfile", str(openssl_cert), str(openssl_cert)],
        capture_output=True, text=True
    )
    
    assert "OK" in our_verify.stdout, "Our cert should verify"
    assert "OK" in openssl_verify.stdout, "OpenSSL cert should verify"
