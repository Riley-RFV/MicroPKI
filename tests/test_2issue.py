import os
import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from s2_fixt import run_cli, clean

def test_intermediate_files_exist(intermediate):
    """PKI-10 + KEY-5: files are named and placed correctly."""
    assert intermediate["cert"].exists()
    assert intermediate["key"].exists()
    assert intermediate["cert"].name == "intermediate.cert.pem"
    assert intermediate["key"].name == "intermediate.key.pem"


def test_intermediate_key_permissions(intermediate):
    if os.name == "nt":
        pytest.skip("Unix permissions")
    assert (intermediate["key"].stat().st_mode & 0o777) == 0o600


def test_intermediate_key_encrypted(intermediate, passphrase_file):
    from micropki.crypto_utils import load_encrypted_key
    with pytest.raises(Exception):
        load_encrypted_key(intermediate["key"], b"wrong-passphrase")
    key = load_encrypted_key(intermediate["key"], intermediate["pass"])
    assert key is not None


def test_issue_server_cert(intermediate, temp_dir):
    from micropki.ca import RootCA
    ca = RootCA(str(temp_dir), create_layout=False)
    cert = ca.issue_cert(
        ca_cert_path=str(intermediate["cert"]),
        ca_key_path=str(intermediate["key"]),
        ca_passphrase=intermediate["pass"],
        template="server",
        subject="CN=example.com,O=Test Org",
        sans=["dns:example.com", "dns:www.example.com", "ip:192.168.1.10"],
        out_dir=str(temp_dir / "leaf"),
        validity_days=365,
        key_type="rsa",
    )
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "example.com" in san.get_values_for_type(x509.DNSName)
    assert "www.example.com" in san.get_values_for_type(x509.DNSName)

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    leaf_cert = temp_dir / "leaf" / "example.com.cert.pem"
    leaf_key = temp_dir / "leaf" / "example.com.key.pem"
    assert leaf_cert.exists()
    assert leaf_key.exists()


def test_leaf_key_unencrypted_and_0600(intermediate, temp_dir):
    from micropki.ca import RootCA
    ca = RootCA(str(temp_dir), create_layout=False)
    ca.issue_cert(
        ca_cert_path=str(intermediate["cert"]),
        ca_key_path=str(intermediate["key"]),
        ca_passphrase=intermediate["pass"],
        template="server",
        subject="CN=plain.example.com",
        sans=["dns:plain.example.com"],
        out_dir=str(temp_dir / "leaf"),
        validity_days=365,
        key_type="rsa",
    )
    key_path = temp_dir / "leaf" / "plain.example.com.key.pem"
    pem = key_path.read_bytes()
    assert b"ENCRYPTED" not in pem  # unencrypted
    if os.name != "nt":
        assert (key_path.stat().st_mode & 0o777) == 0o600


def test_leaf_ecc_key(intermediate, temp_dir):
    from micropki.ca import RootCA
    from cryptography.hazmat.primitives import serialization
    ca = RootCA(str(temp_dir), create_layout=False)
    ca.issue_cert(
        ca_cert_path=str(intermediate["cert"]),
        ca_key_path=str(intermediate["key"]),
        ca_passphrase=intermediate["pass"],
        template="client",
        subject="CN=ecc.example.com",
        sans=["email:a@b.c"],
        out_dir=str(temp_dir / "leaf"),
        validity_days=365,
        key_type="ecc",
    )
    key_path = temp_dir / "leaf" / "ecc.example.com.key.pem"
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    assert key.curve.key_size == 256


def test_leaf_issuer_is_intermediate(intermediate, temp_dir):
    from micropki.ca import RootCA
    from micropki.crypto_utils import load_certificate
    ca = RootCA(str(temp_dir), create_layout=False)
    cert = ca.issue_cert(
        ca_cert_path=str(intermediate["cert"]),
        ca_key_path=str(intermediate["key"]),
        ca_passphrase=intermediate["pass"],
        template="server",
        subject="CN=issuer.example.com",
        sans=["dns:issuer.example.com"],
        out_dir=str(temp_dir / "leaf"),
        validity_days=365,
        key_type="rsa",
    )
    inter_cert = load_certificate(intermediate["cert"])
    assert cert.issuer == inter_cert.subject
