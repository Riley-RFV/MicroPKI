import pytest
from s2_fixt import run_cli, clean

def test_cli_issue_cert_server_no_san(temp_dir, passphrase_file, root_ca, intermediate):
    result = run_cli([
        "ca", "issue-cert",
        "--ca-cert", str(intermediate["cert"]),
        "--ca-key", str(intermediate["key"]),
        "--ca-pass-file", str(passphrase_file),
        "--template", "server",
        "--subject", "CN=no-san.example.com",
        "--out-dir", str(temp_dir / "leaf"),
    ])
    assert result.returncode != 0
    assert "san" in clean(result.stdout + result.stderr)


def test_cli_issue_cert_code_signing_rejects_ip(temp_dir, passphrase_file, root_ca, intermediate):
    result = run_cli([
        "ca", "issue-cert",
        "--ca-cert", str(intermediate["cert"]),
        "--ca-key", str(intermediate["key"]),
        "--ca-pass-file", str(passphrase_file),
        "--template", "code_signing",
        "--subject", "CN=signer",
        "--san", "ip:1.2.3.4",
        "--out-dir", str(temp_dir / "leaf"),
    ])
    assert result.returncode != 0
    out = clean(result.stdout + result.stderr)
    assert "not allowed" in out or "unsupported" in out


def test_cli_issue_cert_wrong_pass(temp_dir, inv_passphrase_file, root_ca, intermediate):
    result = run_cli([
        "ca", "issue-cert",
        "--ca-cert", str(intermediate["cert"]),
        "--ca-key", str(intermediate["key"]),
        "--ca-pass-file", str(inv_passphrase_file),
        "--template", "server",
        "--subject", "CN=wrongpass.example.com",
        "--san", "dns:wrongpass.example.com",
        "--out-dir", str(temp_dir / "leaf"),
    ])
    assert result.returncode != 0


def test_cli_issue_cert_csr_with_ca_true_rejected(temp_dir, passphrase_file, root_ca, intermediate):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ca-leaf")]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    csr_path = temp_dir / "ca_true.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    result = run_cli([
        "ca", "issue-cert",
        "--ca-cert", str(intermediate["cert"]),
        "--ca-key", str(intermediate["key"]),
        "--ca-pass-file", str(passphrase_file),
        "--template", "server",
        "--subject", "CN=ca-leaf",
        "--san", "dns:ca-leaf.example.com",
        "--csr", str(csr_path),
        "--out-dir", str(temp_dir / "leaf"),
    ])
    if result.returncode != 0:
        return
    issued = temp_dir / "leaf" / "ca-leaf.cert.pem"
    assert issued.exists()
    cert = x509.load_pem_x509_certificate(issued.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
