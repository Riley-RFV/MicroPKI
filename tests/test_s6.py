"""Sprint 6 tests: client tools, path validation, revocation fallback, /request-cert.

One file per sprint. Re-declares fixtures; reuses s2_fixt.run_cli for CLI calls.
"""
import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID
from s2_fixt import run_cli, clean

@pytest.fixture
def s6_db(temp_dir):
    return temp_dir / "micropki.db"

@pytest.fixture
def s6_root(temp_dir, passphrase_file, s6_db):
    from micropki.ca import RootCA
    from micropki.database import init_db

    init_db(s6_db)
    ca = RootCA(str(temp_dir))
    ca.initialize(
        subject="CN=Sprint6 Root CA,O=Test Org",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=3650,
    )
    return {
        "out_dir": temp_dir,
        "cert": temp_dir / "certs" / "ca.cert.pem",
        "key": temp_dir / "private" / "ca.key.pem",
        "pass": passphrase_file.read_bytes(),
        "pass_file": passphrase_file,
        "db": s6_db,
    }

@pytest.fixture
def s6_inter(s6_root, passphrase_file):
    from micropki.ca import RootCA

    ca = RootCA(str(s6_root["out_dir"]))
    ca.issue_intermediate(
        root_cert_path=str(s6_root["cert"]),
        root_key_path=str(s6_root["key"]),
        root_passphrase=s6_root["pass"],
        subject="CN=Sprint6 Intermediate CA,O=Test Org",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825, pathlen=0,
        db_path=s6_root["db"],
    )
    return {
        "out_dir": s6_root["out_dir"],
        "cert": s6_root["out_dir"] / "certs" / "intermediate.cert.pem",
        "key": s6_root["out_dir"] / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "pass_file": passphrase_file,
        "db": s6_root["db"],
    }

def _issue_leaf(inter, out_dir, cn, template="server", sans=None):
    from micropki.ca import RootCA
    ca = RootCA(str(out_dir), create_layout=False)
    cert = ca.issue_cert(
        ca_cert_path=str(inter["cert"]),
        ca_key_path=str(inter["key"]),
        ca_passphrase=inter["pass"],
        template=template,
        subject=f"CN={cn},O=Test Org",
        sans=sans or [f"dns:{cn}"],
        out_dir=str(out_dir / "leaf"),
        validity_days=365,
        key_type="rsa",
        db_path=inter["db"],
    )
    return cert, out_dir / "leaf" / f"{cn}.cert.pem"

@pytest.fixture
def s6_ocsp(s6_root, s6_inter):
    from micropki.ocsp_responder import serve
    from micropki.ca import RootCA

    out = s6_root["out_dir"]
    ca = RootCA(str(out), create_layout=False)
    ca.issue_ocsp_cert(
        ca_cert_path=str(s6_inter["cert"]),
        ca_key_path=str(s6_inter["key"]),
        ca_passphrase=s6_inter["pass"],
        subject="CN=ocsp-responder,O=Test Org",
        key_type="rsa", key_size=2048,
        sans=["dns:localhost"],
        out_dir=str(out / "certs"),
        validity_days=365,
        db_path=s6_root["db"],
    )
    resp_cert = out / "certs" / "ocsp-responder.cert.pem"
    resp_key = out / "certs" / "ocsp-responder.key.pem"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve, args=("127.0.0.1", port),
        kwargs=dict(db_path=s6_root["db"],
                    responder_cert=resp_cert, responder_key=resp_key,
                    ca_cert=s6_inter["cert"], cache_ttl=60),
        daemon=True,
    ).start()
    _wait_port(port)
    return {"url": f"http://127.0.0.1:{port}/ocsp",
            "cert": resp_cert, "port": port}

@pytest.fixture
def s6_repo(s6_root, s6_inter):
    """Start repo with /request-cert enabled. Returns dict with base URL."""
    from micropki.repository import serve

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve, args=("127.0.0.1", port, s6_root["db"],
                            s6_root["out_dir"] / "certs"),
        kwargs=dict(
            ca_private_dir=s6_root["out_dir"] / "private",
            ca_pass_file=s6_inter["pass_file"],
            api_key="test-key",
        ),
        daemon=True,
    ).start()
    _wait_port(port)
    return {"url": f"http://127.0.0.1:{port}", "port": port}

def test_gen_csr_basic(temp_dir):
    out_key = temp_dir / "app.key.pem"
    out_csr = temp_dir / "app.csr.pem"
    log = temp_dir / "client.log"
    r = run_cli(["client", "gen-csr",
                 "--subject", "CN=app.example.com,O=MyOrg",
                 "--key-type", "rsa", "--key-size", "2048",
                 "--san", "dns:app.example.com",
                 "--san", "ip:10.0.0.1",
                 "--out-key", str(out_key),
                 "--out-csr", str(out_csr),
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr

    assert out_key.is_file()
    assert out_csr.is_file()
    if os.name != "nt":
        assert (out_key.stat().st_mode & 0o777) == 0o600

    key_pem = out_key.read_bytes()
    assert b"ENCRYPTED" not in key_pem

    csr = x509.load_pem_x509_csr(out_csr.read_bytes(), default_backend())
    assert csr.is_signature_valid
    assert "app.example.com" in csr.subject.rfc4514_string()

    san = csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert "app.example.com" in san.get_values_for_type(x509.DNSName)
    assert any(str(ip) == "10.0.0.1"
               for ip in san.get_values_for_type(x509.IPAddress))

def test_request_cert_via_repo(s6_repo, s6_root, s6_inter, temp_dir):
    csr_path = temp_dir / "app.csr.pem"
    key_path = temp_dir / "app.key.pem"
    log = temp_dir / "client.log"
    r = run_cli(["client", "gen-csr",
                 "--subject", "CN=reqcert.example.com,O=MyOrg",
                 "--key-type", "rsa", "--key-size", "2048",
                 "--san", "dns:reqcert.example.com",
                 "--out-key", str(key_path),
                 "--out-csr", str(csr_path),
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr

    cert_path = temp_dir / "app.cert.pem"
    r = run_cli(["client", "request-cert",
                 "--csr", str(csr_path),
                 "--template", "server",
                 "--ca-url", s6_repo["url"],
                 "--out-cert", str(cert_path),
                 "--api-key", "test-key",
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr
    assert cert_path.is_file()

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes(),
                                          default_backend())
    assert "reqcert.example.com" in cert.subject.rfc4514_string()

    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert "reqcert.example.com" in san.get_values_for_type(x509.DNSName)

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku

def test_request_cert_wrong_api_key(s6_repo, s6_inter, temp_dir):
    csr_path = temp_dir / "app.csr.pem"
    log = temp_dir / "client.log"
    run_cli(["client", "gen-csr",
             "--subject", "CN=x.example.com",
             "--san", "dns:x.example.com",
             "--out-key", str(temp_dir / "k.pem"),
             "--out-csr", str(csr_path),
             "--log-file", str(log)])
    r = run_cli(["client", "request-cert",
                 "--csr", str(csr_path),
                 "--template", "server",
                 "--ca-url", s6_repo["url"],
                 "--out-cert", str(temp_dir / "c.pem"),
                 "--api-key", "wrong",
                 "--log-file", str(log)])
    assert r.returncode != 0
    assert "401" in r.stdout + r.stderr

def test_validate_chain_ok(s6_root, s6_inter, temp_dir):
    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "valid.example.com")
    log = temp_dir / "client.log"
    r = run_cli(["client", "validate",
                 "--cert", str(cert_path),
                 "--untrusted", str(s6_inter["cert"]),
                 "--trusted", str(s6_root["cert"]),
                 "--mode", "chain",
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr
    assert "VALID" in r.stdout
    assert "[OK] build_chain" in r.stdout

def test_validate_expired(s6_root, s6_inter, temp_dir):
    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "expired.example.com")
    log = temp_dir / "client.log"
    r = run_cli(["client", "validate",
                 "--cert", str(cert_path),
                 "--untrusted", str(s6_inter["cert"]),
                 "--trusted", str(s6_root["cert"]),
                 "--mode", "chain",
                 "--validation-time", "2030-01-01T00:00:00Z",
                 "--log-file", str(log)])
    assert r.returncode != 0
    assert "INVALID" in r.stdout
    assert "not valid" in r.stdout

def test_validate_without_intermediate_fails(s6_root, s6_inter, temp_dir):
    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "nointer.example.com")
    log = temp_dir / "client.log"
    r = run_cli(["client", "validate",
                 "--cert", str(cert_path),
                 "--trusted", str(s6_root["cert"]),
                 "--mode", "chain",
                 "--log-file", str(log)])
    assert r.returncode != 0
    assert "INVALID" in r.stdout
    assert "No issuer" in r.stdout

def test_validate_json_format(s6_root, s6_inter, temp_dir):
    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "json.example.com")
    log = temp_dir / "client.log"
    r = run_cli(["client", "validate",
                 "--cert", str(cert_path),
                 "--untrusted", str(s6_inter["cert"]),
                 "--trusted", str(s6_root["cert"]),
                 "--mode", "chain",
                 "--format", "json",
                 "--log-file", str(log)])
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["ok"] is True
    assert isinstance(data["steps"], list)

def test_check_status_crl_revoked(s6_root, s6_inter, temp_dir):
    from micropki.revocation import revoke_certificate
    from micropki.crl import build_and_save_crl
    from micropki.crypto_utils import load_certificate, load_encrypted_key
    from micropki.database import connect, list_revoked_by_issuer

    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "revoked-crl.example.com")
    serial_hex = format(cert.serial_number, "x")
    revoke_certificate(db_path=s6_root["db"], serial_hex=serial_hex,
                       reason="keyCompromise")

    ca_cert = load_certificate(s6_inter["cert"])
    ca_key = load_encrypted_key(s6_inter["key"], s6_inter["pass"])
    conn = connect(s6_root["db"])
    try:
        build_and_save_crl(
            ca_cert=ca_cert, ca_key=ca_key,
            revoked_rows=list_revoked_by_issuer(
                conn, ca_cert.subject.rfc4514_string()),
            db_conn=conn,
            out_dir=s6_root["out_dir"], ca_label="intermediate",
            next_update_days=7,
        )
    finally:
        conn.close()
    crl_path = s6_root["out_dir"] / "crl" / "intermediate.crl.pem"

    log = temp_dir / "client.log"
    r = run_cli(["client", "check-status",
                 "--cert", str(cert_path),
                 "--ca-cert", str(s6_inter["cert"]),
                 "--crl", str(crl_path),
                 "--log-file", str(log)])
    assert r.returncode != 0 
    assert "status=revoked" in r.stdout
    assert "source=crl" in r.stdout
    out = r.stdout.lower().replace("_","")
    assert "keycompromise" in out

def test_check_status_ocsp_revoked(s6_ocsp, s6_root, s6_inter, temp_dir):
    from micropki.revocation import revoke_certificate

    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "revoked-ocsp.example.com")
    serial_hex = format(cert.serial_number, "x")
    revoke_certificate(db_path=s6_root["db"], serial_hex=serial_hex,
                       reason="keyCompromise")

    log = temp_dir / "client.log"
    r = run_cli(["client", "check-status",
                 "--cert", str(cert_path),
                 "--ca-cert", str(s6_inter["cert"]),
                 "--ocsp-url", s6_ocsp["url"],
                 "--log-file", str(log)])
    assert r.returncode != 0
    assert "status=revoked" in r.stdout
    assert "source=ocsp" in r.stdout

def test_check_status_fallback_to_crl(s6_root, s6_inter, temp_dir):
    from micropki.revocation import revoke_certificate
    from micropki.crl import build_and_save_crl
    from micropki.crypto_utils import load_certificate, load_encrypted_key
    from micropki.database import connect, list_revoked_by_issuer

    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "fallback.example.com")
    serial_hex = format(cert.serial_number, "x")
    revoke_certificate(db_path=s6_root["db"], serial_hex=serial_hex,
                       reason="keyCompromise")

    ca_cert = load_certificate(s6_inter["cert"])
    ca_key = load_encrypted_key(s6_inter["key"], s6_inter["pass"])
    conn = connect(s6_root["db"])
    try:
        build_and_save_crl(
            ca_cert=ca_cert, ca_key=ca_key,
            revoked_rows=list_revoked_by_issuer(
                conn, ca_cert.subject.rfc4514_string()),
            db_conn=conn,
            out_dir=s6_root["out_dir"], ca_label="intermediate",
            next_update_days=7,
        )
    finally:
        conn.close()
    crl_path = s6_root["out_dir"] / "crl" / "intermediate.crl.pem"

    log = temp_dir / "client.log"
    r = run_cli(["client", "check-status",
                 "--cert", str(cert_path),
                 "--ca-cert", str(s6_inter["cert"]),
                 "--ocsp-url", "http://127.0.0.1:1/ocsp",
                 "--crl", str(crl_path),
                 "--log-file", str(log)])
    assert r.returncode != 0
    assert "status=revoked" in r.stdout
    assert "source=crl" in r.stdout

    log_text = log.read_text()
    assert "OCSP failed, falling back to CRL" in log_text

def test_request_cert_malformed_csr(s6_repo, temp_dir):
    import urllib.request
    import urllib.error

    req = urllib.request.Request(
        f"{s6_repo['url']}/request-cert?template=server",
        data=b"not a valid CSR",
        headers={"Content-Type": "application/x-pem-file",
                 "X-API-Key": "test-key"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=5)
    assert ei.value.code == 400

def test_request_cert_csr_with_ca_true_is_leaf(s6_repo, s6_root, s6_inter,
                                               temp_dir):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "ca-leaf")]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("ca-leaf.example.com")]),
            critical=False)
        .sign(key, hashes.SHA256())
    )
    csr_path = temp_dir / "ca_true.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    out_cert = temp_dir / "ca-leaf.cert.pem"
    log = temp_dir / "client.log"
    r = run_cli(["client", "request-cert",
                 "--csr", str(csr_path),
                 "--template", "server",
                 "--ca-url", s6_repo["url"],
                 "--out-cert", str(out_cert),
                 "--api-key", "test-key",
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr
    cert = x509.load_pem_x509_certificate(out_cert.read_bytes(),
                                          default_backend())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False

def test_build_chain_ok(s6_root, s6_inter):
    from micropki.validation import build_chain, load_untrusted, load_trusted
    from micropki.crypto_utils import load_certificate

    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "chain.example.com")
    leaf = load_certificate(cert_path)
    untrusted = load_untrusted([str(s6_inter["cert"])])
    trusted = load_trusted(str(s6_root["cert"]))
    chain = build_chain(leaf, untrusted, trusted)
    assert len(chain) == 3
    assert chain[-1].subject == trusted[0].subject

def test_build_chain_missing_intermediate(s6_root, s6_inter):
    from micropki.validation import build_chain, load_untrusted, load_trusted
    from micropki.crypto_utils import load_certificate

    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "nointer2.example.com")
    leaf = load_certificate(cert_path)
    untrusted = load_untrusted([])
    trusted = load_trusted(str(s6_root["cert"]))
    with pytest.raises(ValueError, match="No issuer"):
        build_chain(leaf, untrusted, trusted)

def test_ocsp_url_from_aia_none(s6_root, s6_inter):
    from micropki.revocation_check import _ocsp_url_from_aia
    from micropki.crypto_utils import load_certificate

    cert, cert_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                  "no-aia.example.com")
    leaf = load_certificate(cert_path)
    assert _ocsp_url_from_aia(leaf) is None

def test_check_crl_good_and_revoked(s6_root, s6_inter, temp_dir):
    from micropki.revocation_check import check_crl
    from micropki.revocation import revoke_certificate
    from micropki.crl import build_and_save_crl
    from micropki.crypto_utils import load_certificate, load_encrypted_key
    from micropki.database import connect, list_revoked_by_issuer

    ca_cert = load_certificate(s6_inter["cert"])
    ca_key = load_encrypted_key(s6_inter["key"], s6_inter["pass"])

    good_cert, good_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                       "crl-good.example.com")
    bad_cert, bad_path = _issue_leaf(s6_inter, s6_root["out_dir"],
                                     "crl-bad.example.com")
    revoke_certificate(db_path=s6_root["db"],
                       serial_hex=format(bad_cert.serial_number, "x"),
                       reason="superseded")

    conn = connect(s6_root["db"])
    try:
        build_and_save_crl(
            ca_cert=ca_cert, ca_key=ca_key,
            revoked_rows=list_revoked_by_issuer(
                conn, ca_cert.subject.rfc4514_string()),
            db_conn=conn,
            out_dir=s6_root["out_dir"], ca_label="intermediate",
            next_update_days=7,
        )
    finally:
        conn.close()
    crl_path = s6_root["out_dir"] / "crl" / "intermediate.crl.pem"

    good = check_crl(cert=load_certificate(good_path), issuer=ca_cert,
                     crl_arg=str(crl_path))
    assert good["status"] == "good"
    assert good["source"] == "crl"

    bad = check_crl(cert=load_certificate(bad_path), issuer=ca_cert,
                    crl_arg=str(crl_path))
    assert bad["status"] == "revoked"
    assert bad["reason"].lower() == "superseded"

def test_e2e_full_client_flow(s6_repo, s6_ocsp, s6_root, s6_inter, temp_dir):
    from micropki.revocation import revoke_certificate

    log = temp_dir / "client.log"
    csr_path = temp_dir / "e2e.csr.pem"
    key_path = temp_dir / "e2e.key.pem"
    cert_path = temp_dir / "e2e.cert.pem"

    r = run_cli(["client", "gen-csr",
                 "--subject", "CN=e2e.example.com,O=MyOrg",
                 "--san", "dns:e2e.example.com",
                 "--out-key", str(key_path),
                 "--out-csr", str(csr_path),
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr

    r = run_cli(["client", "request-cert",
                 "--csr", str(csr_path),
                 "--template", "server",
                 "--ca-url", s6_repo["url"],
                 "--out-cert", str(cert_path),
                 "--api-key", "test-key",
                 "--log-file", str(log)])
    assert r.returncode == 0, r.stderr

    r = run_cli(["client", "validate",
                 "--cert", str(cert_path),
                 "--untrusted", str(s6_inter["cert"]),
                 "--trusted", str(s6_root["cert"]),
                 "--mode", "chain",
                 "--log-file", str(log)])
    assert r.returncode == 0
    assert "VALID" in r.stdout

    r = run_cli(["client", "check-status",
                 "--cert", str(cert_path),
                 "--ca-cert", str(s6_inter["cert"]),
                 "--ocsp-url", s6_ocsp["url"],
                 "--log-file", str(log)])
    assert r.returncode == 0
    assert "status=good" in r.stdout

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes(),
                                          default_backend())
    revoke_certificate(db_path=s6_root["db"],
                       serial_hex=format(cert.serial_number, "x"),
                       reason="keyCompromise")

    r = run_cli(["client", "validate",
                 "--cert", str(cert_path),
                 "--untrusted", str(s6_inter["cert"]),
                 "--trusted", str(s6_root["cert"]),
                 "--ocsp",
                 "--mode", "full",
                 "--log-file", str(log)])
    assert r.returncode != 0
    assert "INVALID" in r.stdout or "revoked" in r.stdout.lower()

@pytest.mark.skip(reason="TEST-42 is Could (EKU mismatch)")
def test_validate_eku_mismatch():
    pass

@pytest.mark.skip(reason="TEST-47 is N/A (multiple paths)")
def test_build_chain_multiple_paths():
    pass

def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    pytest.fail("server did not start in time")
