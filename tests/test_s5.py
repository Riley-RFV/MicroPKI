import os
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from s2_fixt import run_cli, clean

@pytest.fixture
def s5_db(temp_dir):
    return temp_dir / "micropki.db"

@pytest.fixture
def s5_root(temp_dir, passphrase_file, s5_db):
    from micropki.ca import RootCA
    from micropki.database import init_db

    init_db(s5_db)
    ca = RootCA(str(temp_dir))
    ca.initialize(
        subject="CN=Sprint5 Root CA,O=Test Org",
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
        "db": s5_db,
    }

@pytest.fixture
def s5_inter(s5_root, passphrase_file):
    from micropki.ca import RootCA

    ca = RootCA(str(s5_root["out_dir"]))
    ca.issue_intermediate(
        root_cert_path=str(s5_root["cert"]),
        root_key_path=str(s5_root["key"]),
        root_passphrase=s5_root["pass"],
        subject="CN=Sprint5 Intermediate CA,O=Test Org",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825, pathlen=0,
        db_path=s5_root["db"],
    )
    return {
        "out_dir": s5_root["out_dir"],
        "cert": s5_root["out_dir"] / "certs" / "intermediate.cert.pem",
        "key": s5_root["out_dir"] / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "pass_file": passphrase_file,
        "db": s5_root["db"],
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

def _issue_ocsp_cert(inter, out_dir, cn="ocsp-responder"):
    from micropki.ca import RootCA
    ca = RootCA(str(out_dir), create_layout=False)
    cert = ca.issue_ocsp_cert(
        ca_cert_path=str(inter["cert"]),
        ca_key_path=str(inter["key"]),
        ca_passphrase=inter["pass"],
        subject=f"CN={cn},O=Test Org",
        key_type="rsa", key_size=2048,
        sans=[f"dns:{cn}.local"],
        out_dir=str(out_dir / "certs"),
        validity_days=365,
        db_path=inter["db"],
    )
    return cert, out_dir / "certs" / f"{cn}.cert.pem", out_dir / "certs" / f"{cn}.key.pem"

@pytest.fixture
def s5_ocsp_server(s5_root, s5_inter):
    from micropki.ocsp_responder import serve

    out = s5_root["out_dir"]
    resp_cert, resp_cert_path, resp_key_path = _issue_ocsp_cert(s5_inter, out)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    threading.Thread(
        target=serve,
        args=("127.0.0.1", port),
        kwargs=dict(
            db_path=s5_root["db"],
            responder_cert=resp_cert_path,
            responder_key=resp_key_path,
            ca_cert=s5_inter["cert"],
            cache_ttl=60,
        ),
        daemon=True,
    ).start()
    _wait_port(port)

    yield {
        "url": f"http://127.0.0.1:{port}/ocsp",
        "responder_cert": resp_cert_path,
        "responder_cert_x509": resp_cert,
        "ca_cert": s5_inter["cert"],
        "db": s5_root["db"],
        "out_dir": out,
    }

def test_ocsp_cert_extensions(s5_root, s5_inter):
    cert, _, _ = _issue_ocsp_cert(s5_inter, s5_root["out_dir"])

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True
    assert ku.key_cert_sign is False
    assert ku.crl_sign is False

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.OCSP_SIGNING in eku

def test_ocsp_cert_key_unencrypted_0600(s5_root, s5_inter):
    _, _, key_path = _issue_ocsp_cert(s5_inter, s5_root["out_dir"])
    pem = key_path.read_bytes()
    assert b"ENCRYPTED" not in pem
    if os.name != "nt":
        assert (key_path.stat().st_mode & 0o777) == 0o600

def test_ocsp_cert_openssl_text(s5_root, s5_inter):
    _, cert_path, _ = _issue_ocsp_cert(s5_inter, s5_root["out_dir"])
    res = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    out = res.stdout
    assert "OCSP Signing" in out
    assert "CA:FALSE" in out
    assert "Digital Signature" in out

def test_ocsp_good(s5_root, s5_inter, s5_ocsp_server):
    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "good.example.com",
                                  sans=["dns:good.example.com"])
    res = _openssl_ocsp(
        issuer=s5_inter["cert"],
        cert=cert_path,
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "Cert Status: good" in res.stdout
    assert "Response verify OK" in (res.stdout + res.stderr)

def test_ocsp_revoked(s5_root, s5_inter, s5_ocsp_server):
    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "revoked.example.com",
                                  sans=["dns:revoked.example.com"])
    serial_hex = format(cert.serial_number, "x")

    from micropki.revocation import revoke_certificate
    revoke_certificate(db_path=s5_root["db"], serial_hex=serial_hex,
                       reason="keyCompromise")

    res = _openssl_ocsp(
        issuer=s5_inter["cert"],
        cert=cert_path,
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "Cert Status: revoked" in res.stdout
    assert "Revocation Reason: keyCompromise" in res.stdout
    assert "Revocation Time" in res.stdout

def test_ocsp_unknown(s5_root, s5_inter, s5_ocsp_server):
    res = _openssl_ocsp(
        issuer=s5_inter["cert"],
        serial="0xDEADBEEF",
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "Cert Status: unknown" in res.stdout

def test_ocsp_nonce_echoed(s5_root, s5_inter, s5_ocsp_server):
    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "nonce.example.com",
                                  sans=["dns:nonce.example.com"])
    res = _openssl_ocsp(
        issuer=s5_inter["cert"],
        cert=cert_path,
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
        nonce=True,
    )
    assert res.returncode == 0, res.stderr
    assert "OCSP Nonce" in res.stdout
    text = res.stdout
    idx = text.find("OCSP Nonce")
    snippet = text[idx:idx + 200]
    assert any(ch in snippet for ch in "0123456789ABCDEF")

def test_ocsp_no_nonce_by_default(s5_root, s5_inter, s5_ocsp_server):
    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "nononce.example.com",
                                  sans=["dns:nononce.example.com"])
    res = _openssl_ocsp(
        issuer=s5_inter["cert"],
        cert=cert_path,
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
        no_nonce=True,
    )
    assert res.returncode == 0, res.stderr
    assert "Cert Status: good" in res.stdout

def test_ocsp_signature_verified(s5_root, s5_inter, s5_ocsp_server):
    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "sigverify.example.com",
                                  sans=["dns:sigverify.example.com"])
    res = _openssl_ocsp(
        issuer=s5_inter["cert"],
        cert=cert_path,
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
    )
    assert "Response verify OK" in (res.stdout + res.stderr)

def test_ocsp_malformed_request(s5_ocsp_server):
    import urllib.request
    import urllib.error

    url = s5_ocsp_server["url"]
    req = urllib.request.Request(
        url, data=b"not a valid OCSP request",
        headers={"Content-Type": "application/ocsp-request"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        body = e.read()
        assert e.code in (200, 400)
        return
    assert isinstance(body, bytes)
    assert len(body) > 0

def test_ocsp_wrong_content_type(s5_ocsp_server):
    import urllib.request
    import urllib.error

    req = urllib.request.Request(
        s5_ocsp_server["url"], data=b"x",
        headers={"Content-Type": "text/plain"}, method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=5)
    assert ei.value.code == 400

def test_ocsp_unknown_issuer(s5_root, s5_inter, s5_ocsp_server, temp_dir):
    from micropki.ca import RootCA
    from micropki.database import init_db

    other_dir = temp_dir / "other"
    other_dir.mkdir()
    other_db = other_dir / "micropki.db"
    init_db(other_db)

    other_root = RootCA(str(other_dir))
    other_root.initialize(
        subject="CN=Other Root,O=Other",
        key_type="rsa", key_size=4096,
        passphrase=b"other-pass", validity_days=365,
    )
    other_root.issue_intermediate(
        root_cert_path=str(other_dir / "certs" / "ca.cert.pem"),
        root_key_path=str(other_dir / "private" / "ca.key.pem"),
        root_passphrase=b"other-pass",
        subject="CN=Other Intermediate,O=Other",
        key_type="rsa", key_size=4096,
        passphrase=b"other-pass",
        validity_days=365, pathlen=0, db_path=other_db,
    )
    other_inter = {
        "cert": other_dir / "certs" / "intermediate.cert.pem",
        "key": other_dir / "private" / "intermediate.key.pem",
        "pass": b"other-pass",
        "db": other_db,
    }
    _, cert_path = _issue_leaf(other_inter, other_dir,
                               "foreign.example.com",
                               sans=["dns:foreign.example.com"])

    res = _openssl_ocsp(
        issuer=other_inter["cert"],
        cert=cert_path,
        url=s5_ocsp_server["url"],
        vafile=s5_ocsp_server["responder_cert"],
        resp_text=True,
    )
    out = res.stdout + res.stderr
    assert ("unknown" in out.lower()) or ("unauthorized" in out.lower()) \
           or ("signer certificate not found" in out.lower())

def test_parse_ocsp_request_from_openssl(s5_root, s5_inter, temp_dir):
    from micropki.ocsp import parse_ocsp_request
    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "parse.example.com",
                                  sans=["dns:parse.example.com"])
    req_path = temp_dir / "req.der"
    res = subprocess.run(
        ["openssl", "ocsp", "-issuer", str(s5_inter["cert"]),
         "-cert", str(cert_path), "-reqout", str(req_path), "-no_nonce"],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    parsed = parse_ocsp_request(req_path.read_bytes())
    assert parsed.nonce is None
    assert len(parsed.cert_ids) == 1
    cid = parsed.cert_ids[0]
    assert cid["hash_alg"] in ("sha1", "sha256")
    assert cid["serial"] == cert.serial_number

def test_issuer_hashes_match_openssl(s5_root, s5_inter, temp_dir):
    from micropki.ocsp import parse_ocsp_request, issuer_name_hash, issuer_key_hash
    from micropki.crypto_utils import load_certificate

    cert, cert_path = _issue_leaf(s5_inter, s5_root["out_dir"],
                                  "hashes.example.com",
                                  sans=["dns:hashes.example.com"])
    req_path = temp_dir / "req.der"
    subprocess.run(
        ["openssl", "ocsp", "-issuer", str(s5_inter["cert"]),
         "-cert", str(cert_path), "-reqout", str(req_path), "-no_nonce"],
        check=True, capture_output=True,
    )
    parsed = parse_ocsp_request(req_path.read_bytes())
    cid = parsed.cert_ids[0]
    inter = load_certificate(s5_inter["cert"])
    assert issuer_name_hash(inter, cid["hash_alg"]) == cid["issuer_name_hash"]
    assert issuer_key_hash(inter, cid["hash_alg"]) == cid["issuer_key_hash"]

def test_reason_mapping():
    from micropki.ocsp import _map_reason
    assert _map_reason(None) is None
    assert _map_reason("keyCompromise") is not None
    assert _map_reason("bogus") is None

@pytest.mark.skip(reason="TEST-36 is Could (performance)")
def test_ocsp_load_100():
    pass

def _openssl_ocsp(*, issuer: Path, url: str, cert: Path | None = None,
                  serial: str | None = None, vafile: Path | None = None,
                  resp_text: bool = True, nonce: bool = False,
                  no_nonce: bool = False):
    cmd = ["openssl", "ocsp", "-issuer", str(issuer), "-url", url]
    if cert is not None:
        cmd += ["-cert", str(cert)]
    if serial is not None:
        cmd += ["-serial", serial]
    if vafile is not None:
        cmd += ["-VAfile", str(vafile)]
    if resp_text:
        cmd += ["-resp_text"]
    if nonce:
        cmd += ["-nonce"]
    if no_nonce:
        cmd += ["-no_nonce"]
    return subprocess.run(cmd, capture_output=True, text=True)

def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    pytest.fail("OCSP responder did not start in time")
