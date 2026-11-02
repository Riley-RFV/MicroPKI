import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from s2_fixt import run_cli, clean

@pytest.fixture
def s4_db(temp_dir):
    return temp_dir / "micropki.db"

@pytest.fixture
def s4_root(temp_dir, passphrase_file, s4_db):
    from micropki.ca import RootCA
    from micropki.database import init_db

    init_db(s4_db)
    ca = RootCA(str(temp_dir))
    ca.initialize(
        subject="CN=Sprint4 Root CA,O=Test Org",
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
        "db": s4_db,
    }

@pytest.fixture
def s4_inter(s4_root, passphrase_file):
    from micropki.ca import RootCA

    ca = RootCA(str(s4_root["out_dir"]))
    ca.issue_intermediate(
        root_cert_path=str(s4_root["cert"]),
        root_key_path=str(s4_root["key"]),
        root_passphrase=s4_root["pass"],
        subject="CN=Sprint4 Intermediate CA,O=Test Org",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825, pathlen=0,
        db_path=s4_root["db"],
    )
    return {
        "out_dir": s4_root["out_dir"],
        "cert": s4_root["out_dir"] / "certs" / "intermediate.cert.pem",
        "key": s4_root["out_dir"] / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "pass_file": passphrase_file,
        "db": s4_root["db"],
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

def _serial(cert):
    return format(cert.serial_number, "x")

def _revoke_cli(db, out_dir, serial_hex, reason, log, *,
                pass_file=None, force=True, extra=()):
    args = ["ca", "revoke", serial_hex, "--reason", reason,
            "--db-path", str(db), "--out-dir", str(out_dir),
            "--log-file", str(log)]
    if pass_file is not None:
        args += ["--ca-pass-file", str(pass_file)]
    if force:
        args += ["--force"]
    args += list(extra)
    return run_cli(args)

def _gen_crl_cli(db, out_dir, ca_label, pass_file, log, *, extra=()):
    args = ["ca", "gen-crl", "--ca", ca_label,
            "--ca-pass-file", str(pass_file),
            "--out-dir", str(out_dir),
            "--db-path", str(db),
            "--log-file", str(log)]
    args += list(extra)
    return run_cli(args)

@pytest.mark.parametrize("raw", [
    "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL",
    "privilegeWithdrawn", "aACompromise",
])
def test_normalize_reason_accepts_all_canonical(raw):
    from micropki.crl import normalize_reason
    assert normalize_reason(raw) == raw.lower()

@pytest.mark.parametrize("raw,canonical", [
    ("KEYCOMPROMISE", "keycompromise"),
    ("key_compromise", "keycompromise"),
    ("key-compromise", "keycompromise"),
    ("KeyCompromise", "keycompromise"),
])
def test_normalize_reason_is_case_and_sep_insensitive(raw, canonical):
    from micropki.crl import normalize_reason
    assert normalize_reason(raw) == canonical

def test_normalize_reason_rejects_unknown():
    from micropki.crl import normalize_reason
    with pytest.raises(ValueError):
        normalize_reason("bogusReason")

def test_revoke_unknown_serial_fails(s4_root):
    log = s4_root["out_dir"] / "ca.log"
    result = _revoke_cli(s4_root["db"], s4_root["out_dir"],
                         "deadbeefcafe", "keyCompromise", log)
    assert result.returncode != 0
    text = log.read_text()
    assert "Revocation failed" in text or "not found" in text.lower()


def test_revoke_updates_db_and_is_noop_on_repeat(s4_root, s4_inter):
    from micropki.database import connect, get_certificate_by_serial

    cert, _ = _issue_leaf(s4_inter, s4_root["out_dir"], "once.example.com",
                          sans=["dns:once.example.com"])
    serial_hex = _serial(cert)
    log = s4_root["out_dir"] / "ca.log"

    r1 = _revoke_cli(s4_root["db"], s4_root["out_dir"], serial_hex,
                     "keyCompromise", log, force=True)
    assert r1.returncode == 0, r1.stderr

    conn = connect(s4_root["db"])
    try:
        row = get_certificate_by_serial(conn, serial_hex)
    finally:
        conn.close()
    assert row["status"] == "revoked"
    first_date = row["revocation_date"]
    assert first_date is not None
    assert row["revocation_reason"] == "keycompromise"

    r2 = _revoke_cli(s4_root["db"], s4_root["out_dir"], serial_hex,
                     "superseded", log, force=True)
    assert r2.returncode == 0

    conn = connect(s4_root["db"])
    try:
        row2 = get_certificate_by_serial(conn, serial_hex)
    finally:
        conn.close()
    assert row2["revocation_date"] == first_date
    assert row2["revocation_reason"] == "keycompromise"
    assert "already revoked" in log.read_text().lower()

def test_lifecycle_revoke_and_crl(s4_root, s4_inter):
    """TEST-21: issue -> valid -> revoke -> gen-crl -> entry present -> HTTP."""
    from micropki.database import connect, get_certificate_by_serial

    cert, _ = _issue_leaf(s4_inter, s4_root["out_dir"], "life.example.com",
                          sans=["dns:life.example.com"])
    serial_hex = _serial(cert)
    serial_int = cert.serial_number
    log = s4_root["out_dir"] / "ca.log"

    conn = connect(s4_root["db"])
    try:
        row = get_certificate_by_serial(conn, serial_hex)
    finally:
        conn.close()
    assert row["status"] == "valid"

    r = _revoke_cli(s4_root["db"], s4_root["out_dir"], serial_hex,
                    "keyCompromise", log,
                    pass_file=s4_inter["pass_file"], force=True)
    assert r.returncode == 0, r.stderr

    conn = connect(s4_root["db"])
    try:
        row = get_certificate_by_serial(conn, serial_hex)
    finally:
        conn.close()
    assert row["status"] == "revoked"
    assert row["revocation_reason"] == "keycompromise"
    assert row["revocation_date"]

    crl_path = s4_root["out_dir"] / "crl" / "intermediate.crl.pem"
    assert crl_path.is_file()

    from micropki.crl import load_crl
    crl = load_crl(crl_path)
    revoked_serials = [r.serial_number for r in crl]
    assert serial_int in revoked_serials

    entry = next(r for r in crl if r.serial_number == serial_int)
    reason_ext = entry.extensions.get_extension_for_class(x509.CRLReason).value
    assert reason_ext.reason == x509.ReasonFlags.key_compromise

def test_lifecycle_crl_via_http(s4_root, s4_inter):
    from micropki.repository import serve

    cert, _ = _issue_leaf(s4_inter, s4_root["out_dir"], "http-life.example.com",
                          sans=["dns:http-life.example.com"])
    serial_hex = _serial(cert)
    log = s4_root["out_dir"] / "ca.log"

    _revoke_cli(s4_root["db"], s4_root["out_dir"], serial_hex,
                "keyCompromise", log,
                pass_file=s4_inter["pass_file"], force=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s4_root["db"]),
              str(s4_root["out_dir"] / "certs")),
        daemon=True,
    ).start()
    _wait_port(port)

    crl_disk = s4_root["out_dir"] / "crl" / "intermediate.crl.pem"
    req = urllib.request.Request(f"http://127.0.0.1:{port}/crl")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/pkix-crl"
        assert resp.headers.get("ETag")
        assert resp.headers.get("Cache-Control")
        body = resp.read()
    assert body == crl_disk.read_bytes()

    res = subprocess.run(
        ["openssl", "crl", "-in", str(crl_disk), "-inform", "PEM",
         "-CAfile", str(s4_inter["cert"]), "-noout"],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "verify OK" in res.stdout + res.stderr

def test_crl_signature_verified_by_openssl(s4_root, s4_inter):
    cert, _ = _issue_leaf(s4_inter, s4_root["out_dir"], "sig.example.com",
                          sans=["dns:sig.example.com"])
    log = s4_root["out_dir"] / "ca.log"
    _revoke_cli(s4_root["db"], s4_root["out_dir"], _serial(cert),
                "keyCompromise", log,
                pass_file=s4_inter["pass_file"], force=True)

    crl = s4_root["out_dir"] / "crl" / "intermediate.crl.pem"
    res = subprocess.run(
        ["openssl", "crl", "-in", str(crl), "-inform", "PEM",
         "-CAfile", str(s4_inter["cert"]), "-noout"],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr

def test_crl_number_monotonic(s4_root, s4_inter):
    from micropki.crl import load_crl

    log = s4_root["out_dir"] / "ca.log"
    r1 = _gen_crl_cli(s4_root["db"], s4_root["out_dir"], "intermediate",
                      s4_inter["pass_file"], log)
    assert r1.returncode == 0, r1.stderr
    crl1 = load_crl(s4_root["out_dir"] / "crl" / "intermediate.crl.pem")
    n1 = crl1.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number

    r2 = _gen_crl_cli(s4_root["db"], s4_root["out_dir"], "intermediate",
                      s4_inter["pass_file"], log)
    assert r2.returncode == 0, r2.stderr
    crl2 = load_crl(s4_root["out_dir"] / "crl" / "intermediate.crl.pem")
    n2 = crl2.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number

    assert n2 == n1 + 1

def test_http_crl_matches_disk(s4_root, s4_inter):
    from micropki.repository import serve

    log = s4_root["out_dir"] / "ca.log"
    _gen_crl_cli(s4_root["db"], s4_root["out_dir"], "intermediate",
                 s4_inter["pass_file"], log)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s4_root["db"]),
              str(s4_root["out_dir"] / "certs")),
        daemon=True,
    ).start()
    _wait_port(port)

    disk = s4_root["out_dir"] / "crl" / "intermediate.crl.pem"
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/crl", timeout=5) as resp:
        body = resp.read()
    assert body == disk.read_bytes()

def test_http_crl_root_query(s4_root, s4_inter):
    from micropki.repository import serve

    log = s4_root["out_dir"] / "ca.log"
    _gen_crl_cli(s4_root["db"], s4_root["out_dir"], "root",
                 s4_root["pass_file"], log)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s4_root["db"]),
              str(s4_root["out_dir"] / "certs")),
        daemon=True,
    ).start()
    _wait_port(port)

    disk = s4_root["out_dir"] / "crl" / "root.crl.pem"
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/crl?ca=root", timeout=5) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/pkix-crl"
        assert resp.read() == disk.read_bytes()

def test_http_crl_path_style(s4_root, s4_inter):
    from micropki.repository import serve

    log = s4_root["out_dir"] / "ca.log"
    _gen_crl_cli(s4_root["db"], s4_root["out_dir"], "intermediate",
                 s4_inter["pass_file"], log)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s4_root["db"]),
              str(s4_root["out_dir"] / "certs")),
        daemon=True,
    ).start()
    _wait_port(port)

    with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/crl/intermediate.crl", timeout=5) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/pkix-crl"

def test_http_crl_bad_ca_400(s4_root, s4_inter):
    from micropki.repository import serve

    log = s4_root["out_dir"] / "ca.log"
    _gen_crl_cli(s4_root["db"], s4_root["out_dir"], "intermediate",
                 s4_inter["pass_file"], log)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s4_root["db"]),
              str(s4_root["out_dir"] / "certs")),
        daemon=True,
    ).start()
    _wait_port(port)

    req = urllib.request.Request(f"http://127.0.0.1:{port}/crl?ca=bogus")
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=5)
    assert ei.value.code == 400

def test_http_crl_missing_file_404(s4_root, s4_inter):
    from micropki.repository import serve

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s4_root["db"]),
              str(s4_root["out_dir"] / "certs")),
        daemon=True,
    ).start()
    _wait_port(port)

    req = urllib.request.Request(f"http://127.0.0.1:{port}/crl")
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=5)
    assert ei.value.code == 404

def test_build_crl_empty_has_no_entries(s4_root, s4_inter):
    from micropki.crl import build_and_save_crl, load_crl
    from micropki.crypto_utils import load_certificate, load_encrypted_key
    from micropki.database import connect

    ca_cert = load_certificate(s4_inter["cert"])
    ca_key = load_encrypted_key(s4_inter["key"], s4_inter["pass"])
    conn = connect(s4_root["db"])
    try:
        path = build_and_save_crl(
            ca_cert=ca_cert, ca_key=ca_key,
            revoked_rows=[], db_conn=conn,
            out_dir=s4_root["out_dir"], ca_label="intermediate",
            next_update_days=7,
        )
    finally:
        conn.close()
    crl = load_crl(path)
    assert len(list(crl)) == 0
    assert crl.issuer == ca_cert.subject

def test_crl_metadata_row_written(s4_root, s4_inter):
    from micropki.crl import build_and_save_crl
    from micropki.crypto_utils import load_certificate, load_encrypted_key
    from micropki.database import connect, get_crl_metadata

    ca_cert = load_certificate(s4_inter["cert"])
    ca_key = load_encrypted_key(s4_inter["key"], s4_inter["pass"])
    conn = connect(s4_root["db"])
    try:
        build_and_save_crl(
            ca_cert=ca_cert, ca_key=ca_key,
            revoked_rows=[], db_conn=conn,
            out_dir=s4_root["out_dir"], ca_label="intermediate",
            next_update_days=7,
        )
        meta = get_crl_metadata(conn, ca_cert.subject.rfc4514_string())
    finally:
        conn.close()
    assert meta is not None
    assert meta["crl_number"] >= 1
    assert meta["crl_path"].endswith("intermediate.crl.pem")

def test_crl_number_increases_per_issuer(s4_root, s4_inter):
    from micropki.crl import build_and_save_crl
    from micropki.crypto_utils import load_certificate, load_encrypted_key
    from micropki.database import connect, get_crl_metadata

    ca_cert = load_certificate(s4_inter["cert"])
    ca_key = load_encrypted_key(s4_inter["key"], s4_inter["pass"])
    conn = connect(s4_root["db"])
    try:
        build_and_save_crl(ca_cert=ca_cert, ca_key=ca_key, revoked_rows=[],
                           db_conn=conn, out_dir=s4_root["out_dir"],
                           ca_label="intermediate")
        n1 = get_crl_metadata(conn, ca_cert.subject.rfc4514_string())["crl_number"]
        build_and_save_crl(ca_cert=ca_cert, ca_key=ca_key, revoked_rows=[],
                           db_conn=conn, out_dir=s4_root["out_dir"],
                           ca_label="intermediate")
        n2 = get_crl_metadata(conn, ca_cert.subject.rfc4514_string())["crl_number"]
    finally:
        conn.close()
    assert n2 == n1 + 1

@pytest.mark.skip(reason="TEST-27 is Could; requires TLS setup")
def test_tls_rejects_revoked_cert():
    pass

def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    pytest.fail("repo server did not start in time")
