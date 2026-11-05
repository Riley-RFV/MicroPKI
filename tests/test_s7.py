"""Sprint 7 tests: audit, policy, rate limit, CT, compromise.

One file per sprint. Re-declares fixtures; reuses s2_fixt.run_cli.
"""
import json
import os
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from s2_fixt import run_cli, clean


# --------------------------------------------------------------------- fixtures

@pytest.fixture
def s7_db(temp_dir):
    return temp_dir / "micropki.db"


@pytest.fixture
def s7_root(temp_dir, passphrase_file, s7_db):
    from micropki.ca import RootCA
    from micropki.audit import AuditLog
    from micropki.database import init_db

    init_db(s7_db)
    audit = AuditLog(temp_dir / "audit" / "audit.log")
    ca = RootCA(str(temp_dir), audit=audit)
    ca.initialize(
        subject="CN=Sprint7 Root CA,O=Test Org",
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
        "db": s7_db,
        "audit": audit,
        "audit_log": temp_dir / "audit" / "audit.log",
        "ct_log": temp_dir / "audit" / "ct.log",
    }


@pytest.fixture
def s7_inter(s7_root, passphrase_file):
    from micropki.ca import RootCA

    ca = RootCA(str(s7_root["out_dir"]), audit=s7_root["audit"])
    ca.issue_intermediate(
        root_cert_path=str(s7_root["cert"]),
        root_key_path=str(s7_root["key"]),
        root_passphrase=s7_root["pass"],
        subject="CN=Sprint7 Intermediate CA,O=Test Org",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825, pathlen=0,
        db_path=s7_root["db"],
    )
    return {
        "out_dir": s7_root["out_dir"],
        "cert": s7_root["out_dir"] / "certs" / "intermediate.cert.pem",
        "key": s7_root["out_dir"] / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "pass_file": passphrase_file,
        "db": s7_root["db"],
        "audit": s7_root["audit"],
        "audit_log": s7_root["audit_log"],
        "ct_log": s7_root["ct_log"],
    }


def _issue_leaf(inter, cn, template="server", sans=None, validity=365):
    from micropki.ca import RootCA
    ca = RootCA(str(inter["out_dir"]), create_layout=False,
                audit=inter["audit"])
    cert = ca.issue_cert(
        ca_cert_path=str(inter["cert"]),
        ca_key_path=str(inter["key"]),
        ca_passphrase=inter["pass"],
        template=template,
        subject=f"CN={cn},O=Test Org",
        sans=sans or [f"dns:{cn}"],
        out_dir=str(inter["out_dir"] / "leaf"),
        validity_days=validity,
        key_type="rsa",
        db_path=inter["db"],
    )
    return cert, inter["out_dir"] / "leaf" / f"{cn}.cert.pem"


def _leaf_dir(root):
    p = root["out_dir"] / "leaf"
    p.mkdir(parents=True, exist_ok=True)
    return p


# =====================================================================
# TEST-51: policy — weak RSA key via CSR
# =====================================================================

def test_policy_weak_rsa_csr(s7_root, s7_inter, temp_dir):
    """TEST-51: CSR with RSA-1024 must be rejected + AUDIT failure."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(
            x509.NameOID.COMMON_NAME, "weak.example.com")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("weak.example.com")]),
            critical=False)
        .sign(key, hashes.SHA256())
    )
    csr_path = temp_dir / "weak.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    r = run_cli(["ca", "issue-cert",
                 "--ca-cert", str(s7_inter["cert"]),
                 "--ca-key", str(s7_inter["key"]),
                 "--ca-pass-file", str(s7_inter["pass_file"]),
                 "--template", "server",
                 "--subject", "ignored",
                 "--san", "dns:weak.example.com",
                 "--csr", str(csr_path),
                 "--out-dir", str(_leaf_dir(s7_root)),
                 "--db-path", str(s7_root["db"]),
                 "--audit-log", str(s7_root["audit_log"]),
                 "--log-file", str(temp_dir / "ca.log")])
    assert r.returncode != 0

    log = s7_root["audit_log"].read_text()
    assert "issue_certificate" in log
    assert "failure" in log


# =====================================================================
# TEST-52: policy — validity too long
# =====================================================================

def test_policy_validity_too_long(s7_root, s7_inter):
    """TEST-52: leaf validity > 365d must be rejected + AUDIT failure."""
    from micropki.ca import RootCA
    from micropki.policy import PolicyViolation

    ca = RootCA(str(s7_root["out_dir"]), create_layout=False,
                audit=s7_root["audit"])
    with pytest.raises(PolicyViolation):
        ca.issue_cert(
            ca_cert_path=str(s7_inter["cert"]),
            ca_key_path=str(s7_inter["key"]),
            ca_passphrase=s7_inter["pass"],
            template="server",
            subject="CN=long.example.com",
            sans=["dns:long.example.com"],
            out_dir=str(_leaf_dir(s7_root)),
            validity_days=400,
            key_type="rsa",
            db_path=s7_root["db"],
        )

    log = s7_root["audit_log"].read_text()
    assert "issue_certificate" in log
    assert "failure" in log


# =====================================================================
# TEST-53: policy — wildcard SAN in server
# =====================================================================

def test_policy_wildcard_server(s7_root, s7_inter):
    from micropki.ca import RootCA
    from micropki.policy import PolicyViolation

    ca = RootCA(str(s7_root["out_dir"]), create_layout=False,
                audit=s7_root["audit"])
    with pytest.raises(PolicyViolation):
        ca.issue_cert(
            ca_cert_path=str(s7_inter["cert"]),
            ca_key_path=str(s7_inter["key"]),
            ca_passphrase=s7_inter["pass"],
            template="server",
            subject="CN=wild.example.com",
            sans=["dns:*.example.com"],
            out_dir=str(_leaf_dir(s7_root)),
            validity_days=365,
            key_type="rsa",
            db_path=s7_root["db"],
        )


# =====================================================================
# TEST-54: policy — forbidden SAN type for code_signing
# =====================================================================

def test_policy_code_signing_email_san(s7_root, s7_inter):
    from micropki.ca import RootCA
    from micropki.policy import PolicyViolation

    ca = RootCA(str(s7_root["out_dir"]), create_layout=False,
                audit=s7_root["audit"])
    with pytest.raises((PolicyViolation, ValueError, Exception)):
        ca.issue_cert(
            ca_cert_path=str(s7_inter["cert"]),
            ca_key_path=str(s7_inter["key"]),
            ca_passphrase=s7_inter["pass"],
            template="code_signing",
            subject="CN=signer",
            sans=["email:a@b.c"],
            out_dir=str(_leaf_dir(s7_root)),
            validity_days=365,
            key_type="rsa",
            db_path=s7_root["db"],
        )


# =====================================================================
# TEST-55/56: audit tamper detection
# =====================================================================

def test_audit_verify_clean(s7_root, s7_inter):
    _issue_leaf(s7_inter, "audit1.example.com")
    _issue_leaf(s7_inter, "audit2.example.com")
    from micropki.audit import verify_audit
    r = verify_audit(s7_root["audit_log"])
    assert r["ok"] is True
    assert r["records"] >= 4


def test_audit_tamper_detected(s7_root, s7_inter):
    _issue_leaf(s7_inter, "tamper1.example.com")
    _issue_leaf(s7_inter, "tamper2.example.com")
    log_path = s7_root["audit_log"]
    data = log_path.read_bytes()
    idx = len(data) // 2
    tampered = data[:idx] + bytes([data[idx] ^ 0x01]) + data[idx+1:]
    log_path.write_bytes(tampered)

    r = run_cli(["audit", "verify", "--log-file", str(log_path)])
    assert r.returncode != 0


def test_audit_missing_record_detected(s7_root, s7_inter):
    _issue_leaf(s7_inter, "miss1.example.com")
    _issue_leaf(s7_inter, "miss2.example.com")
    _issue_leaf(s7_inter, "miss3.example.com")
    log_path = s7_root["audit_log"]
    lines = log_path.read_text().splitlines(keepends=True)
    assert len(lines) >= 4
    del lines[1]
    log_path.write_text("".join(lines))

    from micropki.audit import verify_audit
    r = verify_audit(log_path)
    assert r["ok"] is False
    assert "prev_hash" in r["error"] or "hash" in r["error"]


# =====================================================================
# TEST-57: compromise + block reuse
# =====================================================================

def test_compromise_and_block_reuse(s7_root, s7_inter, temp_dir):
    from micropki.compromise import mark_compromised

    cert, cert_path = _issue_leaf(s7_inter, "comp.example.com")
    serial_hex = format(cert.serial_number, "x")
    mark_compromised(db_path=s7_root["db"], cert=cert,
                     reason="keyCompromise")

    conn = sqlite3.connect(str(s7_root["db"]))
    try:
        row = conn.execute(
            "SELECT status, revocation_reason FROM certificates WHERE serial_hex=?",
            (serial_hex,)).fetchone()
        assert row[0] == "revoked"
        assert row[1].lower() == "keycompromise"
        ck = conn.execute(
            "SELECT * FROM compromised_keys WHERE certificate_serial=?",
            (serial_hex,)).fetchone()
        assert ck is not None
    finally:
        conn.close()

    key_pem = (s7_root["out_dir"] / "leaf" / "comp.example.com.key.pem").read_bytes()
    key = serialization.load_pem_private_key(key_pem, password=None,
                                             backend=default_backend())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, "reused.example.com")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("reused.example.com")]),
            critical=False)
        .sign(key, hashes.SHA256())
    )
    csr_path = temp_dir / "reused.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    from micropki.ca import RootCA
    from micropki.policy import PolicyViolation

    ca = RootCA(str(s7_root["out_dir"]), create_layout=False,
                audit=s7_root["audit"])
    with pytest.raises(PolicyViolation):
        ca.issue_cert(
            ca_cert_path=str(s7_inter["cert"]),
            ca_key_path=str(s7_inter["key"]),
            ca_passphrase=s7_inter["pass"],
            template="server",
            subject="ignored",
            sans=["dns:reused.example.com"],
            out_dir=str(s7_root["out_dir"] / "leaf"),
            validity_days=365,
            key_type="rsa",
            csr_path=str(csr_path),
            db_path=s7_root["db"],
        )


# =====================================================================
# TEST-58: rate limit
# =====================================================================

def test_rate_limit_repo(s7_root, s7_inter):
    from micropki.repository import serve

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    threading.Thread(
        target=serve,
        args=("127.0.0.1", port, s7_root["db"], s7_root["out_dir"] / "certs"),
        kwargs=dict(rate_limit=1.0, rate_burst=2),
        daemon=True,
    ).start()
    _wait_port(port)

    codes = []
    for _ in range(5):
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/ca/root", timeout=5) as r:
                codes.append(r.status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)

    assert codes.count(200) >= 2
    assert codes.count(429) >= 2


# =====================================================================
# TEST-59: CT log
# =====================================================================

def test_ct_log_contains_serial(s7_root, s7_inter):
    cert, _ = _issue_leaf(s7_inter, "ct.example.com")
    serial_hex = format(cert.serial_number, "x")
    ct = s7_root["ct_log"]
    assert ct.is_file(), f"ct.log not found at {ct}"
    text = ct.read_text()
    assert serial_hex in text

    r = run_cli(["audit", "ct-verify",
                 "--ct-log", str(ct), serial_hex])
    assert r.returncode == 0
    assert "in CT log" in r.stdout


def test_ct_log_missing_serial(s7_root, s7_inter):
    _issue_leaf(s7_inter, "ct2.example.com")
    r = run_cli(["audit", "ct-verify",
                 "--ct-log", str(s7_root["ct_log"]), "deadbeefcafe"])
    assert r.returncode != 0
    assert "NOT in CT log" in r.stdout


# =====================================================================
# Module: TokenBucket
# =====================================================================

def test_token_bucket():
    from micropki.ratelimit import TokenBucket
    tb = TokenBucket(rate_per_sec=1.0, burst=2)
    results = [tb.allow("1.2.3.4")[0] for _ in range(5)]
    assert results[0] is True
    assert results[1] is True
    assert results[2] is False
    assert results[3] is False
    assert results[4] is False


def test_token_bucket_disabled():
    from micropki.ratelimit import TokenBucket
    tb = TokenBucket(rate_per_sec=0.0, burst=0)
    for _ in range(10):
        assert tb.allow("1.2.3.4")[0] is True


# =====================================================================
# Module: policy
# =====================================================================

def test_policy_check_rsa_size():
    from micropki.policy import check_rsa_size, PolicyViolation
    check_rsa_size(4096, "root")
    with pytest.raises(PolicyViolation):
        check_rsa_size(2048, "root")
    with pytest.raises(PolicyViolation):
        check_rsa_size(1024, "leaf")


def test_policy_check_validity():
    from micropki.policy import check_validity, PolicyViolation
    check_validity(365, "leaf")
    with pytest.raises(PolicyViolation):
        check_validity(400, "leaf")
    with pytest.raises(PolicyViolation):
        check_validity(2000, "intermediate")


def test_policy_check_pathlen():
    from micropki.policy import check_pathlen, PolicyViolation
    check_pathlen(0, "intermediate")
    with pytest.raises(PolicyViolation):
        check_pathlen(1, "intermediate")


# =====================================================================
# Module: AuditLog + verify_audit
# =====================================================================

def test_audit_log_chain(s7_root):
    from micropki.audit import verify_audit
    r = verify_audit(s7_root["audit_log"])
    assert r["ok"] is True
    assert r["records"] >= 2

    lines = s7_root["audit_log"].read_text().strip().splitlines()
    first = json.loads(lines[0])
    assert first["integrity"]["prev_hash"] == "0" * 64
    assert len(first["integrity"]["hash"]) == 64


def test_audit_query_by_operation(s7_root, s7_inter):
    _issue_leaf(s7_inter, "query.example.com")
    r = run_cli(["audit", "query",
                 "--log-file", str(s7_root["audit_log"]),
                 "--operation", "issue_certificate",
                 "--format", "json"])
    assert r.returncode == 0
    rows = json.loads(r.stdout)
    assert len(rows) >= 1
    assert all("issue_certificate" in row["operation"] for row in rows)


# =====================================================================
# Module: compromise
# =====================================================================

def test_public_key_hash_consistent(s7_root, s7_inter):
    from micropki.compromise import public_key_hash
    cert, _ = _issue_leaf(s7_inter, "hash.example.com")
    h1 = public_key_hash(cert)
    h2 = public_key_hash(cert.public_key())
    assert h1 == h2
    assert len(h1) == 64


# =====================================================================
# Could / N/A — skip
# =====================================================================

@pytest.mark.skip(reason="AUD-5 (rotation) is Could")
def test_audit_rotation():
    pass


@pytest.mark.skip(reason="CTL-5 (anomaly detection) is Could")
def test_detect_anomalies():
    pass


# =====================================================================
# helpers
# =====================================================================

def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    pytest.fail("server did not start in time")
