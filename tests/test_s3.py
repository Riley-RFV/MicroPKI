import io
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

from s2_fixt import run_cli, clean

@pytest.fixture
def s3_db_path(temp_dir):
    """A DB file inside the per-test temp dir."""
    return temp_dir / "micropki.db"

@pytest.fixture
def s3_root_ca(temp_dir, passphrase_file, s3_db_path):
    from micropki.ca import RootCA
    from micropki.database import init_db

    init_db(s3_db_path)
    ca = RootCA(str(temp_dir))
    ca.initialize(
        subject="CN=Sprint3 Root CA,O=Test Org",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=3650,
    )
    return {
        "out_dir": temp_dir,
        "cert": temp_dir / "certs" / "ca.cert.pem",
        "key": temp_dir / "private" / "ca.key.pem",
        "pass": passphrase_file.read_bytes(),
        "db": s3_db_path,
    }

@pytest.fixture
def s3_intermediate(s3_root_ca, passphrase_file):
    from micropki.ca import RootCA

    ca = RootCA(str(s3_root_ca["out_dir"]))
    cert = ca.issue_intermediate(
        root_cert_path=str(s3_root_ca["cert"]),
        root_key_path=str(s3_root_ca["key"]),
        root_passphrase=s3_root_ca["pass"],
        subject="CN=Sprint3 Intermediate CA,O=Test Org",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825,
        pathlen=0,
        db_path=s3_root_ca["db"],
    )
    return {
        "cert": s3_root_ca["out_dir"] / "certs" / "intermediate.cert.pem",
        "key": s3_root_ca["out_dir"] / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "x509": cert,
        "db": s3_root_ca["db"],
    }

@pytest.fixture
def s3_repo_server(s3_root_ca, s3_intermediate):
    from micropki.repository import serve

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    thread = threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(s3_root_ca["db"]),
              str(s3_root_ca["out_dir"] / "certs")),
        daemon=True,
    )
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)
    else:
        pytest.fail("repo server did not start in time")

    yield f"http://127.0.0.1:{port}"

def _http_get(url: str) -> tuple[int, bytes, dict]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)

def _http_status(url: str, method: str = "GET") -> int:
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code

def _issue_leaf(intermediate, out_dir, cn, template="server", sans=None,
                key_type="rsa"):
    from micropki.ca import RootCA
    ca = RootCA(str(out_dir), create_layout=False)
    cert = ca.issue_cert(
        ca_cert_path=str(intermediate["cert"]),
        ca_key_path=str(intermediate["key"]),
        ca_passphrase=intermediate["pass"],
        template=template,
        subject=f"CN={cn},O=Test Org",
        sans=sans or [f"dns:{cn}"],
        out_dir=str(out_dir / "leaf"),
        validity_days=365,
        key_type=key_type,
        db_path=intermediate["db"],
    )
    return cert, out_dir / "leaf" / f"{cn}.cert.pem"

def test_generate_serial_positive_and_64bit():
    from micropki.serial import generate_serial
    for _ in range(20):
        s = generate_serial()
        assert isinstance(s, int)
        assert s > 0
        assert s < (1 << 64)

def test_generate_serial_uniqueness_in_db(s3_root_ca):
    from micropki.database import connect
    from micropki.serial import generate_serial

    conn = connect(s3_root_ca["db"])
    try:
        seen = set()
        for _ in range(100):
            v = generate_serial(conn)
            assert v not in seen
            seen.add(v)
    finally:
        conn.close()

def test_serial_hex_roundtrip():
    from micropki.serial import to_hex, from_hex
    v = 0x6ae374da792a250c
    assert from_hex(to_hex(v)) == v
    assert from_hex("0x" + to_hex(v)) == v

def test_init_db_creates_schema(s3_db_path):
    from micropki.database import init_db
    init_db(s3_db_path)
    conn = sqlite3.connect(str(s3_db_path))
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "certificates" in tables
        cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)")}
        for c in ("serial_hex", "subject", "issuer", "not_before", "not_after",
                  "cert_pem", "status", "revocation_reason", "revocation_date",
                  "created_at"):
            assert c in cols, c
    finally:
        conn.close()

def test_init_db_is_idempotent(s3_db_path):
    from micropki.database import init_db
    init_db(s3_db_path)
    init_db(s3_db_path)  # must not raise
    assert s3_db_path.is_file()

def test_serial_hex_unique_constraint(s3_db_path):
    from micropki.database import init_db, connect, insert_certificate
    init_db(s3_db_path)
    conn = connect(s3_db_path)
    try:
        insert_certificate(
            conn, serial_hex="deadbeef", subject="CN=A", issuer="CN=Issuer",
            not_before="2026-01-01T00:00:00+00:00",
            not_after="2027-01-01T00:00:00+00:00",
            cert_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        with pytest.raises(sqlite3.IntegrityError):
            insert_certificate(
                conn, serial_hex="deadbeef", subject="CN=B", issuer="CN=Issuer",
                not_before="2026-01-01T00:00:00+00:00",
                not_after="2027-01-01T00:00:00+00:00",
                cert_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            )
    finally:
        conn.close()

def test_get_certificate_by_serial_case_insensitive(s3_intermediate):
    from micropki.database import connect, get_certificate_by_serial
    serial_hex = format(s3_intermediate["x509"].serial_number, "x")
    conn = connect(s3_intermediate["db"])
    try:
        row_lower = get_certificate_by_serial(conn, serial_hex)
        row_upper = get_certificate_by_serial(conn, serial_hex.upper())
        row_0x = get_certificate_by_serial(conn, "0x" + serial_hex)
    finally:
        conn.close()
    assert row_lower is not None
    assert row_upper is not None
    assert row_0x is not None
    assert row_lower["serial_hex"] == serial_hex

def test_list_certificates_filters(s3_intermediate):
    from micropki.database import connect, list_certificates
    conn = connect(s3_intermediate["db"])
    try:
        all_rows = list_certificates(conn)
        valid_rows = list_certificates(conn, status="valid")
        revoked_rows = list_certificates(conn, status="revoked")
    finally:
        conn.close()
    assert len(all_rows) >= 1
    assert all(r["status"] == "valid" for r in valid_rows)
    assert revoked_rows == []

def test_update_status_stub(s3_intermediate):
    from micropki.database import connect, update_status, get_certificate_by_serial
    serial_hex = format(s3_intermediate["x509"].serial_number, "x")
    conn = connect(s3_intermediate["db"])
    try:
        update_status(conn, serial_hex, "revoked", reason="keyCompromise")
        row = get_certificate_by_serial(conn, serial_hex)
        assert row["status"] == "revoked"
        assert row["revocation_reason"] == "keyCompromise"
        assert row["revocation_date"] is not None
    finally:
        conn.close()

def test_list_revoked(s3_intermediate):
    from micropki.database import connect, update_status, list_revoked
    serial_hex = format(s3_intermediate["x509"].serial_number, "x")
    conn = connect(s3_intermediate["db"])
    try:
        update_status(conn, serial_hex, "revoked", reason="keyCompromise")
        revoked = list_revoked(conn)
        assert any(r["serial_hex"] == serial_hex for r in revoked)
    finally:
        conn.close()

def test_cli_db_init(temp_dir):
    db = temp_dir / "cli.db"
    result = run_cli(["db", "init", "--db-path", str(db),
                      "--log-file", str(temp_dir / "log.json")])
    assert result.returncode == 0, result.stderr
    assert db.is_file()

def test_cli_db_init_idempotent(temp_dir):
    db = temp_dir / "cli.db"
    log = temp_dir / "log.json"
    r1 = run_cli(["db", "init", "--db-path", str(db), "--log-file", str(log)])
    r2 = run_cli(["db", "init", "--db-path", str(db), "--log-file", str(log)])
    assert r1.returncode == 0
    assert r2.returncode == 0

def test_cli_list_certs_table(s3_intermediate, s3_root_ca):
    log = s3_root_ca["out_dir"] / "ca.log"
    result = run_cli(["ca", "list-certs", "--db-path", str(s3_root_ca["db"]),
                      "--log-file", str(log)])
    assert result.returncode == 0, result.stderr
    assert "SERIAL_HEX" in result.stdout
    assert "valid" in result.stdout

def test_cli_list_certs_json(s3_intermediate, s3_root_ca):
    log = s3_root_ca["out_dir"] / "ca.log"
    result = run_cli(["ca", "list-certs", "--db-path", str(s3_root_ca["db"]),
                      "--format", "json", "--log-file", str(log)])
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert all("serial_hex" in r for r in data)

def test_cli_list_certs_csv(s3_intermediate, s3_root_ca):
    log = s3_root_ca["out_dir"] / "ca.log"
    result = run_cli(["ca", "list-certs", "--db-path", str(s3_root_ca["db"]),
                      "--format", "csv", "--log-file", str(log)])
    assert result.returncode == 0, result.stderr
    header = result.stdout.splitlines()[0]
    assert "serial_hex" in header and "status" in header

def test_cli_show_cert_pem(s3_intermediate, s3_root_ca):
    serial_hex = format(s3_intermediate["x509"].serial_number, "x")
    log = s3_root_ca["out_dir"] / "ca.log"
    result = run_cli(["ca", "show-cert", serial_hex,
                      "--db-path", str(s3_root_ca["db"]),
                      "--log-file", str(log)])
    assert result.returncode == 0, result.stderr
    assert "-----BEGIN CERTIFICATE-----" in result.stdout
    assert "-----END CERTIFICATE-----" in result.stdout

def test_cli_show_cert_unknown_serial(s3_root_ca):
    log = s3_root_ca["out_dir"] / "ca.log"
    result = run_cli(["ca", "show-cert", "deadbeefcafe",
                      "--db-path", str(s3_root_ca["db"]),
                      "--log-file", str(log)])
    assert result.returncode != 0

def test_cli_list_certs_missing_db(temp_dir):
    result = run_cli(["ca", "list-certs",
                      "--db-path", str(temp_dir / "nope.db"),
                      "--log-file", str(temp_dir / "log.json")])
    assert result.returncode != 0
    assert "not found" in clean(result.stdout + result.stderr)

def test_issue_inserts_into_db(s3_intermediate, s3_root_ca):
    from micropki.database import connect, list_certificates

    issued = [
        _issue_leaf(s3_intermediate, s3_root_ca["out_dir"], "a.example.com",
                    template="server", sans=["dns:a.example.com"]),
        _issue_leaf(s3_intermediate, s3_root_ca["out_dir"], "b.example.com",
                    template="server", sans=["dns:b.example.com", "ip:10.0.0.1"]),
        _issue_leaf(s3_intermediate, s3_root_ca["out_dir"], "alice",
                    template="client", sans=["email:alice@example.com"]),
        _issue_leaf(s3_intermediate, s3_root_ca["out_dir"], "bob",
                    template="client", sans=["email:bob@example.com"]),
        _issue_leaf(s3_intermediate, s3_root_ca["out_dir"], "signer",
                    template="code_signing", sans=[]),
    ]

    conn = connect(s3_root_ca["db"])
    try:
        rows = list_certificates(conn)
    finally:
        conn.close()

    assert len(rows) == 6
    serials = [r["serial_hex"] for r in rows]
    assert len(serials) == len(set(serials)), "serials must be unique"

    for cert, _ in issued:
        serial_hex = format(cert.serial_number, "x")
        assert serial_hex in serials
        row = next(r for r in rows if r["serial_hex"] == serial_hex)
        assert row["subject"]
        assert row["issuer"]
        assert row["not_before"]
        assert row["not_after"]
        assert row["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert row["status"] == "valid"
        assert row["revocation_reason"] is None
        assert row["revocation_date"] is None
        assert row["created_at"]

def test_cli_retrieval_matches_issued(s3_intermediate, s3_root_ca):
    cert, _ = _issue_leaf(s3_intermediate, s3_root_ca["out_dir"],
                          "cli-retrieval.example.com",
                          template="server",
                          sans=["dns:cli-retrieval.example.com"])
    serial_hex = format(cert.serial_number, "x")
    log = s3_root_ca["out_dir"] / "ca.log"

    listed = run_cli(["ca", "list-certs", "--db-path", str(s3_root_ca["db"]),
                      "--format", "json", "--log-file", str(log)])
    assert listed.returncode == 0
    data = json.loads(listed.stdout)
    match = [r for r in data if r["serial_hex"] == serial_hex]
    assert len(match) == 1
    assert "cli-retrieval.example.com" in match[0]["subject"]

    shown = run_cli(["ca", "show-cert", serial_hex,
                     "--db-path", str(s3_root_ca["db"]),
                     "--log-file", str(log)])
    assert shown.returncode == 0
    assert "-----BEGIN CERTIFICATE-----" in shown.stdout

def test_repo_get_certificate_matches_disk(s3_repo_server, s3_intermediate,
                                           s3_root_ca):
    cert, disk_path = _issue_leaf(s3_intermediate, s3_root_ca["out_dir"],
                                  "http.example.com",
                                  sans=["dns:http.example.com"])
    serial_hex = format(cert.serial_number, "x")

    status, body, headers = _http_get(
        f"{s3_repo_server}/certificate/{serial_hex}")
    assert status == 200
    assert "pem" in headers.get("Content-Type", "").lower() or \
           "text/plain" in headers.get("Content-Type", "").lower()
    assert headers.get("Access-Control-Allow-Origin") == "*"
    assert body == disk_path.read_bytes()


def test_repo_get_certificate_uppercase_serial(s3_repo_server, s3_intermediate,
                                               s3_root_ca):
    cert, disk_path = _issue_leaf(s3_intermediate, s3_root_ca["out_dir"],
                                  "http-upper.example.com",
                                  sans=["dns:http-upper.example.com"])
    serial_hex = format(cert.serial_number, "x").upper()
    status, body, _ = _http_get(f"{s3_repo_server}/certificate/{serial_hex}")
    assert status == 200
    assert body == disk_path.read_bytes()


def test_repo_get_certificate_404(s3_repo_server):
    status, _, _ = _http_get(f"{s3_repo_server}/certificate/deadbeefcafe")
    assert status == 404

def test_repo_get_ca_root(s3_repo_server, s3_root_ca):
    status, body, headers = _http_get(f"{s3_repo_server}/ca/root")
    assert status == 200
    assert body == s3_root_ca["cert"].read_bytes()
    assert "pem" in headers.get("Content-Type", "").lower()


def test_repo_get_ca_intermediate(s3_repo_server, s3_intermediate):
    status, body, headers = _http_get(f"{s3_repo_server}/ca/intermediate")
    assert status == 200
    assert body == s3_intermediate["cert"].read_bytes()

def test_repo_crl_returns_501(s3_repo_server):
    status, body, _ = _http_get(f"{s3_repo_server}/crl")
    assert status == 501
    assert b"not implemented" in body.lower()

def test_repo_bad_serial_400(s3_repo_server):
    status, _, _ = _http_get(f"{s3_repo_server}/certificate/XYZ")
    assert status == 400

def test_repo_post_returns_405(s3_repo_server):
    assert _http_status(f"{s3_repo_server}/ca/root", method="POST") == 405
    assert _http_status(f"{s3_repo_server}/certificate/abc", method="PUT") == 405

def test_repo_unknown_ca_404(s3_repo_server):
    status, _, _ = _http_get(f"{s3_repo_server}/ca/root/ca")
    assert status == 404

def test_cli_repo_status_port_open(s3_repo_server):
    url = s3_repo_server  # http://127.0.0.1:<port>
    port = int(url.rsplit(":", 1)[1])
    result = run_cli(["repo", "status", "--host", "127.0.0.1",
                      "--port", str(port),
                      "--log-file", str(Path("/tmp") / "repo-status.log")])
    assert result.returncode == 0
    assert "running" in clean(result.stdout)


def test_cli_repo_status_port_closed(temp_dir):
    result = run_cli(["repo", "status", "--host", "127.0.0.1",
                      "--port", "1",
                      "--log-file", str(temp_dir / "log.json")])
    assert result.returncode != 0
    assert "not running" in clean(result.stdout)

def test_issue_100_unique_serials(s3_intermediate, s3_root_ca):
    from micropki.database import connect, list_certificates

    for i in range(100):
        _issue_leaf(s3_intermediate, s3_root_ca["out_dir"],
                    f"many{i:03d}.example.com",
                    template="server",
                    sans=[f"dns:many{i:03d}.example.com"])

    conn = connect(s3_root_ca["db"])
    try:
        rows = list_certificates(conn)
    finally:
        conn.close()

    assert len(rows) == 101
    serials = [r["serial_hex"] for r in rows]
    assert len(serials) == len(set(serials))

def test_e2e_full_workflow(temp_dir, passphrase_file):
    """TEST-20: db init -> issue-intermediate -> 3 leaves -> repo -> GET -> compare."""
    from micropki.ca import RootCA
    from micropki.database import init_db, connect, list_certificates
    from micropki.repository import serve

    db = temp_dir / "micropki.db"
    log = temp_dir / "ca.log"

    init_db(db)

    root = RootCA(str(temp_dir))
    root.initialize(
        subject="CN=E2E Root CA,O=Test",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=3650,
    )
    inter_cert = root.issue_intermediate(
        root_cert_path=str(temp_dir / "certs" / "ca.cert.pem"),
        root_key_path=str(temp_dir / "private" / "ca.key.pem"),
        root_passphrase=passphrase_file.read_bytes(),
        subject="CN=E2E Intermediate,O=Test",
        key_type="rsa", key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825, pathlen=0, db_path=db,
    )
    inter = {
        "cert": temp_dir / "certs" / "intermediate.cert.pem",
        "key": temp_dir / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "db": db,
    }

    issued = [
        _issue_leaf(inter, temp_dir, "e2e-a.example.com",
                    template="server", sans=["dns:e2e-a.example.com"]),
        _issue_leaf(inter, temp_dir, "e2e-b.example.com",
                    template="server", sans=["dns:e2e-b.example.com"]),
        _issue_leaf(inter, temp_dir, "e2e-client",
                    template="client", sans=["email:e2e@example.com"]),
    ]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    thread = threading.Thread(
        target=serve,
        args=("127.0.0.1", port, str(db), str(temp_dir / "certs")),
        daemon=True,
    )
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)
    else:
        pytest.fail("repo server did not start")

    cert, disk = issued[0]
    serial_hex = format(cert.serial_number, "x")
    status, body, _ = _http_get(f"http://127.0.0.1:{port}/certificate/{serial_hex}")
    assert status == 200
    assert body == disk.read_bytes()

    status, body, _ = _http_get(f"http://127.0.0.1:{port}/ca/root")
    assert status == 200
    assert body == (temp_dir / "certs" / "ca.cert.pem").read_bytes()

    status, body, _ = _http_get(f"http://127.0.0.1:{port}/ca/intermediate")
    assert status == 200
    assert body == (temp_dir / "certs" / "intermediate.cert.pem").read_bytes()

    conn = connect(db)
    try:
        rows = list_certificates(conn)
    finally:
        conn.close()
    assert len(rows) == 4
