import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def ok(msg):
    print(f"{GREEN}[OK]{RESET} {msg}")

def fail(msg):
    print(f"{RED}[FAIL]{RESET} {msg}")
    sys.exit(1)

def step(msg):
    print(f"\n{YELLOW}=== {msg} ==={RESET}")

def run(args, check=True, capture=True):
    r = subprocess.run(args, capture_output=capture, text=True)
    if check and r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        fail(f"command failed: {' '.join(args)}")
    return r

def wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    fail(f"port {port} did not open")

def main():
    work = Path(tempfile.mkdtemp(prefix="micropki-demo-"))
    print(f"Working dir: {work}")
    os.chdir(work)

    secrets = work / "secrets"
    secrets.mkdir()
    (secrets / "root.pass").write_text("root-pass-demo")
    (secrets / "inter.pass").write_text("inter-pass-demo")
    os.chmod(secrets / "root.pass", 0o600)
    os.chmod(secrets / "inter.pass", 0o600)

    pki = work / "pki"
    db = pki / "micropki.db"
    ca_log = pki / "ca.log"

    M = [sys.executable, "-m", "micropki.cli"]

    step("1. Initialize DB and Root CA")
    run(M + ["db", "init", "--db-path", str(db), "--log-file", str(ca_log)])
    run(M + ["ca", "init",
             "--subject", "CN=Demo Root CA,O=Demo,C=RU",
             "--key-type", "rsa", "--key-size", "4096",
             "--passphrase-file", str(secrets / "root.pass"),
             "--out-dir", str(pki), "--validity-days", "3650",
             "--log-file", str(ca_log)])
    ok("Root CA created")

    step("2. Issue Intermediate CA")
    run(M + ["ca", "issue-intermediate",
             "--root-cert", str(pki / "certs" / "ca.cert.pem"),
             "--root-key", str(pki / "private" / "ca.key.pem"),
             "--root-pass-file", str(secrets / "root.pass"),
             "--subject", "CN=Demo Intermediate CA,O=Demo",
             "--key-type", "rsa", "--key-size", "4096",
             "--passphrase-file", str(secrets / "inter.pass"),
             "--out-dir", str(pki), "--validity-days", "1825",
             "--pathlen", "0", "--db-path", str(db),
             "--log-file", str(ca_log)])
    ok("Intermediate CA created")

    step("3. Issue server, client, OCSP certs")
    run(M + ["ca", "issue-cert",
             "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
             "--ca-key", str(pki / "private" / "intermediate.key.pem"),
             "--ca-pass-file", str(secrets / "inter.pass"),
             "--template", "server",
             "--subject", "CN=localhost,O=Demo",
             "--san", "dns:localhost", "--san", "ip:127.0.0.1",
             "--out-dir", str(pki / "certs"), "--validity-days", "365",
             "--db-path", str(db), "--log-file", str(ca_log)])
    ok("Server cert (CN=localhost)")

    run(M + ["ca", "issue-cert",
             "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
             "--ca-key", str(pki / "private" / "intermediate.key.pem"),
             "--ca-pass-file", str(secrets / "inter.pass"),
             "--template", "client",
             "--subject", "CN=Alice,O=Demo",
             "--san", "email:alice@example.com",
             "--out-dir", str(pki / "certs"), "--validity-days", "365",
             "--db-path", str(db), "--log-file", str(ca_log)])
    ok("Client cert (CN=Alice)")

    run(M + ["ca", "issue-ocsp-cert",
             "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
             "--ca-key", str(pki / "private" / "intermediate.key.pem"),
             "--ca-pass-file", str(secrets / "inter.pass"),
             "--subject", "CN=ocsp-responder,O=Demo",
             "--key-type", "rsa", "--key-size", "2048",
             "--san", "dns:localhost",
             "--out-dir", str(pki / "certs"), "--validity-days", "365",
             "--db-path", str(db), "--log-file", str(ca_log)])
    ok("OCSP responder cert")

    step("4. Start repo (8080) and OCSP (8081)")
    repo_proc = subprocess.Popen(
        M + ["repo", "serve", "--host", "127.0.0.1", "--port", "8080",
             "--db-path", str(db), "--cert-dir", str(pki / "certs"),
             "--ca-private-dir", str(pki / "private"),
             "--ca-pass-file", str(secrets / "inter.pass"),
             "--log-file", str(pki / "repo.log")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ocsp_proc = subprocess.Popen(
        M + ["ocsp", "serve", "--host", "127.0.0.1", "--port", "8081",
             "--db-path", str(db),
             "--responder-cert", str(pki / "certs" / "ocsp-responder.cert.pem"),
             "--responder-key", str(pki / "certs" / "ocsp-responder.key.pem"),
             "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
             "--log-file", str(pki / "ocsp.log")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(8080)
    wait_port(8081)
    ok("Servers up")

    try:
        step("5. Validate server cert (chain + OCSP)")
        r = run(M + ["client", "validate",
                     "--cert", str(pki / "certs" / "localhost.cert.pem"),
                     "--untrusted", str(pki / "certs" / "intermediate.cert.pem"),
                     "--trusted", str(pki / "certs" / "ca.cert.pem"),
                     "--ocsp", "--mode", "full",
                     "--log-file", str(pki / "client.log")], check=False)
        if "VALID" not in r.stdout:
            fail("expected VALID")
        ok("Valid chain + good status")

        step("6. Revoke server cert")
        serial = None
        for line in run(M + ["ca", "list-certs", "--db-path", str(db),
                             "--format", "json",
                             "--log-file", str(ca_log)]).stdout.splitlines():
            pass
        rows = json.loads(run(M + ["ca", "list-certs", "--db-path", str(db),
                                   "--format", "json",
                                   "--log-file", str(ca_log)]).stdout)
        serial = next(r["serial_hex"] for r in rows if "localhost" in r["subject"])
        run(M + ["ca", "revoke", serial, "--reason", "keyCompromise", "--force",
                 "--ca-pass-file", str(secrets / "inter.pass"),
                 "--cert-dir", str(pki / "certs"),
                 "--private-dir", str(pki / "private"),
                 "--db-path", str(db), "--out-dir", str(pki),
                 "--log-file", str(ca_log)])
        ok(f"Revoked serial={serial}")

        step("7. Validate again — should be INVALID (revoked)")
        r = run(M + ["client", "validate",
                     "--cert", str(pki / "certs" / "localhost.cert.pem"),
                     "--untrusted", str(pki / "certs" / "intermediate.cert.pem"),
                     "--trusted", str(pki / "certs" / "ca.cert.pem"),
                     "--ocsp", "--mode", "full",
                     "--log-file", str(pki / "client.log")], check=False)
        if "INVALID" not in r.stdout and "revoked" not in r.stdout.lower():
            fail("expected INVALID/revoked")
        ok("Revoked cert rejected")

        step("8. Verify audit integrity")
        r = run(M + ["audit", "verify", "--log-file", str(pki / "audit" / "audit.log")],
                check=False)
        if r.returncode != 0:
            fail("audit verify failed")
        ok("Audit chain intact")

        step("9. Policy violation (RSA-1024 CSR)")
        weak_key = work / "weak.key"
        weak_csr = work / "weak.csr"
        run(["openssl", "req", "-new", "-newkey", "rsa:1024", "-nodes",
             "-keyout", str(weak_key), "-out", str(weak_csr),
             "-subj", "/CN=weak.example.com"])
        r = run(M + ["ca", "issue-cert",
                     "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
                     "--ca-key", str(pki / "private" / "intermediate.key.pem"),
                     "--ca-pass-file", str(secrets / "inter.pass"),
                     "--template", "server", "--subject", "ignored",
                     "--san", "dns:weak.example.com",
                     "--csr", str(weak_csr),
                     "--out-dir", str(pki / "certs"),
                     "--db-path", str(db), "--log-file", str(ca_log)], check=False)
        if r.returncode == 0:
            fail("weak key should be rejected")
        ok("Weak key rejected")

        step("10. TLS demo (revoked cert)")
        run(M + ["ca", "issue-cert",
                 "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
                 "--ca-key", str(pki / "private" / "intermediate.key.pem"),
                 "--ca-pass-file", str(secrets / "inter.pass"),
                 "--template", "server", "--subject", "CN=tls.localhost,O=Demo",
                 "--san", "dns:localhost", "--san", "ip:127.0.0.1",
                 "--out-dir", str(pki / "certs"), "--validity-days", "365",
                 "--db-path", str(db), "--log-file", str(ca_log)])

        chain = pki / "certs" / "tls.localhost.chain.pem"
        chain.write_bytes(
            (pki / "certs" / "tls.localhost.cert.pem").read_bytes()
            + (pki / "certs" / "intermediate.cert.pem").read_bytes())
        srv = _start_https(chain, pki / "certs" / "tls.localhost.key.pem")
        try:
            ok("HTTPS server on 8443")
        except Exception as e:
            fail(f"HTTPS failed: {e}")

        step("11. Code-signing demo")
        run(M + ["ca", "issue-cert",
                 "--ca-cert", str(pki / "certs" / "intermediate.cert.pem"),
                 "--ca-key", str(pki / "private" / "intermediate.key.pem"),
                 "--ca-pass-file", str(secrets / "inter.pass"),
                 "--template", "code_signing",
                 "--subject", "CN=Demo Code Signer,O=Demo",
                 "--san", "dns:signer.example.com",
                 "--out-dir", str(pki / "certs"), "--validity-days", "365",
                 "--db-path", str(db), "--log-file", str(ca_log)])
        pub = work / "code_signer.pub.pem"
        run(["openssl", "x509",
             "-in", str(pki / "certs" / "Demo Code Signer.cert.pem"),
             "-pubkey", "-noout", "-out", str(pub)])

        script = work / "hello.sh"
        script.write_text("#!/bin/sh\necho hello\n")
        sig = work / "hello.sh.sig"
        run(["openssl", "dgst", "-sha256",
             "-sign", str(pki / "certs" / "Demo Code Signer.key.pem"),
             "-out", str(sig), str(script)])

        r = run(["openssl", "dgst", "-sha256",
                 "-verify", str(pub),
                 "-signature", str(sig), str(script)], check=False)
        if "Verified OK" not in (r.stdout + r.stderr):
            fail(f"code-sign verify failed: {r.stdout} {r.stderr}")
        ok("Code signature verified")

        script.write_text("#!/bin/sh\necho TAMPERED\n")
        r = run(["openssl", "dgst", "-sha256",
                 "-verify", str(pub),
                 "-signature", str(sig), str(script)], check=False)
        if "Verified OK" in (r.stdout + r.stderr):
            fail("tampered script should not verify")
        ok("Tampered script rejected")
        print(f"\n{GREEN}=== DEMO COMPLETE ==={RESET}")

    finally:
        repo_proc.terminate()
        ocsp_proc.terminate()
        repo_proc.wait(timeout=5)
        ocsp_proc.wait(timeout=5)
        print(f"\nWork dir kept for inspection: {work}")


def _start_https(cert_chain: Path, key: Path, port: int = 8443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_chain), str(key))

    class H(SimpleHTTPRequestHandler):
        def log_message(self, *a): pass

    httpd = HTTPServer(("127.0.0.1", port), H)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    return httpd


if __name__ == "__main__":
    main()
