import logging
import re
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from .database import connect, get_certificate_by_serial
from .logger import log_event
import email.utils
import hashlib
import time
import tempfile
from .ca import RootCA
from cryptography.hazmat.primitives import serialization
from .ratelimit import TokenBucket
from .audit import AuditLog

logger = logging.getLogger("pki_audit")

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
PEM_CT = "application/x-pem-file"



def make_handler(db_path: Path, cert_dir: Path, *, ca_private_dir: Path | None = None,
                 ca_pass_file: Path | None = None, api_key: str | None = None,
                 rate_limit: float = 0.0, rate_burst: int = 10,
                 audit_log: Path | None=None):
    ca_private_dir = ca_private_dir or cert_dir.parent / "private"
    audit = AuditLog(audit_log or (cert_dir.parent / "audit" / "audit.log"))
    limiter = TokenBucket(rate_limit, rate_burst)
    class Handler(BaseHTTPRequestHandler):
        server_version = "MicroPKI-Repo/1.0"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, body: bytes, content_type: str):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Access-Control-Allow-Origin", "*")  # REPO-7
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

            log_event(logger, logging.INFO,
                      f"[HTTP] {self.command} {self.path}",
                      client=self.client_address[0], status=code)
        
        def _check_limit(self) -> bool:
            ip = self.client_address[0]
            allowed, retry = limiter.allow(ip)
            if not allowed:
                self.send_response(429)
                self.send_header("Retry-After", str(retry))
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "0")
                self.end_headers()
                log_event(logger, logging.WARNING, "[HTTP] 429 rate limit",
                          client=ip, path=self.path, retry_after=retry)
                return False
            return True

        def do_GET(self):
            if not self._check_limit():
                return
            path = urlparse(self.path).path
            if path.startswith("/certificate/"):
                return self._cert(path[len("/certificate/"):])
            if path == "/ca/root":
                return self._ca("ca.cert.pem")
            if path == "/ca/intermediate":
                return self._ca("intermediate.cert.pem")
            if path == "/crl":
              return self._crl(parse_qs(urlparse(self.path).query))
            if path.startswith("/crl/") and path.endswith(".crl"):
              label = path[len("/crl/"):-len(".crl")]
              return self._crl({"ca": [label]})
            return self._send(404, b"Not found\n", "text/plain")

        def _cert(self, serial: str):
            if not serial or not HEX_RE.match(serial):
                return self._send(400, b"Invalid serial number\n", "text/plain")
            conn = connect(db_path)
            try:
                row = get_certificate_by_serial(conn, serial)
            finally:
                conn.close()
            if row is None:
                return self._send(404, b"Certificate not found\n", "text/plain")
            self._send(200, row["cert_pem"].encode(), PEM_CT)

        def _ca(self, filename: str):
            p = cert_dir / filename
            if not p.is_file():
                return self._send(404, b"CA certificate not found\n", "text/plain")
            self._send(200, p.read_bytes(), PEM_CT)

        def _method_not_allowed(self):
            self._send(405, b"Method not allowed\n", "text/plain")

        def _crl(self, query: dict):
            ca = (query.get("ca", [None])[0] or "intermediate").lower()
            if ca not in ("root", "intermediate"):
                return self._send(400, b"Unknown CA (expected root|intermediate)\n",
                                  "text/plain")
            crl_path = cert_dir.parent / "crl" / f"{ca}.crl.pem"
            if not crl_path.is_file():
                return self._send(404, b"CRL not found\n", "text/plain")

            body = crl_path.read_bytes()
            stat = crl_path.stat()
            etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'

            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Last-Modified",
                             email.utils.formatdate(stat.st_mtime, usegmt=True))
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "max-age=3600")
            self.end_headers()
            self.wfile.write(body)
            log_event(logger, logging.INFO,
                      f"[HTTP] {self.command} {self.path}",
                      client=self.client_address[0], status=200)

        def do_POST(self):
            if not self._check_limit():
              return
            path = urlparse(self.path).path
            if path == "/request-cert":
                return self._request_cert(urlparse(self.path).query)
            self._send(405, b"Method not allowed\n", "text/plain")

        def _request_cert(self, query: str):
            q = parse_qs(query)
            template = (q.get("template", ["server"])[0])
            if template not in ("server", "client", "code_signing"):
                return self._send(400, b"Invalid template\n", "text/plain")
            if api_key and self.headers.get("X-API-Key") != api_key:
                return self._send(401, b"Unauthorized\n", "text/plain")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return self._send(400, b"Empty body\n", "text/plain")
            csr_pem = self.rfile.read(length)
            
            tmp_dir = Path(tempfile.mkdtemp())
            tmp = tmp_dir / "external.csr.pem"
            tmp.write_bytes(csr_pem)
            try:
                ca = RootCA(str(cert_dir.parent), create_layout=False, audit=audit)
                cert = ca.issue_cert(
                    ca_cert_path=str(cert_dir / "intermediate.cert.pem"),
                    ca_key_path=str(ca_private_dir / "intermediate.key.pem"),
                    ca_passphrase=(ca_pass_file.read_bytes().strip()
                                   if ca_pass_file else b"CHANGE-ME"),
                    template=template,
                    subject="ignored", sans=[],
                    out_dir=str(cert_dir),
                    validity_days=365,
                    key_type="rsa",
                    csr_path=str(tmp),
                    db_path=db_path,
                )
            except Exception as e:
                log_event(logger, logging.ERROR, "request-cert failed", error=str(e))
                return self._send(400, f"CA error: {e}\n".encode(), "text/plain")
            finally:
                tmp.unlink(missing_ok=True)
                try:
                    tmp_dir.rmdir()
                except OSError:
                    pass

            body = cert.public_bytes(serialization.Encoding.PEM)
            log_event(logger, logging.INFO, "[HTTP] POST /request-cert",
                      client=self.client_address[0], status=201,
                      template=template, serial=hex(cert.serial_number))
            self._send(201, body, "application/x-pem-file")

        def do_PUT(self):
          self._send(405, b"Method not allowed\n", "text/plain")

        do_DELETE = do_PUT
        do_PATCH = do_PUT
    return Handler


def serve(host: str, port: int, db_path: Path, cert_dir: Path, *,
          ca_private_dir: Path | None = None,
          ca_pass_file: Path | None = None,
          api_key: str | None = None,
          rate_limit: float = 0.0,
          rate_burst: int = 10,
          audit_log: Path | None=None) -> None:
    handler = make_handler(
        Path(db_path), Path(cert_dir),
        ca_private_dir=Path(ca_private_dir) if ca_private_dir else None,
        ca_pass_file=Path(ca_pass_file) if ca_pass_file else None,
        api_key=api_key,
        rate_limit=rate_limit,
        rate_burst=rate_burst,
        audit_log=Path(audit_log) if audit_log else None,
    )
    httpd = HTTPServer((host, port), handler)
    log_event(logger, logging.INFO, "Repository server started",
              host=host, port=port, db_path=str(db_path),
              cert_dir=str(cert_dir),
              request_cert=bool(ca_pass_file))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event(logger, logging.INFO, "Repository server stopped")
    finally:
        httpd.server_close()


def probe_status(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0
