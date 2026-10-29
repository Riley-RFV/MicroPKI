import logging
import re
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .database import connect, get_certificate_by_serial
from .logger import log_event

logger = logging.getLogger("pki_audit")

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
PEM_CT = "application/x-pem-file"


def make_handler(db_path: Path, cert_dir: Path):
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

        def do_GET(self):
            path = urlparse(self.path).path
            if path.startswith("/certificate/"):
                return self._cert(path[len("/certificate/"):])
            if path == "/ca/root":
                return self._ca("ca.cert.pem")
            if path == "/ca/intermediate":
                return self._ca("intermediate.cert.pem")
            if path == "/crl":
                return self._send(501,
                                  b"CRL generation is not implemented yet\n",
                                  "text/plain")
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

        do_POST = do_PUT = do_DELETE = do_PATCH = _method_not_allowed

    return Handler


def serve(host: str, port: int, db_path: Path, cert_dir: Path) -> None:
    handler = make_handler(Path(db_path), Path(cert_dir))
    httpd = HTTPServer((host, port), handler)
    log_event(logger, logging.INFO, "Repository server started",
              host=host, port=port,
              db_path=str(db_path), cert_dir=str(cert_dir))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event(logger, logging.INFO, "Repository server stopped (KeyboardInterrupt)")
    finally:
        httpd.server_close()


def probe_status(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0
