import hashlib
import logging
import sqlite3
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ocsp as x509_ocsp
from .database import connect, get_certificate_by_serial
from .logger import log_event
from .ocsp import (parse_ocsp_request, match_issuer, build_ocsp_response, build_error_response)
import traceback
from .ratelimit import TokenBucket

logger = logging.getLogger("pki_audit")

CT_REQUEST = "application/ocsp-request"
CT_RESPONSE = "application/ocsp-response"

class _Cache:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._store: dict[tuple, tuple[float, bytes]] = {}

    def _key(self, parsed, ca_cert, db_path, responder_cert):
        if parsed.nonce is not None or len(parsed.cert_ids) != 1:
            return None
        cid = parsed.cert_ids[0]
        return (
            cid["serial"],
            cid["hash_alg"],
            cid["issuer_name_hash"],
            cid["issuer_key_hash"],
            str(db_path),
            responder_cert.fingerprint(hashes.SHA256())
        )

    def get(self, key):
        if key is None:
            return None
        entry = self._store.get(key)
        if entry is None:
            return None
        exp, der = entry
        if time.time() >= exp:
            self._store.pop(key, None)
            return None
        return der

    def put(self, key, der):
        if key is None:
            return
        self._store[key] = (time.time() + self.ttl, der)

def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes(), default_backend())

def _load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None,
                                              backend=default_backend())

def _status_for_serial(db_path: Path, serial: int) -> dict:
    conn = connect(db_path)
    try:
        row = get_certificate_by_serial(conn, format(serial, "x"))
    finally:
        conn.close()
    if row is None:
        return {"status": "unknown"}
    cert = x509.load_pem_x509_certificate(
        row["cert_pem"].encode(), default_backend()
    )
    if row["status"] == "revoked":
        try:
            when = datetime.fromisoformat(row["revocation_date"])
        except (TypeError, ValueError):
            when = datetime.now(timezone.utc)
        return {"status": "revoked", "revoked_at": when,
                "reason": row["revocation_reason"], "cert": cert}
    return {"status": "good", "cert": cert}

def make_handler(db_path: Path, responder_cert_path: Path,
                 responder_key_path: Path, ca_cert_path: Path,
                 cache_ttl: int = 60,
                 rate_limit: float = 0.0,
                 rate_burst:  int = 10):

    responder_cert = _load_cert(responder_cert_path)
    responder_key = _load_key(responder_key_path)
    ca_cert = _load_cert(ca_cert_path)
    cache = _Cache(cache_ttl)
    limiter = TokenBucket(rate_limit, rate_burst)

    root_cert = None
    root_path = ca_cert_path.parent / "ca.cert.pem"
    if root_path.is_file() and root_path != ca_cert_path:
        try:
            root_cert = _load_cert(root_path)
        except Exception:
            root_cert = None

    known_issuers = [ca_cert] + ([root_cert] if root_cert else [])

    class Handler(BaseHTTPRequestHandler):
        server_version = "MicroPKI-OCSP/1.0"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body: bytes, content_type: str):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
            if urlparse(self.path).path == "/":
                return self._send(200, b"MicroPKI OCSP responder\n", "text/plain")
            return self._send(405, b"Method not allowed\n", "text/plain")

        def do_POST(self):
            if not self._check_limit():
                return
            started = time.time()
            path = urlparse(self.path).path
            if path not in ("/ocsp", "/"):
                return self._send(404, b"Not found\n", "text/plain")
            if self.headers.get("Content-Type", "").split(";")[0] != CT_REQUEST:
                return self._send(400, b"Expected Content-Type: application/ocsp-request\n",
                                  "text/plain")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return self._send(400, b"Empty body\n", "text/plain")
            der = self.rfile.read(length)

            try:
                parsed = parse_ocsp_request(der)
            except ValueError as e:
                log_event(logger, logging.WARNING, "Malformed OCSP request",
                          client=self.client_address[0], error=str(e))
                body = build_error_response(x509_ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
                return self._send(200, body, CT_RESPONSE)

            key = cache._key(parsed, ca_cert, db_path, responder_cert)
            cached = cache.get(key)
            if cached is not None:
                log_event(logger, logging.INFO, "OCSP cache hit",
                          client=self.client_address[0],
                          serials=[cid["serial"] for cid in parsed.cert_ids])
                return self._send(200, cached, CT_RESPONSE)

            try:
                matches = match_issuer(parsed.cert_ids, known_issuers)
                if not matches:
                    log_event(logger, logging.WARNING,
                              "OCSP: no known issuer for any CertID",
                              client=self.client_address[0],
                              serials=[cid["serial"] for cid in parsed.cert_ids])
                    body = build_error_response(x509_ocsp.OCSPResponseStatus.UNAUTHORIZED)
                    return self._send(200, body, CT_RESPONSE)
                statuses = {}
                for cid in parsed.cert_ids:
                    statuses[cid["serial"]] = _status_for_serial(db_path, cid["serial"])

                body = build_ocsp_response(
                    request=parsed,
                    responder_cert=responder_cert,
                    responder_key=responder_key,
                    issuer_for_serial=matches,
                    status_by_serial=statuses,
                    cache_ttl=cache_ttl,
                )
            except Exception as e:
                log_event(logger, logging.ERROR, "OCSP internal error",
                          client=self.client_address[0], error=str(e))
                body = build_error_response(x509_ocsp.OCSPResponseStatus.INTERNAL_ERROR)
                return self._send(200, body, CT_RESPONSE)

            cache.put(key, body)
            elapsed_ms = int((time.time() - started) * 1000)
            log_event(logger, logging.INFO, "OCSP response",
                      client=self.client_address[0],
                      serials=[cid["serial"] for cid in parsed.cert_ids],
                      statuses=[statuses[cid["serial"]]["status"]
                                for cid in parsed.cert_ids],
                      matched=len(matches),
                      elapsed_ms=elapsed_ms,
                      nonce=bool(parsed.nonce))
            self._send(200, body, CT_RESPONSE)

    return Handler

def serve(host: str, port: int, *, db_path: Path,
          responder_cert: Path, responder_key: Path,
          ca_cert: Path, cache_ttl: int = 60,
          rate_limit: float = 0.0,
          rate_burst: int = 10) -> None:
    handler = make_handler(Path(db_path), Path(responder_cert),
                           Path(responder_key), Path(ca_cert),
                           cache_ttl=cache_ttl,
                           rate_limit=rate_limit,
                           rate_burst=rate_burst)
    httpd = HTTPServer((host, port), handler)
    log_event(logger, logging.INFO, "OCSP responder started",
              host=host, port=port,
              responder_cert=str(responder_cert),
              ca_cert=str(ca_cert), cache_ttl=cache_ttl)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event(logger, logging.INFO, "OCSP responder stopped (KeyboardInterrupt)")
    finally:
        httpd.server_close()
