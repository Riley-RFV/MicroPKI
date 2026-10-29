import argparse
import sys
from pathlib import Path
from .ca import RootCA
import logging
from .logger import log_event, setup_logger
from .chain import verify_chain
import csv
import json
from .database import init_db, connect, get_certificate_by_serial, list_certificates
import io
from .repository import serve
from .repository import probe_status

logger = logging.getLogger("pki_audit")

DEFAULT_DB = "./pki/micropki.db"

def get_passphrase(path: str) -> bytes:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise FileNotFoundError(f"Passphrase file not found: {path}")

    with open(file_path, "rb") as f:
        passphrase = f.read().strip()

    if not passphrase:
        raise ValueError("Passphrase file is empty")

    return passphrase

def _resolve_key_size(args) -> int:
    if args.key_size is None:
        args.key_size = 4096 if args.key_type == "rsa" else 384
    if args.key_type == "rsa" and args.key_size != 4096:
        raise ValueError("For RSA, --key-size must be 4096")
    if args.key_type == "ecc" and args.key_size != 384:
        raise ValueError("For ECC, --key-size must be 384 (NIST P-384)")
    return args.key_size

def _single_subject(args) -> str:
    if len(args.subject) != 1:
        raise ValueError("Exactly one --subject is required")
    subject = args.subject[0].strip()
    if not subject:
        raise ValueError("--subject must be a non-empty string")
    return subject

def _fmt_table(rows) -> str:
    if not rows:
        return "(no certificates)\n"
    headers = ("serial_hex", "subject", "not_after", "status")
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(r[h])))
    line = "  ".join(h.upper().ljust(widths[h]) for h in headers)
    sep = "  ".join("-" * widths[h] for h in headers)
    out = [line, sep]
    for r in rows:
        out.append("  ".join(str(r[h]).ljust(widths[h]) for h in headers))
    return "\n".join(out) + "\n"

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MicroPKI - Minimal Public Key Infrastructure Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    ca_parser = subparsers.add_parser("ca", help="CA management commands")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")

    init_parser = ca_sub.add_parser("init", help="Initialize Root CA")
    init_parser.add_argument("--out-dir", type=str, default="./pki_data",
                             help="Output directory for CA files")
    init_parser.add_argument("--subject", type=str, required=True, action="append",
                             help="Subject DN (e.g., '/CN=My Root CA/O=My Org' or 'CN=My Root CA,O=My Org')")
    init_parser.add_argument("--validity-days", type=int, default=3650,
                             help="Certificate validity in days (default: 3650)")
    init_parser.add_argument("--passphrase-file", type=str, required=True,
                             help="Path to file containing encryption passphrase for private key")
    init_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa",
                             help="Key generation (rsa - 4096, ecc - 384)")
    init_parser.add_argument("--key-size", type=int, default=None,
                             help="Key size in bits (RSA: 4096, ECC: 384)")
    init_parser.add_argument("--log-file", type=str, default=None,
                             help="Path to log file")

    inter_parser = ca_sub.add_parser("issue-intermediate",
                                     help="Issue an intermediate CA certificate")
    inter_parser.add_argument("--root-cert", required=True,
                              help="Path to root CA certificate (PEM)")
    inter_parser.add_argument("--root-key", required=True,
                              help="Path to root CA encrypted private key (PEM)")
    inter_parser.add_argument("--root-pass-file", required=True,
                              help="Path to file with root key passphrase")
    inter_parser.add_argument("--subject", required=True, action="append",
                              help="Subject DN for the intermediate CA")
    inter_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    inter_parser.add_argument("--key-size", type=int, default=None)
    inter_parser.add_argument("--passphrase-file", required=True,
                              help="Path to file with passphrase for the intermediate key")
    inter_parser.add_argument("--out-dir", default="./pki",
                              help="Output directory (default: ./pki)")
    inter_parser.add_argument("--validity-days", type=int, default=1825,
                              help="Validity in days (default: 1825)")
    inter_parser.add_argument("--pathlen", type=int, default=0,
                              help="pathLenConstraint (default: 0)")
    inter_parser.add_argument("--db-path", default=DEFAULT_DB)
    inter_parser.add_argument("--log-file", default=None)

    issue_parser = ca_sub.add_parser("issue-cert",
                                     help="Issue a leaf certificate from an intermediate CA")
    issue_parser.add_argument("--ca-cert", required=True,
                              help="Path to intermediate CA certificate (PEM)")
    issue_parser.add_argument("--ca-key", required=True,
                              help="Path to intermediate CA encrypted private key (PEM)")
    issue_parser.add_argument("--ca-pass-file", required=True,
                              help="Path to file with intermediate key passphrase")
    issue_parser.add_argument("--template", choices=["server", "client", "code_signing"],
                              required=True)
    issue_parser.add_argument("--subject", required=True, action="append",
                              help="Subject DN for the leaf certificate")
    issue_parser.add_argument("--san", action="append", default=[],
                              help="SAN entry, e.g. dns:example.com, ip:1.2.3.4, email:a@b.c, uri:https://x")
    issue_parser.add_argument("--out-dir", default="./pki/certs",
                              help="Output directory (default: ./pki/certs)")
    issue_parser.add_argument("--validity-days", type=int, default=365,
                              help="Validity in days (default: 365)")
    issue_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa",
                              help="Leaf key type when generating a new key (ignored with --csr)")
    issue_parser.add_argument("--csr", default=None,
                              help="Sign an external CSR instead of generating a new key pair")
    issue_parser.add_argument("--db-path", default=DEFAULT_DB)
    issue_parser.add_argument("--log-file", default=None)

    chain_parser = ca_sub.add_parser("verify-chain",
                                     help="Verify a certificate chain: leaf -> intermediate -> root")
    chain_parser.add_argument("--leaf", required=True)
    chain_parser.add_argument("--intermediate", required=True)
    chain_parser.add_argument("--root", required=True)
    chain_parser.add_argument("--log-file", default=None)

    list_parser = ca_sub.add_parser("list-certs")
    list_parser.add_argument("--db-path", default=DEFAULT_DB)
    list_parser.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    list_parser.add_argument("--issuer", default=None)
    list_parser.add_argument("--date-from", dest="date_from", default=None)
    list_parser.add_argument("--date-to", dest="date_to", default=None)
    list_parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    list_parser.add_argument("--log-file", default=None)

    show_parser = ca_sub.add_parser("show-cert")
    show_parser.add_argument("serial", help="Certificate serial (hex, case-insensitive)")
    show_parser.add_argument("--db-path", default=DEFAULT_DB)
    show_parser.add_argument("--log-file", default=None)

    db_parser = subparsers.add_parser("db", help="Database management")
    db_sub = db_parser.add_subparsers(dest="db_command")
    db_init = db_sub.add_parser("init", help="Create SQLite schema (CLI-12)")
    db_init.add_argument("--db-path", default=DEFAULT_DB)
    db_init.add_argument("--log-file", default=None)

    repo_parser = subparsers.add_parser("repo", help="HTTP repository")
    repo_sub = repo_parser.add_subparsers(dest="repo_command")

    serve_parser = repo_sub.add_parser("serve", help="Start HTTP repository (CLI-15)")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--db-path", default=DEFAULT_DB)
    serve_parser.add_argument("--cert-dir", default="./pki/certs")
    serve_parser.add_argument("--log-file", default=None)

    status_parser = repo_sub.add_parser("status", help="Check if repo port is open (CLI-16)")
    status_parser.add_argument("--host", default="127.0.0.1")
    status_parser.add_argument("--port", type=int, default=8080)
    status_parser.add_argument("--log-file", default=None)

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    try:
        logger = setup_logger(log_path=getattr(args, "log_file", None))
    except Exception as e:
        print(f"Error: failed to initialize logger: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.command == "ca":
            if not getattr(args, "ca_command", None):
                parser.print_help()
                sys.exit(1)

            if args.ca_command == "init":
                subject = _single_subject(args)
                _resolve_key_size(args)
                if args.validity_days <= 0:
                    raise ValueError("--validity-days must be a positive integer")
                if not Path(args.passphrase_file).expanduser().is_file():
                    raise ValueError(f"Passphrase file not found: {args.passphrase_file}")
                log_event(logger, logging.INFO, "CLI command executed: ca init",
                          key_type=args.key_type, key_size=args.key_size,
                          out_dir=args.out_dir)
                passphrase = get_passphrase(args.passphrase_file)
                ca = RootCA(args.out_dir)
                ca.initialize(subject=subject, key_type=args.key_type,
                              key_size=args.key_size, passphrase=passphrase,
                              validity_days=args.validity_days)
                print(f"Root CA successfully initialized at {args.out_dir}")
                sys.exit(0)

            if args.ca_command == "issue-intermediate":
                subject = _single_subject(args)
                _resolve_key_size(args)
                if args.validity_days <= 0:
                    raise ValueError("--validity-days must be a positive integer")
                if args.pathlen < 0:
                    raise ValueError("--pathlen must be >= 0")
                for p in (args.root_cert, args.root_key,
                          args.root_pass_file, args.passphrase_file):
                    if not Path(p).expanduser().is_file():
                        raise ValueError(f"File not found: {p}")
                init_db(args.db_path)
                log_event(logger, logging.INFO, "CLI command executed: ca issue-intermediate",
                          key_type=args.key_type, key_size=args.key_size,
                          out_dir=args.out_dir, pathlen=args.pathlen,
                          db_path=args.db_path)
                root_pp = get_passphrase(args.root_pass_file)
                inter_pp = get_passphrase(args.passphrase_file)
                ca = RootCA(args.out_dir)
                cert = ca.issue_intermediate(
                    root_cert_path=args.root_cert, root_key_path=args.root_key,
                    root_passphrase=root_pp, subject=subject,
                    key_type=args.key_type, key_size=args.key_size,
                    passphrase=inter_pp, validity_days=args.validity_days,
                    pathlen=args.pathlen, db_path=args.db_path)
                print(f"Intermediate CA issued: serial={hex(cert.serial_number)}")
                sys.exit(0)

            if args.ca_command == "issue-cert":
                subject = _single_subject(args) if args.csr is None else (
                    args.subject[0] if args.subject else "")
                if args.validity_days <= 0:
                    raise ValueError("--validity-days must be a positive integer")
                for p in (args.ca_cert, args.ca_key, args.ca_pass_file):
                    if not Path(p).expanduser().is_file():
                        raise ValueError(f"File not found: {p}")
                if args.csr is not None and not Path(args.csr).expanduser().is_file():
                    raise ValueError(f"CSR file not found: {args.csr}")
                init_db(args.db_path)
                log_event(logger, logging.INFO, "CLI command executed: ca issue-cert",
                          template=args.template, key_type=args.key_type,
                          out_dir=args.out_dir, csr=args.csr,
                          sans=args.san, db_path=args.db_path)
                ca_pp = get_passphrase(args.ca_pass_file)
                ca = RootCA(args.out_dir, create_layout=False)
                cert = ca.issue_cert(
                    ca_cert_path=args.ca_cert, ca_key_path=args.ca_key,
                    ca_passphrase=ca_pp, template=args.template,
                    subject=subject, sans=args.san, out_dir=args.out_dir,
                    validity_days=args.validity_days, key_type=args.key_type,
                    csr_path=args.csr, db_path=args.db_path)
                print(f"Certificate issued: serial={hex(cert.serial_number)}")
                sys.exit(0)

            if args.ca_command == "verify-chain":
                ok = verify_chain(args.leaf, args.intermediate, args.root)
                print("Chain OK" if ok else "Chain INVALID")
                sys.exit(0 if ok else 1)

            if args.ca_command == "list-certs":
                if not Path(args.db_path).expanduser().is_file():
                    raise ValueError(f"Database not found: {args.db_path} "
                                     f"(run `db init --db-path {args.db_path}`)")
                conn = connect(args.db_path)
                try:
                    rows = list_certificates(conn, status=args.status,
                                             issuer=args.issuer,
                                             date_from=args.date_from,
                                             date_to=args.date_to)
                finally:
                    conn.close()
                if args.format == "json":
                    print(json.dumps([dict(r) for r in rows], indent=2))
                elif args.format == "csv":
                    buf = io.StringIO()
                    fields = ("serial_hex", "subject", "issuer", "not_before",
                              "not_after", "status")
                    w = csv.DictWriter(buf, fieldnames=fields)
                    w.writeheader()
                    for r in rows:
                        w.writerow({k: r[k] for k in fields})
                    print(buf.getvalue(), end="")
                else:
                    print(_fmt_table(rows), end="")
                log_event(logger, logging.INFO, "Listed certificates",
                          count=len(rows), status=args.status)
                sys.exit(0)

            if args.ca_command == "show-cert":
                if not Path(args.db_path).expanduser().is_file():
                    raise ValueError(f"Database not found: {args.db_path}")
                conn = connect(args.db_path)
                try:
                    row = get_certificate_by_serial(conn, args.serial)
                finally:
                    conn.close()
                if row is None:
                    log_event(logger, logging.WARNING,
                              "Certificate not found", serial=args.serial)
                    print(f"Certificate not found: {args.serial}", file=sys.stderr)
                    sys.exit(1)
                print(row["cert_pem"], end="" if row["cert_pem"].endswith("\n") else "\n")
                log_event(logger, logging.INFO, "Certificate fetched",
                          serial=args.serial)
                sys.exit(0)

        if args.command == "db":
            if not getattr(args, "db_command", None):
                parser.print_help()
                sys.exit(1)
            if args.db_command == "init":
                init_db(args.db_path)
                print(f"Database initialized at {args.db_path}")
                sys.exit(0)

        if args.command == "repo":
            if not getattr(args, "repo_command", None):
                parser.print_help()
                sys.exit(1)
            if args.repo_command == "serve":
                if not Path(args.db_path).expanduser().is_file():
                    raise ValueError(f"Database not found: {args.db_path} "
                                     f"(run `db init --db-path {args.db_path}`)")
                serve(args.host, args.port, args.db_path, args.cert_dir)
                sys.exit(0)
            if args.repo_command == "status":
                running = probe_status(args.host, args.port)
                print(f"Repository at {args.host}:{args.port} is "
                      f"{'running' if running else 'not running'}")
                sys.exit(0 if running else 1)

        parser.print_help()
        sys.exit(1)

    except ValueError as e:
        log_event(logger, logging.WARNING, "Validation failed", reason=str(e))
        print(f"Validation Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        log_event(logger, logging.ERROR, "Command failed", error=str(e))
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
