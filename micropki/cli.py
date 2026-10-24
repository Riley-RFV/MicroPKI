import argparse
import sys
import getpass
from pathlib import Path
from .ca import RootCA
import logging
from .logger import log_event, setup_logger

logger = logging.getLogger("pki_audit")

def get_passphrase(path: str) -> bytes:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise FileNotFoundError(f"Passphrase file not found: {path}")
    
    with open(file_path, "rb") as f:
        passphrase = f.read().strip()
        
    if not passphrase:
        raise ValueError("Passphrase files empty")
        
    return passphrase

def _resolve_key_size(args) -> int:
    if args.key_size is None:
        args.key_size = 4096 if args.key_type == "rsa" else 384
    if args.key_type == "rsa" and args.key_size != 4096:
        raise ValueError("For RSA, --key-size must be 4096")
    if args.key_type == "ecc" and args.key_size != 384:
        raise ValueError("For ECC, --key-size must be 384 (NIST P-384)")
    return args.key_size

def main():
    parser = argparse.ArgumentParser(description="MicroPKI - Minimal Public Key Infrastructure Tool")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    ca_parser = subparsers.add_parser("ca", help="CA managment commands")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")
    init_parser = ca_sub.add_parser("init", help="Initialize Root CA")
    init_parser.add_argument("--out-dir", type=str, default="./pki_data", help="Output directory for CA files")
    init_parser.add_argument("--subject", type=str, required=True, action="append", 
                             help="Subject DN (e.g., '/CN=My Root CA/O=My Org' or 'CN=My Root CA,O=My Org')")
    init_parser.add_argument("--validity-days", type=int, default=3650, 
                             help="Certificate validity in days (default: 3650)")
    init_parser.add_argument("--passphrase-file", type=str, required=True, 
                             help="Path to file containing encryption passphrase for private key")
    init_parser.add_argument("--key-type", choices=['rsa', 'ecc'], default="rsa",
                             help="Key generation (rsa - 4096, ecc - 384)")
    init_parser.add_argument("--key-size", type=int, default=None,
                             help="Key size in bits (RSA: 4096, ECC: 384)")
    init_parser.add_argument("--log-file", type=str, default=None,
                             help="Path to log file")

    args = parser.parse_args()


    
    if args.command == "ca" and args.ca_command == "init":
        try:
            logger = setup_logger(log_path=args.log_file)
            if len(args.subject) != 1:
              raise ValueError("Only one argument type '--subject' is requairde")
            args.subject = args.subject[0]
            _resolve_key_size(args)
            if not args.subject or not args.subject.strip():
                raise ValueError("--subject must be a non-empty string")
            if args.validity_days <= 0:
                raise ValueError("--validity-days must be a positive integer")
            if not Path(args.passphrase_file).expanduser().is_file():
                raise ValueError(f"Passphrase file not found: {args.passphrase_file}")
            log_event(logger, logging.INFO, "CLI command executed: ca init",
                      key_type=args.key_type, key_size=args.key_size, out_dir=args.out_dir)

            passphrase = get_passphrase(args.passphrase_file)
            ca = RootCA(args.out_dir)
            ca.initialize(subject=args.subject, key_type=args.key_type,
                          key_size=args.key_size, passphrase=passphrase,
                          validity_days=args.validity_days)
            log_event(logger, logging.INFO, "Root CA successfully initialized", out_dir=args.out_dir)
            print(f"Root CA successfully initialized at {args.out_dir}")
            sys.exit(0)
        except ValueError as e:
            log_event(logger, logging.WARNING, "Validation failed", reason=str(e))
            print(f"Validation Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            log_event(logger, logging.ERROR, "CA init failed", error=str(e))
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
      parser.print_help()
      sys.exit(1)

if __name__ == "__main__":
    main()
