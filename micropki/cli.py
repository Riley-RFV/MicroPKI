import argparse
import sys
import getpass
from pathlib import Path
from .ca import RootCA
import logging
from .logger import setup_logger, log_event

logger=setup_logger()

def get_passphrase(path: str) -> bytes:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise FileNotFoundError(f"Passphrase file not found: {path}")
    
    with open(file_path, "rb") as f:
        passphrase = f.read().strip()
        
    if not passphrase:
        raise ValueError("Passphrase file is empty")
        
    return passphrase

def main():
    parser = argparse.ArgumentParser()
    
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init-ca", help="Initialize Root CA")
    init_parser.add_argument("--out-dir", type=str, default="./pki_data", help="Output directory for CA files")
    init_parser.add_argument("--subject", type=str, required=True, 
                             help="Subject DN (e.g., '/CN=My Root CA/O=My Org' or 'CN=My Root CA,O=My Org')")
    init_parser.add_argument("--validity-days", type=int, default=3650, 
                             help="Certificate validity in days (default: 3650)")
    init_parser.add_argument("--passphrase-file", type=str, required=True, 
                             help="Path to file containing encryption passphrase for private key")
    init_parser.add_argument("--key-type", choices=['rsa','ecc'], default="rsa",
                             help="Key generation (rsa - 4069, ecc - 384)")
    init_parser.add_argument("--key-size", type=int, default=4096,
                             help="Appropriate size in bits (RSA:4096, ECC:384)")
    args = parser.parse_args()
    
    if args.command == "init-ca":
        try:
            log_event(logger, logging.INFO, "CLI command executed: init-ca", 
                      key_type=args.key_type, key_size=args.key_size, out_dir=args.out_dir)
            passphrase = get_passphrase(args.passphrase_file)
            ca = RootCA(args.out_dir)
            ca.initialize(subject=args.subject, key_type=args.key_type, key_size=args.key_size, passphrase=passphrase, validity_days=args.validity_days)
            print(f"Root CA successfully initialized at {args.out_dir}")
            sys.exit(0)
        except ValueError as e:
            log_event(logger, logging.WARNING, "Validation failed", reason=str(e))
            print(f"Validation Error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
