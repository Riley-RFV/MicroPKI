import argparse
import sys
import getpass
from pathlib import Path
from .ca import RootCA

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
    parser = argparse.ArgumentParser(description="MicroPKI - Minimal Public Key Infrastructure Tool")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    init_parser = subparsers.add_parser("init-ca", help="Initialize Root CA")
    init_parser.add_argument("--out-dir", type=str, default="./pki_data", help="Output directory for CA files")
    init_parser.add_argument("--subject", type=str, required=True, 
                             help="Subject DN (e.g., '/CN=My Root CA/O=My Org' or 'CN=My Root CA,O=My Org')")
    init_parser.add_argument("--validity-days", type=int, default=3650, 
                             help="Certificate validity in days (default: 3650)")
    init_parser.add_argument("--passphrase-file", type=str, required=True, 
                             help="Path to file containing encryption passphrase for private key")
    
    args = parser.parse_args()
    
    if args.command == "init-ca":
        try:
            passphrase = get_passphrase(args.passphrase_file)
            ca = RootCA(args.out_dir)
            ca.initialize(subject=args.subject, passphrase=passphrase, validity_days=args.validity_days)
            print(f"Root CA successfully initialized at {args.out_dir}")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
