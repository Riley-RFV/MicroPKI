import subprocess
import sys

import pytest


def run_cli(args):
    cmd = [sys.executable, "-m", "micropki.cli"] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def clean(s: str) -> str:
    return "\n".join(
        line for line in s.split("\n")
        if "RuntimeWarning" not in line and "frozen runpy" not in line
    ).lower()


@pytest.fixture
def root_ca(temp_dir, passphrase_file):
    from micropki.ca import RootCA
    ca = RootCA(str(temp_dir))
    ca.initialize(
        subject="CN=Test Root CA,O=Test Org",
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
    }


@pytest.fixture
def intermediate(root_ca, passphrase_file):
    from micropki.ca import RootCA
    ca = RootCA(str(root_ca["out_dir"]))
    cert = ca.issue_intermediate(
        root_cert_path=str(root_ca["cert"]),
        root_key_path=str(root_ca["key"]),
        root_passphrase=root_ca["pass"],
        subject="CN=Test Intermediate CA,O=Test Org",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=1825,
        pathlen=0,
    )
    return {
        "cert": root_ca["out_dir"] / "certs" / "intermediate.cert.pem",
        "key": root_ca["out_dir"] / "private" / "intermediate.key.pem",
        "pass": passphrase_file.read_bytes(),
        "x509": cert,
    }
