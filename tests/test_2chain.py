import pytest
from s2_fixt import run_cli, clean

def _issue_leaf(intermediate, temp_dir, cn, template="server", sans=None):
    from micropki.ca import RootCA
    ca = RootCA(str(temp_dir), create_layout=False)
    ca.issue_cert(
        ca_cert_path=str(intermediate["cert"]),
        ca_key_path=str(intermediate["key"]),
        ca_passphrase=intermediate["pass"],
        template=template,
        subject=f"CN={cn}",
        sans=sans or [f"dns:{cn}"],
        out_dir=str(temp_dir / "leaf"),
        validity_days=365,
        key_type="rsa",
    )
    return temp_dir / "leaf" / f"{cn}.cert.pem"


def test_verify_chain_ok(intermediate, temp_dir, root_ca):
    from micropki.chain import verify_chain
    leaf = _issue_leaf(intermediate, temp_dir, "ok.example.com")
    assert verify_chain(
        leaf_path=str(leaf),
        intermediate_path=str(intermediate["cert"]),
        root_path=str(root_ca["cert"]),
    ) is True


def test_verify_chain_wrong_root(intermediate, temp_dir):
    from micropki.chain import verify_chain
    from micropki.ca import RootCA

    other_root_dir = temp_dir / "other_root"
    other = RootCA(str(other_root_dir))
    other.initialize(
        subject="CN=Other Root CA,O=Other",
        key_type="rsa", key_size=4096,
        passphrase=b"other-pass", validity_days=365,
    )

    leaf = _issue_leaf(intermediate, temp_dir, "badroot.example.com")
    with pytest.raises(Exception):
        verify_chain(
            leaf_path=str(leaf),
            intermediate_path=str(intermediate["cert"]),
            root_path=str(other_root_dir / "certs" / "ca.cert.pem"),
        )


def test_verify_chain_wrong_intermediate(intermediate, temp_dir, root_ca):
    from micropki.chain import verify_chain
    from micropki.ca import RootCA
    ca = RootCA(str(root_ca["out_dir"]))
    ca.issue_intermediate(
        root_cert_path=str(root_ca["cert"]),
        root_key_path=str(root_ca["key"]),
        root_passphrase=root_ca["pass"],
        subject="CN=Second Intermediate,O=Test",
        key_type="rsa", key_size=4096,
        passphrase=root_ca["pass"],
        validity_days=365, pathlen=0,
    )
    other_inter = root_ca["out_dir"] / "certs" / "intermediate.cert.pem"

    leaf = _issue_leaf(intermediate, temp_dir, "wronginter.example.com")
    ca.issue_intermediate(
        root_cert_path=str(root_ca["cert"]),
        root_key_path=str(root_ca["key"]),
        root_passphrase=root_ca["pass"],
        subject="CN=Second Intermediate,O=Test",
        key_type="rsa", key_size=4096,
        passphrase=root_ca["pass"],
        validity_days=365, pathlen=0,
    )
    with pytest.raises(Exception):
        verify_chain(
            leaf_path=str(leaf),
            intermediate_path=str(other_inter),
            root_path=str(root_ca["cert"]),
        )


def test_verify_chain_openssl(intermediate, temp_dir, root_ca):
    import subprocess
    leaf = _issue_leaf(intermediate, temp_dir, "openssl.example.com")
    result = subprocess.run(
        ["openssl", "verify",
         "-CAfile", str(root_ca["cert"]),
         "-untrusted", str(intermediate["cert"]),
         str(leaf)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
