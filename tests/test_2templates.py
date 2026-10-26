import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from s2_fixt import run_cli, clean

def _ext_map(template, key, sans):
    from micropki.templates import build_template_extensions
    return {type(e).__name__: (e, c)
            for e, c in build_template_extensions(template, key, sans)}


def test_server_template_requires_san():
    from micropki.templates import build_template_extensions
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    with pytest.raises(ValueError):
        build_template_extensions("server", key, [])


def test_server_template_rsa_extensions():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    exts = _ext_map("server", key, ["dns:example.com"])

    bc, bc_crit = exts["BasicConstraints"]
    assert bc.ca is False
    assert bc_crit is True

    ku, ku_crit = exts["KeyUsage"]
    assert ku.digital_signature is True
    assert ku.key_encipherment is True
    assert ku_crit is True

    eku, _ = exts["ExtendedKeyUsage"]
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_server_template_ecc_no_key_encipherment():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    exts = _ext_map("server", key, ["dns:example.com"])
    ku, _ = exts["KeyUsage"]
    assert ku.digital_signature is True
    assert ku.key_encipherment is False


def test_client_template_eku():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    exts = _ext_map("client", key, ["email:a@b.c"])
    eku, _ = exts["ExtendedKeyUsage"]
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_code_signing_template_eku():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    exts = _ext_map("code_signing", key, [])
    eku, _ = exts["ExtendedKeyUsage"]
    assert ExtendedKeyUsageOID.CODE_SIGNING in eku


def test_unknown_template_rejected():
    from micropki.templates import build_template_extensions
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    with pytest.raises(ValueError):
        build_template_extensions("bogus", key, [])
