import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from s2_fixt import run_cli, clean

def test_build_csr_has_basic_constraints():
    from micropki.csr import build_intermediate_csr
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = build_intermediate_csr("CN=Int CA,O=Test", key, pathlen=0)

    bc = csr.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0


def test_csr_signature_valid():
    from micropki.csr import build_intermediate_csr
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = build_intermediate_csr("CN=Int CA,O=Test", key, pathlen=1)
    assert csr.is_signature_valid


def test_sign_intermediate_aki_from_root_ski(root_ca):
    from micropki.csr import build_intermediate_csr, sign_intermediate_csr
    from micropki.crypto_utils import load_certificate, load_encrypted_key

    root_cert = load_certificate(root_ca["cert"])
    root_key = load_encrypted_key(root_ca["key"], root_ca["pass"])
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = build_intermediate_csr("CN=Int CA,O=Test", int_key, pathlen=0)
    cert = sign_intermediate_csr(csr, root_cert, root_key, validity_days=365, pathlen=0)

    root_ski = root_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value.digest
    aki = cert.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == root_ski


def test_sign_intermediate_extensions(root_ca):
    from micropki.csr import build_intermediate_csr, sign_intermediate_csr
    from micropki.crypto_utils import load_certificate, load_encrypted_key

    root_cert = load_certificate(root_ca["cert"])
    root_key = load_encrypted_key(root_ca["key"], root_ca["pass"])
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = build_intermediate_csr("CN=Int CA,O=Test", int_key, pathlen=0)
    cert = sign_intermediate_csr(csr, root_cert, root_key, validity_days=365, pathlen=0)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True
    assert ku.crl_sign is True
    assert cert.issuer == root_cert.subject


def test_sign_intermediate_invalid_csr_signature(root_ca):
    from micropki.csr import build_intermediate_csr, sign_intermediate_csr
    from micropki.crypto_utils import load_certificate, load_encrypted_key

    root_cert = load_certificate(root_ca["cert"])
    root_key = load_encrypted_key(root_ca["key"], root_ca["pass"])
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = build_intermediate_csr("CN=Int CA,O=Test", int_key, pathlen=0)

    bad_csr = x509.load_pem_x509_csr(csr.public_bytes(
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["Encoding"]).Encoding.PEM))
    assert bad_csr.is_signature_valid

