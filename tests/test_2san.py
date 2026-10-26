import pytest
from cryptography import x509
from s2_fixt import run_cli, clean

@pytest.mark.parametrize("raw,expected_cls", [
    ("dns:example.com", x509.DNSName),
    ("ip:192.168.1.1", x509.IPAddress),
])
def test_parse_san_server_ok(raw, expected_cls):
    from micropki.san import parse_san
    san = parse_san([raw], template="server")
    assert isinstance(san, x509.SubjectAlternativeName)
    assert isinstance(list(san)[0], expected_cls)


def test_parse_san_client_email():
    from micropki.san import parse_san
    san = parse_san(["email:alice@example.com"], template="client")
    assert isinstance(list(san)[0], x509.RFC822Name)


def test_parse_san_code_signing_uri():
    from micropki.san import parse_san
    san = parse_san(["uri:https://example.com"], template="code_signing")
    assert isinstance(list(san)[0], x509.UniformResourceIdentifier)


def test_parse_san_empty_returns_none():
    from micropki.san import parse_san
    assert parse_san([], template="server") is None


def test_parse_san_duplicates_dropped():
    from micropki.san import parse_san
    san = parse_san(["dns:a.example.com", "dns:a.example.com"], template="server")
    assert len(list(san)) == 1


def test_parse_san_bad_type():
    from micropki.san import parse_san
    with pytest.raises(ValueError):
        parse_san(["foo:bar"], template="server")


def test_parse_san_missing_colon():
    from micropki.san import parse_san
    with pytest.raises(ValueError):
        parse_san(["example.com"], template="server")


def test_parse_san_code_signing_rejects_ip():
    """CLI-10: unsupported SAN type for the template."""
    from micropki.san import parse_san
    with pytest.raises(ValueError):
        parse_san(["ip:1.2.3.4"], template="code_signing")


def test_parse_san_server_rejects_email():
    from micropki.san import parse_san
    with pytest.raises(ValueError):
        parse_san(["email:a@b.c"], template="server")


def test_parse_san_bad_ip():
    from micropki.san import parse_san
    with pytest.raises(ValueError):
        parse_san(["ip:not-an-ip"], template="server")
