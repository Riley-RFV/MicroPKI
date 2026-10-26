import pytest
from s2_fixt import run_cli, clean

def test_parse_dn_rejects_unknown_attr():
    from micropki.certificates import parse_subject_dn
    with pytest.raises(ValueError):
        parse_subject_dn("CN=Test,FOO=bar")


def test_parse_dn_rejects_duplicate():
    from micropki.certificates import parse_subject_dn
    with pytest.raises(ValueError):
        parse_subject_dn("CN=A,CN=B")


def test_parse_dn_rejects_missing_equals():
    from micropki.certificates import parse_subject_dn
    with pytest.raises(ValueError):
        parse_subject_dn("CN=Test,broken")
