
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

"""
util tests

"""
import codecs
import sys
from typing import NoReturn, Optional, Tuple, Type
from unittest.mock import Mock, patch

import pytest

from pip_requirements_parser import BOMS, auto_decode
from pip_requirements_parser import split_auth_from_netloc


if sys.byteorder == "little":
    expected_byte_string = (
        "b'\\xff\\xfe/\\x00p\\x00a\\x00t\\x00h\\x00/\\x00d\\x00\\xe9\\x00f\\x00'"
    )
elif sys.byteorder == "big":
    expected_byte_string = (
        "b'\\xfe\\xff\\x00/\\x00p\\x00a\\x00t\\x00h\\x00/\\x00d\\x00\\xe9\\x00f'"
    )


class TestEncoding:
    """Tests for pip_requirements_parser.encoding"""

    def test_auto_decode_utf_16_le(self) -> None:
        data = (
            b"\xff\xfeD\x00j\x00a\x00n\x00g\x00o\x00=\x00"
            b"=\x001\x00.\x004\x00.\x002\x00"
        )
        assert data.startswith(codecs.BOM_UTF16_LE)
        assert auto_decode(data) == "Django==1.4.2"

    def test_auto_decode_utf_16_be(self) -> None:
        data = (
            b"\xfe\xff\x00D\x00j\x00a\x00n\x00g\x00o\x00="
            b"\x00=\x001\x00.\x004\x00.\x002"
        )
        assert data.startswith(codecs.BOM_UTF16_BE)
        assert auto_decode(data) == "Django==1.4.2"

    def test_auto_decode_no_bom(self) -> None:
        assert auto_decode(b"foobar") == "foobar"

    def test_auto_decode_pep263_headers(self) -> None:
        latin1_req = "# coding=latin1\n# Pas trop de café"
        assert auto_decode(latin1_req.encode("latin1")) == latin1_req

    def test_auto_decode_no_preferred_encoding(self) -> None:
        om, em = Mock(), Mock()
        om.return_value = "ascii"
        em.return_value = None
        data = "data"
        with patch("sys.getdefaultencoding", om):
            with patch("locale.getpreferredencoding", em):
                ret = auto_decode(data.encode(sys.getdefaultencoding()))
        assert ret == data

    @pytest.mark.parametrize("encoding", [encoding for bom, encoding in BOMS])
    def test_all_encodings_are_valid(self, encoding: str) -> None:
        # we really only care that there is no LookupError
        assert "".encode(encoding).decode(encoding) == ""


def raises(error: Type[Exception]) -> NoReturn:
    raise error


@pytest.mark.parametrize(
    "netloc, expected",
    [
        # Test a basic case.
        ("example.com", ("example.com", (None, None))),
        # Test with username and no password.
        ("user@example.com", ("example.com", ("user", None))),
        # Test with username and password.
        ("user:pass@example.com", ("example.com", ("user", "pass"))),
        # Test with username and empty password.
        ("user:@example.com", ("example.com", ("user", ""))),
        # Test the password containing an @ symbol.
        ("user:pass@word@example.com", ("example.com", ("user", "pass@word"))),
        # Test the password containing a : symbol.
        ("user:pass:word@example.com", ("example.com", ("user", "pass:word"))),
        # Test URL-encoded reserved characters.
        ("user%3Aname:%23%40%5E@example.com", ("example.com", ("user:name", "#@^"))),
    ],
)
def test_split_auth_from_netloc(
    netloc: str, expected: Tuple[str, Tuple[Optional[str], Optional[str]]]
) -> None:
    actual = split_auth_from_netloc(netloc)
    assert actual == expected

