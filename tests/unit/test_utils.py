
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

"""
util tests

"""
import codecs
import sys
from io import BytesIO
from typing import NoReturn, Optional, Tuple, Type
from unittest.mock import Mock, patch

import pytest

from pip_requirements import HashMismatch, HashMissing, InstallationError
from pip_requirements import BOMS, auto_decode
from pip_requirements import Hashes, MissingHashes
from pip_requirements import split_auth_from_netloc

from tests.lib.path import Path



if sys.byteorder == "little":
    expected_byte_string = (
        "b'\\xff\\xfe/\\x00p\\x00a\\x00t\\x00h\\x00/\\x00d\\x00\\xe9\\x00f\\x00'"
    )
elif sys.byteorder == "big":
    expected_byte_string = (
        "b'\\xfe\\xff\\x00/\\x00p\\x00a\\x00t\\x00h\\x00/\\x00d\\x00\\xe9\\x00f'"
    )


class TestHashes:
    """Tests for pip_requirements.hashes"""

    @pytest.mark.parametrize(
        "hash_name, hex_digest, expected",
        [
            # Test a value that matches but with the wrong hash_name.
            ("sha384", 128 * "a", False),
            # Test matching values, including values other than the first.
            ("sha512", 128 * "a", True),
            ("sha512", 128 * "b", True),
            # Test a matching hash_name with a value that doesn't match.
            ("sha512", 128 * "c", False),
        ],
    )
    def test_is_hash_allowed(
        self, hash_name: str, hex_digest: str, expected: bool
    ) -> None:
        hashes_data = {
            "sha512": [128 * "a", 128 * "b"],
        }
        hashes = Hashes(hashes_data)
        assert hashes.is_hash_allowed(hash_name, hex_digest) == expected

    def test_success(self, tmpdir: Path) -> None:
        """Make sure no error is raised when at least one hash matches.

        Test check_against_path because it calls everything else.

        """
        file = tmpdir / "to_hash"
        file.write_text("hello")
        hashes = Hashes(
            {
                "sha256": [
                    "2cf24dba5fb0a30e26e83b2ac5b9e29e"
                    "1b161e5c1fa7425e73043362938b9824"
                ],
                "sha224": ["wrongwrong"],
                "md5": ["5d41402abc4b2a76b9719d911017c592"],
            }
        )
        hashes.check_against_path(file)

    def test_failure(self) -> None:
        """Hashes should raise HashMismatch when no hashes match."""
        hashes = Hashes({"sha256": ["wrongwrong"]})
        with pytest.raises(HashMismatch):
            hashes.check_against_file(BytesIO(b"hello"))

    def test_missing_hashes(self) -> None:
        """MissingHashes should raise HashMissing when any check is done."""
        with pytest.raises(HashMissing):
            MissingHashes().check_against_file(BytesIO(b"hello"))

    def test_unknown_hash(self) -> None:
        """Hashes should raise InstallationError when it encounters an unknown
        hash."""
        hashes = Hashes({"badbad": ["dummy"]})
        with pytest.raises(InstallationError):
            hashes.check_against_file(BytesIO(b"hello"))

    def test_non_zero(self) -> None:
        """Test that truthiness tests tell whether any known-good hashes
        exist."""
        assert Hashes({"sha256": ["dummy"]})
        assert not Hashes()
        assert not Hashes({})

    def test_equality(self) -> None:
        assert Hashes() == Hashes()
        assert Hashes({"sha256": ["abcd"]}) == Hashes({"sha256": ["abcd"]})
        assert Hashes({"sha256": ["ab", "cd"]}) == Hashes({"sha256": ["cd", "ab"]})

    def test_hash(self) -> None:
        cache = {}
        cache[Hashes({"sha256": ["ab", "cd"]})] = 42
        assert cache[Hashes({"sha256": ["ab", "cd"]})] == 42


class TestEncoding:
    """Tests for pip_requirements.encoding"""

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

