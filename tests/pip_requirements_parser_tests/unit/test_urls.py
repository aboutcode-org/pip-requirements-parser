
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import sys
from typing import Optional

import pytest

from pip_requirements_parser import get_url_scheme, url_to_path


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://localhost:8080/", "http"),
        ("file:c:/path/to/file", "file"),
        ("file:/dev/null", "file"),
        ("", None),
    ],
)
def test_get_url_scheme(url: str, expected: Optional[str]) -> None:
    assert get_url_scheme(url) == expected


@pytest.mark.parametrize(
    "url,win_expected,non_win_expected",
    [
        ("file:tmp", "tmp", "tmp"),
        ("file:c:/path/to/file", r"C:\path\to\file", "c:/path/to/file"),
        ("file:/path/to/file", r"\path\to\file", "/path/to/file"),
        ("file://localhost/tmp/file", r"\tmp\file", "/tmp/file"),
        ("file://localhost/c:/tmp/file", r"C:\tmp\file", "/c:/tmp/file"),
        ("file://somehost/tmp/file", r"\\somehost\tmp\file", None),
        ("file:///tmp/file", r"\tmp\file", "/tmp/file"),
        ("file:///c:/tmp/file", r"C:\tmp\file", "/c:/tmp/file"),
    ],
)
def test_url_to_path(url: str, win_expected: str, non_win_expected: str) -> None:
    if sys.platform == "win32":
        expected_path = win_expected
    else:
        expected_path = non_win_expected

    if expected_path is None:
        with pytest.raises(ValueError):
            url_to_path(url)
    else:
        assert url_to_path(url) == expected_path
