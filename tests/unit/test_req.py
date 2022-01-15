
# Copyright (c) 2008-2021 The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import os
import shutil
import sys
import tempfile
from typing import Tuple
from unittest import mock

import pytest
from packaging.markers import Marker
from packaging.requirements import Requirement

from pip_requirements import (
    InstallationError,
    InvalidWheelFilename,
)
from pip_requirements import InstallRequirement
from pip_requirements import (
    _get_url_from_path,
    _looks_like_path,
    install_req_from_editable,
    install_req_from_line,
    install_req_from_parsed_requirement,
    parse_editable,
)
from pip_requirements import (
    ParsedLine,
    get_line_parser,
    handle_requirement_line,
)
from pip_requirements import path_to_url

from tests.lib import TestData


def get_processed_req_from_line(
    line: str, fname: str = "file", lineno: int = 1
) -> InstallRequirement:
    line_parser = get_line_parser(None)
    args_str, opts = line_parser(line)
    parsed_line = ParsedLine(
        fname,
        lineno,
        args_str,
        opts,
        False,
    )
    parsed_req = handle_requirement_line(parsed_line)
    assert parsed_req is not None
    req = install_req_from_parsed_requirement(parsed_req)
    req.user_supplied = True
    return req



class TestInstallRequirement:
    def setup(self) -> None:
        self.tempdir = tempfile.mkdtemp()

    def teardown(self) -> None:
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_url_with_query(self) -> None:
        """InstallRequirement should strip the fragment, but not the query."""
        url = "http://foo.com/?p=bar.git;a=snapshot;h=v0.1;sf=tgz"
        fragment = "#egg=bar"
        req = install_req_from_line(url + fragment)
        assert req.link is not None
        assert req.link.url == url + fragment, req.link

    def test_pep440_wheel_link_requirement(self) -> None:
        url = "https://whatever.com/test-0.4-py2.py3-bogus-any.whl"
        line = "test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl"
        req = install_req_from_line(line)
        parts = str(req.req).split("@", 1)
        assert len(parts) == 2
        assert parts[0].strip() == "test"
        assert parts[1].strip() == url

    def test_pep440_url_link_requirement(self) -> None:
        url = "git+http://foo.com@ref#egg=foo"
        line = "foo @ git+http://foo.com@ref#egg=foo"
        req = install_req_from_line(line)
        parts = str(req.req).split("@", 1)
        assert len(parts) == 2
        assert parts[0].strip() == "foo"
        assert parts[1].strip() == url

    def test_url_with_authentication_link_requirement(self) -> None:
        url = "https://what@whatever.com/test-0.4-py2.py3-bogus-any.whl"
        line = "https://what@whatever.com/test-0.4-py2.py3-bogus-any.whl"
        req = install_req_from_line(line)
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.scheme == "https"
        assert req.link.url == url

    def test_unsupported_wheel_link_requirement_raises(self) -> None:
        req = install_req_from_line(
            "https://whatever.com/peppercorn-0.4-py2.py3-bogus-any.whl",
        )
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.scheme == "https"

    def test_unsupported_wheel_local_file_requirement_raises(
        self, data: TestData
    ) -> None:
        req = install_req_from_line(
            data.packages.joinpath("simple.dist-0.1-py1-none-invalid.whl"),
        )
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.scheme == "file"

    def test_str(self) -> None:
        req = install_req_from_line("simple==0.1")
        assert str(req) == "simple==0.1"

    def test_repr(self) -> None:
        req = install_req_from_line("simple==0.1")
        assert repr(req) == ("<InstallRequirement object: simple==0.1 editable=False>")

    def test_invalid_wheel_requirement_raises(self) -> None:
        with pytest.raises(InvalidWheelFilename):
            install_req_from_line("invalid.whl")

    def test_wheel_requirement_sets_req_attribute(self) -> None:
        req = install_req_from_line("simple-0.1-py2.py3-none-any.whl")
        assert isinstance(req.req, Requirement)
        assert str(req.req) == "simple==0.1"

    def test_url_preserved_line_req(self) -> None:
        """Confirm the url is preserved in a non-editable requirement"""
        url = "git+http://foo.com@ref#egg=foo"
        req = install_req_from_line(url)
        assert req.link is not None
        assert req.link.url == url

    def test_url_preserved_editable_req(self) -> None:
        """Confirm the url is preserved in a editable requirement"""
        url = "git+http://foo.com@ref#egg=foo"
        req = install_req_from_editable(url)
        assert req.link is not None
        assert req.link.url == url

    def test_markers(self) -> None:
        for line in (
            # recommended syntax
            'mock3; python_version >= "3"',
            # with more spaces
            'mock3 ; python_version >= "3" ',
            # without spaces
            'mock3;python_version >= "3"',
        ):
            req = install_req_from_line(line)
            assert req.req is not None
            assert req.req.name == "mock3"
            assert str(req.req.specifier) == ""
            assert str(req.markers) == 'python_version >= "3"'

    def test_markers_semicolon(self) -> None:
        # check that the markers can contain a semicolon
        req = install_req_from_line('semicolon; os_name == "a; b"')
        assert req.req is not None
        assert req.req.name == "semicolon"
        assert str(req.req.specifier) == ""
        assert str(req.markers) == 'os_name == "a; b"'

    def test_markers_url(self) -> None:
        # test "URL; markers" syntax
        url = "http://foo.com/?p=bar.git;a=snapshot;h=v0.1;sf=tgz"
        line = f'{url}; python_version >= "3"'
        req = install_req_from_line(line)
        assert req.link is not None
        assert req.link.url == url, req.link.url
        assert str(req.markers) == 'python_version >= "3"'

        # without space, markers are part of the URL
        url = "http://foo.com/?p=bar.git;a=snapshot;h=v0.1;sf=tgz"
        line = f'{url};python_version >= "3"'
        req = install_req_from_line(line)
        assert req.link is not None
        assert req.link.url == line, req.link.url
        assert req.markers is None

    def test_markers_match_from_line(self) -> None:
        # match
        for markers in (
            'python_version >= "1.0"',
            f"sys_platform == {sys.platform!r}",
        ):
            line = "name; " + markers
            req = install_req_from_line(line)
            assert str(req.markers) == str(Marker(markers))
            assert req.match_markers()

        # don't match
        for markers in (
            'python_version >= "5.0"',
            f"sys_platform != {sys.platform!r}",
        ):
            line = "name; " + markers
            req = install_req_from_line(line)
            assert str(req.markers) == str(Marker(markers))
            assert not req.match_markers()

    def test_markers_match(self) -> None:
        # match
        for markers in (
            'python_version >= "1.0"',
            f"sys_platform == {sys.platform!r}",
        ):
            line = "name; " + markers
            req = install_req_from_line(line, comes_from="")
            assert str(req.markers) == str(Marker(markers))
            assert req.match_markers()

        # don't match
        for markers in (
            'python_version >= "5.0"',
            f"sys_platform != {sys.platform!r}",
        ):
            line = "name; " + markers
            req = install_req_from_line(line, comes_from="")
            assert str(req.markers) == str(Marker(markers))
            assert not req.match_markers()

    def test_extras_for_line_path_requirement(self) -> None:
        line = "SomeProject[ex1,ex2]"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_line(line, comes_from=comes_from)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_extras_for_line_url_requirement(self) -> None:
        line = "git+https://url#egg=SomeProject[ex1,ex2]"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_line(line, comes_from=comes_from)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_extras_for_editable_path_requirement(self) -> None:
        url = ".[ex1,ex2]"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_editable(url, comes_from=comes_from)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_extras_for_editable_url_requirement(self) -> None:
        url = "git+https://url#egg=SomeProject[ex1,ex2]"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_editable(url, comes_from=comes_from)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_unexisting_path(self) -> None:
        with pytest.raises(InstallationError) as e:
            install_req_from_line(os.path.join("this", "path", "does", "not", "exist"))
        err_msg = e.value.args[0]
        assert "Invalid requirement" in err_msg
        assert "It looks like a path." in err_msg

    def test_single_equal_sign(self) -> None:
        with pytest.raises(InstallationError) as e:
            install_req_from_line("toto=42")
        err_msg = e.value.args[0]
        assert "Invalid requirement" in err_msg
        assert "= is not a valid operator. Did you mean == ?" in err_msg

    def test_unidentifiable_name(self) -> None:
        test_name = "-"
        with pytest.raises(InstallationError) as e:
            install_req_from_line(test_name)
        err_msg = e.value.args[0]
        assert f"Invalid requirement: '{test_name}'" == err_msg

    def test_requirement_file(self) -> None:
        req_file_path = os.path.join(self.tempdir, "test.txt")
        with open(req_file_path, "w") as req_file:
            req_file.write("pip\nsetuptools")
        with pytest.raises(InstallationError) as e:
            install_req_from_line(req_file_path)
        err_msg = e.value.args[0]
        assert "Invalid requirement" in err_msg
        assert "It looks like a path. The path does exist." in err_msg
        assert "appears to be a requirements file." in err_msg
        assert "If that is the case, use the '-r' flag to install" in err_msg


def test_parse_editable_explicit_vcs() -> None:
    assert parse_editable("svn+https://foo#egg=foo") == (
        "foo",
        "svn+https://foo#egg=foo",
        set(),
    )


def test_parse_editable_vcs_extras() -> None:
    assert parse_editable("svn+https://foo#egg=foo[extras]") == (
        "foo[extras]",
        "svn+https://foo#egg=foo[extras]",
        set(),
    )


def test_exclusive_environment_markers() -> None:
    """Make sure RequirementSet accepts several excluding env markers"""
    eq36 = install_req_from_line("Django>=1.6.10,<1.7 ; python_version == '3.6'")
    eq36.user_supplied = True
    ne36 = install_req_from_line("Django>=1.6.10,<1.8 ; python_version != '3.6'")
    ne36.user_supplied = True



@pytest.mark.parametrize(
    "args, expected",
    [
        # Test UNIX-like paths
        (("/path/to/installable"), True),
        # Test relative paths
        (("./path/to/installable"), True),
        # Test current path
        (("."), True),
        # Test url paths
        (("https://whatever.com/test-0.4-py2.py3-bogus-any.whl"), True),
        # Test pep440 paths
        (("test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl"), True),
        # Test wheel
        (("simple-0.1-py2.py3-none-any.whl"), False),
    ],
)
def test_looks_like_path(args: str, expected: bool) -> None:
    assert _looks_like_path(args) == expected


@pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="Test only available on Windows"
)
@pytest.mark.parametrize(
    "args, expected",
    [
        # Test relative paths
        ((".\\path\\to\\installable"), True),
        (("relative\\path"), True),
        # Test absolute paths
        (("C:\\absolute\\path"), True),
    ],
)
def test_looks_like_path_win(args: str, expected: bool) -> None:
    assert _looks_like_path(args) == expected


@pytest.mark.parametrize(
    "args, mock_returns, expected",
    [
        # Test pep440 urls
        (
            (
                "/path/to/foo @ git+http://foo.com@ref#egg=foo",
                "foo @ git+http://foo.com@ref#egg=foo",
            ),
            (False, False),
            None,
        ),
        # Test pep440 urls without spaces
        (
            (
                "/path/to/foo@git+http://foo.com@ref#egg=foo",
                "foo @ git+http://foo.com@ref#egg=foo",
            ),
            (False, False),
            None,
        ),
        # Test pep440 wheel
        (
            (
                "/path/to/test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl",
                "test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl",
            ),
            (False, False),
            None,
        ),
        # Test name is not a file
        (("/path/to/simple==0.1", "simple==0.1"), (False, False), None),
    ],
)
@mock.patch("pip_requirements.os.path.isdir")
@mock.patch("pip_requirements.os.path.isfile")
def test_get_url_from_path(
    isdir_mock: mock.Mock,
    isfile_mock: mock.Mock,
    args: Tuple[str, str],
    mock_returns: Tuple[bool, bool],
    expected: None,
) -> None:
    isdir_mock.return_value = mock_returns[0]
    isfile_mock.return_value = mock_returns[1]
    assert _get_url_from_path(*args) is expected


@mock.patch("pip_requirements.os.path.isdir")
@mock.patch("pip_requirements.os.path.isfile")
def test_get_url_from_path__archive_file(
    isdir_mock: mock.Mock, isfile_mock: mock.Mock
) -> None:
    isdir_mock.return_value = False
    isfile_mock.return_value = True
    name = "simple-0.1-py2.py3-none-any.whl"
    path = os.path.join("/path/to/" + name)
    url = path_to_url(path)
    assert _get_url_from_path(path, name) == url


@mock.patch("pip_requirements.os.path.isdir")
@mock.patch("pip_requirements.os.path.isfile")
def test_get_url_from_path__installable_dir(
    isdir_mock: mock.Mock, isfile_mock: mock.Mock
) -> None:
    isdir_mock.return_value = True
    isfile_mock.return_value = True
    name = "some/setuptools/project"
    path = os.path.join("/path/to/" + name)
    url = path_to_url(path)
    assert _get_url_from_path(path, name) == url


@mock.patch("pip_requirements.os.path.isdir")
def test_get_url_from_path__installable_error(isdir_mock: mock.Mock) -> None:
    isdir_mock.return_value = True
    name = "some/setuptools/project"
    path = os.path.join("/path/to/" + name)
    with pytest.raises(InstallationError) as e:
        _get_url_from_path(path, name)
    err_msg = e.value.args[0]
    assert "Neither 'setup.py' nor 'pyproject.toml' found" in err_msg
