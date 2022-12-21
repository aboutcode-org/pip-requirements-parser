
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import os
import posixpath
import shutil
import sys
import tempfile
from typing import Tuple
from unittest.case import TestCase

import pytest
from packaging.markers import Marker
from packaging.requirements import Requirement

from pip_requirements_parser import _get_url_from_path
from pip_requirements_parser import _looks_like_path
from pip_requirements_parser import parse_editable

from pip_requirements_parser import build_editable_req
from pip_requirements_parser import build_install_req

from pip_requirements_parser import InstallationError
from pip_requirements_parser import InvalidWheelFilename
from pip_requirements_parser import RequirementLine


class TestInstallRequirement(TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_url_with_query(self) -> None:
        """InstallRequirement should strip the fragment, but not the query."""
        url = "http://foo.com/?p=bar.git;a=snapshot;h=v0.1;sf=tgz"
        fragment = "#egg=bar"
        req = build_install_req(url + fragment)
        assert req.link is not None
        assert req.link.url == url + fragment, req.link

    def test_pep440_wheel_link_requirement(self) -> None:
        line = "test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl"
        req = build_install_req(line)
        assert str(req.req) == "test@ https://whatever.com/test-0.4-py2.py3-bogus-any.whl"
        assert str(req.link) == "https://whatever.com/test-0.4-py2.py3-bogus-any.whl"

    def test_pep440_url_link_requirement(self) -> None:
        line = "foo @ git+http://foo.com@ref#egg=foo"
        req = build_install_req(line)
        assert str(req.req) == "foo@ git+http://foo.com@ref#egg=foo"
        assert str(req.link) == "git+http://foo.com@ref#egg=foo"

    def test_url_with_authentication_link_requirement(self) -> None:
        url = "https://what@whatever.com/test-0.4-py2.py3-bogus-any.whl"
        line = "https://what@whatever.com/test-0.4-py2.py3-bogus-any.whl"
        req = build_install_req(line)
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.scheme == "https"
        assert req.link.url == url

    def test_unsupported_wheel_link_requirement_raises(self) -> None:
        req = build_install_req(
            "https://whatever.com/peppercorn-0.4-py2.py3-bogus-any.whl",
        )
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.scheme == "https"

    def test_unsupported_wheel_local_file_requirement_raises(self) -> None:
        req = build_install_req("simple.dist-0.1-py1-none-invalid.whl")
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.url == "simple.dist-0.1-py1-none-invalid.whl"

    def test_req_dumps(self) -> None:
        req = build_install_req("simple==0.1")
        assert req.dumps() == "simple==0.1"

    def test_invalid_wheel_requirement_raises(self) -> None:
        with pytest.raises(InvalidWheelFilename):
            build_install_req("invalid.whl")

    def test_wheel_requirement_sets_req_attribute(self) -> None:
        req = build_install_req("simple-0.1-py2.py3-none-any.whl")
        assert isinstance(req.req, Requirement)
        assert str(req.req) == "simple==0.1"

    def test_url_preserved_line_req(self) -> None:
        """Confirm the url is preserved in a non-editable requirement"""
        url = "git+http://foo.com@ref#egg=foo"
        req = build_install_req(url)
        assert req.link is not None
        assert req.link.url == url

    def test_build_editable_req_with_dot_and_extras_preserves_extras_on_dumps(self) -> None:
        url = ".[socks]"
        req = build_editable_req(url)
        assert req.extras == {'socks'}
        assert req.dumps() == "--editable .[socks]"

    def test_build_editable_req_with_dot_dumps(self) -> None:
        url = "."
        req = build_editable_req(url)
        assert req.dumps() == "--editable ."

    def test_url_preserved_editable_req(self) -> None:
        """Confirm the url is preserved in a editable requirement"""
        url = "git+http://foo.com@ref#egg=foo"
        req = build_editable_req(url)
        assert req.link is not None
        assert req.link.url == url

    def test_marker(self) -> None:
        for line in (
            # recommended syntax
            'mock3; python_version >= "3"',
            # with more spaces
            'mock3 ; python_version >= "3" ',
            # without spaces
            'mock3;python_version >= "3"',
        ):
            req = build_install_req(line)
            assert req.req is not None
            assert req.req.name == "mock3"
            assert not req.specifier
            assert str(req.marker) == 'python_version >= "3"'

    def test_marker_semicolon(self) -> None:
        # check that the marker can contain a semicolon
        req = build_install_req('semicolon; os_name == "a; b"')
        assert req.req is not None
        assert req.req.name == "semicolon"
        assert not req.specifier
        assert str(req.marker) == 'os_name == "a; b"'

    def test_marker_url(self) -> None:
        # test "URL; marker" syntax
        url = "http://foo.com/?p=bar.git;a=snapshot;h=v0.1;sf=tgz"
        line = f'{url}; python_version >= "3"'
        req = build_install_req(line)
        assert req.link is not None
        assert req.link.url == url, req.link.url
        assert str(req.marker) == 'python_version >= "3"'

        # without space, marker are part of the URL
        url = "http://foo.com/?p=bar.git;a=snapshot;h=v0.1;sf=tgz"
        line = f'{url};python_version >= "3"'
        req = build_install_req(line)
        assert req.link is not None
        assert req.link.url == line, req.link.url
        assert req.marker is None

    def test_marker_match_from_line(self) -> None:
        # match
        for marker in (
            'python_version >= "1.0"',
            f"sys_platform == {sys.platform!r}",
        ):
            line = "name; " + marker
            req = build_install_req(line)
            assert str(req.marker) == str(Marker(marker))
            assert req.match_marker()

        # don't match
        for marker in (
            'python_version >= "5.0"',
            f"sys_platform != {sys.platform!r}",
        ):
            line = "name; " + marker
            req = build_install_req(line)
            assert str(req.marker) == str(Marker(marker))
            assert not req.match_marker()

    def test_marker_match(self) -> None:
        # match
        for marker in (
            'python_version >= "1.0"',
            f"sys_platform == {sys.platform!r}",
        ):
            line = "name; " + marker
            req = build_install_req(line, requirement_line=None)
            assert str(req.marker) == str(Marker(marker))
            assert req.match_marker()

        # don't match
        for marker in (
            'python_version >= "5.0"',
            f"sys_platform != {sys.platform!r}",
        ):
            line = "name; " + marker
            req = build_install_req(line, requirement_line=None)
            assert str(req.marker) == str(Marker(marker))
            assert not req.match_marker()

    def test_extras_for_line_path_requirement(self) -> None:
        line = "SomeProject[ex1,ex2]"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_install_req(line, requirement_line=requirement_line)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_extras_for_line_url_requirement(self) -> None:
        line = "git+https://url#egg=SomeProject[ex1,ex2]"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_install_req(line, requirement_line=requirement_line)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_extras_for_editable_path_requirement(self) -> None:
        url = ".[ex1,ex2]"
        filename = "filename"

        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=url,
        )
        req = build_editable_req(url, requirement_line=requirement_line)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_extras_for_editable_url_requirement(self) -> None:
        url = "git+https://url#egg=SomeProject[ex1,ex2]"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=url,
        )
        req = build_editable_req(url, requirement_line=requirement_line)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_unexisting_path(self) -> None:
        result = build_install_req(posixpath.join("this", "path", "does", "not", "exist"))
        assert result.link.url == "this/path/does/not/exist"

    def test_single_equal_sign(self) -> None:
        with pytest.raises(InstallationError):
            build_install_req("toto=42")

    def test_unidentifiable_name(self) -> None:
        test_name = "-"
        with pytest.raises(InstallationError):
            build_install_req(test_name)

    def test_requirement_file(self) -> None:
        req_file_path = os.path.join(self.tempdir, "test.txt")
        with open(req_file_path, "w") as req_file:
            req_file.write("pip\nsetuptools")
        result =  build_install_req(req_file_path)
        assert result.req is None
        assert result.link.url.endswith("test.txt")


def test_parse_editable_explicit_vcs() -> None:
    assert parse_editable("svn+https://foo#egg=foo") == (
        "foo",
        "svn+https://foo#egg=foo",
        set(),
    )


def test_parse_editable_with_egg_fragment() -> None:
    assert parse_editable("path/to/AnotherProject#egg=AnotherProject") == (
        "AnotherProject",
        "path/to/AnotherProject#egg=AnotherProject",
        set()
    )

def test_parse_editable_without_egg_fragment() -> None:
    assert parse_editable("path/to/AnotherProject") == (
        None,
        "path/to/AnotherProject",
        set()
    )


def test_parse_editable_example_from_docstring1() -> None:
    # taken from the parse_editable() docstring
    # it is not clear if this is supported and extra are not detected correctly
    # this is a rare edge case anyway
    assert parse_editable("svn+http://blahblah@rev#egg=Foobar[baz]&subdirectory=version_subdir") == (
        'Foobar[baz]',
        'svn+http://blahblah@rev#egg=Foobar[baz]&subdirectory=version_subdir',
        set(),
    )


def test_parse_editable_example_from_docstring2() -> None:
    # taken from the parse_editable() docstring
    assert parse_editable(".[some_extra]") == (None, '.', {'some_extra'})


def test_parse_editable_vcs_extras() -> None:
    assert parse_editable("svn+https://foo#egg=foo[extras]") == (
        "foo",
        "svn+https://foo#egg=foo",
         {'extras'},
    )


def test_exclusive_environment_marker() -> None:
    """Make sure RequirementSet accepts several excluding env marker"""
    eq36 = build_install_req("Django>=1.6.10,<1.7 ; python_version == '3.6'")
    eq36.user_supplied = True
    ne36 = build_install_req("Django>=1.6.10,<1.8 ; python_version != '3.6'")
    ne36.user_supplied = True



@pytest.mark.parametrize(
    "path, expected",
    [
        # Test UNIX-like paths
        ("/path/to/installable", True),
        # Test relative paths
        ("./path/to/installable", True),
        # Test current path
        (".", True),
        # Test url paths
        ("https://whatever.com/test-0.4-py2.py3-bogus-any.whl", True),
        # Test pep440 paths
        ("test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl", True),
        # Test wheel
        ("simple-0.1-py2.py3-none-any.whl", False),
        # editable egg
        ("path/to/AnotherProject#egg=AnotherProject", True),
    ],
)
def test_looks_like_path(path: str, expected: bool) -> None:
    assert _looks_like_path(path) == expected


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
    "args, expected",
    [
        # Test pep440 urls
        (
            (
                "/path/to/foo @ git+http://foo.com@ref#egg=foo",
                "foo @ git+http://foo.com@ref#egg=foo",
            ),
            "/path/to/foo @ git+http://foo.com@ref#egg=foo",
        ),
        # Test pep440 urls without spaces
        (
            (
                "/path/to/foo@git+http://foo.com@ref#egg=foo",
                "foo @ git+http://foo.com@ref#egg=foo",
            ),
            "/path/to/foo@git+http://foo.com@ref#egg=foo",
        ),
        # Test pep440 wheel
        (
            (
                "/path/to/test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl",
                "test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl",
            ),
            "/path/to/test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl",
        ),
        # Test name is not a file
        (("/path/to/simple==0.1", "simple==0.1"), None),
    ],
)
def test_get_url_from_path(
    args: Tuple[str, str],
    expected: None,
) -> None:
    assert _get_url_from_path(*args) == expected


def test_get_url_from_path__archive_file() -> None:
    name = "simple-0.1-py2.py3-none-any.whl"
    path = os.path.join("/path/to/" + name)
    assert _get_url_from_path(path, name) == path


def test_get_url_from_path__installable_error() -> None:
    name = "some/setuptools/project"
    path = os.path.join("/path/to/" + name)
    result = _get_url_from_path(path, name)
    assert result == "/path/to/some/setuptools/project"
