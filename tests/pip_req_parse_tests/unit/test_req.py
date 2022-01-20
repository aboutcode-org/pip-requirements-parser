
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import os
import shutil
import sys
import tempfile
from typing import Tuple

import pytest
from packaging.markers import Marker
from packaging.requirements import Requirement

from pip_requirements import (
    _get_url_from_path,
    _looks_like_path,
    install_req_from_editable,
    install_req_from_line,
    parse_editable,
)
from pip_requirements import InstallationError
from pip_requirements import InvalidWheelFilename
from pip_requirements import RequirementLine


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
        line = "test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl"
        req = install_req_from_line(line)
        assert str(req.req) == "test==0.4"
        assert str(req.link) == "test @ https://whatever.com/test-0.4-py2.py3-bogus-any.whl"

    def test_pep440_url_link_requirement(self) -> None:
        line = "foo @ git+http://foo.com@ref#egg=foo"
        req = install_req_from_line(line)
        assert str(req.req) == "foo"
        assert str(req.link) == "foo @ git+http://foo.com@ref#egg=foo"

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

    def test_unsupported_wheel_local_file_requirement_raises(self) -> None:
        req = install_req_from_line("simple.dist-0.1-py1-none-invalid.whl")
        assert req.link is not None
        assert req.link.is_wheel
        assert req.link.url == "simple.dist-0.1-py1-none-invalid.whl"

    def test_str(self) -> None:
        req = install_req_from_line("simple==0.1")
        assert str(req) == "simple==0.1"

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
            req = install_req_from_line(line, requirement_line=None)
            assert str(req.markers) == str(Marker(markers))
            assert req.match_markers()

        # don't match
        for markers in (
            'python_version >= "5.0"',
            f"sys_platform != {sys.platform!r}",
        ):
            line = "name; " + markers
            req = install_req_from_line(line, requirement_line=None)
            assert str(req.markers) == str(Marker(markers))
            assert not req.match_markers()

    def test_extras_for_line_path_requirement(self) -> None:
        line = "SomeProject[ex1,ex2]"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = install_req_from_line(line, requirement_line=requirement_line)
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
        req = install_req_from_line(line, requirement_line=requirement_line)
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
        req = install_req_from_editable(url, requirement_line=requirement_line)
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
        req = install_req_from_editable(url, requirement_line=requirement_line)
        assert len(req.extras) == 2
        assert req.extras == {"ex1", "ex2"}

    def test_unexisting_path(self) -> None:
        result = install_req_from_line(os.path.join("this", "path", "does", "not", "exist"))
        assert result.link.url == "this/path/does/not/exist"

    def test_single_equal_sign(self) -> None:
        with pytest.raises(InstallationError):
            install_req_from_line("toto=42")

    def test_unidentifiable_name(self) -> None:
        test_name = "-"
        with pytest.raises(InstallationError):
            install_req_from_line(test_name)

    def test_requirement_file(self) -> None:
        req_file_path = os.path.join(self.tempdir, "test.txt")
        with open(req_file_path, "w") as req_file:
            req_file.write("pip\nsetuptools")
        result =  install_req_from_line(req_file_path)
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


def test_exclusive_environment_markers() -> None:
    """Make sure RequirementSet accepts several excluding env markers"""
    eq36 = install_req_from_line("Django>=1.6.10,<1.7 ; python_version == '3.6'")
    eq36.user_supplied = True
    ne36 = install_req_from_line("Django>=1.6.10,<1.8 ; python_version != '3.6'")
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
