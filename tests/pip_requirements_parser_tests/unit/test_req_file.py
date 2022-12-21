
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import pathlib
import textwrap
from typing import Callable
from typing import Iterator, List, Union
from unittest import mock

import pytest
from packaging.specifiers import SpecifierSet

import pip_requirements_parser  # this will be monkeypatched
from pip_requirements_parser import RequirementsFileParseError
from pip_requirements_parser import build_editable_req
from pip_requirements_parser import build_install_req
from pip_requirements_parser import (
    break_args_options,
    split_comments,
    join_lines,
    parse_requirements,
    preprocess,
)
from pip_requirements_parser import CommentLine
from pip_requirements_parser import CommentRequirementLine
from pip_requirements_parser import IncorrectRequirementLine
from pip_requirements_parser import InstallRequirement
from pip_requirements_parser import InvalidRequirementLine
from pip_requirements_parser import OptionLine
from pip_requirements_parser import RequirementsFile
from pip_requirements_parser import RequirementLine
from pip_requirements_parser import TextLine

from pip_requirements_parser_tests.lib import TestData, requirements_file
from pip_requirements_parser_tests.lib.path import Path


def get_requirements_and_lines(
    filename: str,
    is_constraint: bool = False,
    include_nested: bool = False,
) -> Iterator[Union[
    InstallRequirement, 
    OptionLine, 
    InvalidRequirementLine, 
    CommentRequirementLine
]]:
    """
    Wrap parse_requirements/build_req_from_parsedreq to
    avoid having to write the same chunk of code in lots of tests.
    """
    return list(RequirementsFile.parse(
        filename=filename,
        is_constraint=is_constraint,
        include_nested=include_nested,
    ))


@pytest.fixture
def parse_requirement_line(
    monkeypatch: pytest.MonkeyPatch,  # NOQA
    tmpdir: Path,
) -> Callable:
    """
    Return a callable to process a single line of text as if it were a full
    requirements file when calling ``parse_requirements``. Writes the line to
    a temp file.
    """

    def process_line(
        line: str,
        filename: str = 'requirements.txt',
        line_number: int = 1,
        is_constraint: bool = False,
    ) -> List[Union[
        InstallRequirement, 
        OptionLine, 
        InvalidRequirementLine, 
        CommentRequirementLine
    ]]:

        prefix = "\n" * (line_number - 1)
        path = tmpdir.joinpath(filename)
        path.parent.mkdir(exist_ok=True)
        path.write_text(prefix + line)
        monkeypatch.chdir(str(tmpdir))
        return get_requirements_and_lines(filename, is_constraint)

    return process_line


@pytest.fixture
def parse_requirement_text(
    monkeypatch: pytest.MonkeyPatch,  # NOQA
    tmpdir: Path,
) -> Callable:
    """
    Return a callable to process some text as if it were requirements file when
    creating a ``RequirementsFile``. Writes the content to a temp file.
    """

    def process_file(
        text: str,
        filename: str = 'requirements.txt',
        include_nested = False,
    ) -> RequirementsFile:
        path = tmpdir.joinpath(filename)
        path.parent.mkdir(exist_ok=True)
        path.write_text(text)
        monkeypatch.chdir(str(tmpdir))
        return RequirementsFile.from_file(path, include_nested=include_nested)

    return process_file


def test_read_file_url(tmp_path: pathlib.Path) -> None:
    reqs = tmp_path.joinpath("requirements.txt")
    reqs.write_text("foo")
    result = list(parse_requirements(reqs.as_posix()))

    assert len(result) == 1
    result = result[0]
    assert result.requirement_string == "foo"
    assert result.requirement_line.to_dict() == dict(line_number=1, line='foo')


class TestPreprocess:
    """tests for `preprocess`"""

    def test_comments_and_joins_case1(self) -> None:
        content = textwrap.dedent(
            """\
          req1 \\
          # comment \\
          req2
        """
        )
        result = preprocess(content)
        assert list(result) == [
            TextLine(line_number=1, line='req1'),
            CommentLine(line_number=1, line='# comment \\'),
            TextLine(line_number=3, line='req2'),
        ]

    def test_comments_and_joins_case2(self) -> None:
        content = textwrap.dedent(
            """\
          req1\\
          # comment
        """
        )
        result = preprocess(content)
        assert list(result) == [
            TextLine(line_number=1, line='req1'),
            CommentLine(line_number=1, line='# comment'),
        ]

    def test_comments_and_joins_case3(self) -> None:
        content = textwrap.dedent(
            """\
          req1 \\
          # comment
          req2
        """
        )
        result = preprocess(content)
        assert list(result) == [
            TextLine(line_number=1, line='req1'),
            CommentLine(line_number=1, line='# comment'),
            TextLine(line_number=3, line='req2'),
        ]


class TestSplitComments:

    def test_split_comments_ignore_empty_line(self) -> None:
        lines = [(1, ""), (2, "req1"), (3, "req2")]
        result = split_comments(lines)
        assert list(result) == [(2, "req1"), (3, "req2")]

    def test_split_comments_returns_comment_line(self) -> None:
        lines = [(1, "req1"), (2, "# comment"), (3, "req2")]
        result = split_comments(lines)
        assert list(result) == [
            TextLine(line_number=1, line='req1'),
            CommentLine(line_number=2, line='# comment'),
            TextLine(line_number=3, line='req2'),
        ]

    def test_split_comments_returns_end_of_line_comment(self) -> None:
        lines = [(1, "req1"), (2, "req # comment"), (3, "req2")]
        result = split_comments(lines)
        assert list(result) == [
            TextLine(line_number=1, line='req1'),
            TextLine(line_number=2, line='req'),
            CommentLine(line_number=2, line='# comment'),
            TextLine(line_number=3, line='req2'),
        ]


class TestJoinLines:
    """tests for `join_lines`"""

    def test_join_lines(self) -> None:
        lines = enumerate(
            [
                "line 1",
                "line 2:1 \\",
                "line 2:2",
                "line 3:1 \\",
                "line 3:2 \\",
                "line 3:3",
                "line 4",
            ],
            start=1,
        )
        expect = [
            (1, "line 1"),
            (2, "line 2:1 line 2:2"),
            (4, "line 3:1 line 3:2 line 3:3"),
            (7, "line 4"),
        ]
        assert expect == list(join_lines(lines))

    def test_last_line_with_escape(self) -> None:
        lines = enumerate(
            [
                "line 1",
                "line 2 \\",
            ],
            start=1,
        )
        expect = [
            (1, "line 1"),
            (2, "line 2 "),
        ]
        assert expect == list(join_lines(lines))


class TestProcessFile:

    def test_can_dumps_name_at_url_requirements_from_file(self, parse_requirement_text) -> None:
        text = "name@http://foo.com\n"
        rf = parse_requirement_text(text)
        assert rf.dumps() == text

    def test_can_dumps_local_dot_path_from_file(self, parse_requirement_text) -> None:
        text = "."
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.name == None
        assert r.link.url == "."

    def test_can_dumps_local_dot_path_extras_from_file(self, parse_requirement_text) -> None:
        text = ". [extra]"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.name == None
        assert r.link.url == "."
        assert r.extras == {"extra"}
        assert r.dumps() == ". [extra]"

    def test_can_dumps_local_path_from_file(self, parse_requirement_text) -> None:
        text = ".foobar"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.name == None
        assert not r.specifier
        assert r.link.url == ".foobar"
        assert r.dumps() == text

    def test_can_dumps_local_path_extras_from_file(self, parse_requirement_text) -> None:
        text = ".foobar [extra]"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.name == None
        assert not r.specifier
        assert r.link.url == ".foobar"
        assert r.extras == {"extra"}
        assert r.dumps() == text

    def test_can_dumps_local_path_to_wheel_from_file(self, parse_requirement_text) -> None:
        text = "./downloads/numpy-1.9.2-cp34-none-win32.whl"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_wheel
        assert r.name == "numpy"
        assert r.link.url == "./downloads/numpy-1.9.2-cp34-none-win32.whl"
        assert r.extras == set()
        assert r.dumps() == text

    def test_can_dumps_local_path_to_wheel_with_extras_from_file(self, parse_requirement_text) -> None:
        text = "./downloads/numpy-1.9.2-cp34-none-win32.whl [extra,other]"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert not r.is_wheel
        assert r.is_local_path
        assert r.name == None
        assert not r.specifier
        assert r.link.url == "./downloads/numpy-1.9.2-cp34-none-win32.whl"
        assert r.extras == {"extra", "other"}
        assert r.dumps() == text

    def test_can_dumps_local_path_to_plain_wheel_from_file(self, parse_requirement_text) -> None:
        text = "numpy-1.9.2-cp34-none-win32.whl"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_wheel
        assert r.name == "numpy"
        assert str(r.specifier) == "==1.9.2"
        assert r.link.url == "numpy-1.9.2-cp34-none-win32.whl"
        assert r.extras == set()
        assert r.dumps() == "numpy-1.9.2-cp34-none-win32.whl"

    def test_can_dumps_local_path_to_plain_wheel_with_extras_from_file(self, parse_requirement_text) -> None:
        text = "numpy-1.9.2-cp34-none-win32.whl [extra,other]"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_wheel
        assert r.name == "numpy-1.9.2-cp34-none-win32.whl"
        assert not r.specifier
        assert r.link == None
        assert r.extras == {"extra", "other"}
        assert r.dumps() == "numpy-1.9.2-cp34-none-win32.whl [extra,other]"

    def test_can_dumps_local_targz_archive(self, parse_requirement_text) -> None:
        text = "sampleproject-1.0.tar.gz"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert not r.is_wheel
        assert r.is_archive
        assert r.name == None
        assert not r.specifier
        assert r.link.url == "sampleproject-1.0.tar.gz"
        assert r.extras == set()
        assert r.dumps() == text

    def test_can_dumps_vcs_url_egg_and_extra(self, parse_requirement_text) -> None:
        text = "git+https://github.com/lazzrek/raven-python.git#egg=raven[flask]"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert not r.is_wheel
        assert not r.is_archive
        assert r.is_vcs_url
        assert r.name == "raven"
        assert not r.specifier
        assert r.link.url == "git+https://github.com/lazzrek/raven-python.git#egg=raven[flask]"
        assert r.extras == {'flask'}
        assert r.dumps() == text

    def test_parse_name_at_url_to_wheel_with_packaging(self, parse_requirement_text) -> None:
        from packaging.requirements import Requirement

        text = "SomeProject@http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        r = Requirement(text)
        assert r.url =="http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.name == "SomeProject"
        assert not r.specifier
        assert r.extras == set()
        assert str(r) == "SomeProject@ http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"

    def test_parse_name_at_url__with_packaging(self, parse_requirement_text) -> None:
        from packaging.requirements import Requirement

        text = "SomeProject@http://my.package.repo/SomeProject2.tgz"
        r = Requirement(text)
        assert r.url =="http://my.package.repo/SomeProject2.tgz"
        assert r.name == "SomeProject"
        assert not r.specifier
        assert r.extras == set()
        assert str(r) == "SomeProject@ http://my.package.repo/SomeProject2.tgz"

    def test_parse_name_at_vcs_url_to_wheel_with_packaging(self, parse_requirement_text) -> None:
        from packaging.requirements import Requirement

        text = "SomeProject@git+http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        r = Requirement(text)
        assert r.url =="git+http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.name == "SomeProject"
        assert not r.specifier
        assert r.extras == set()
        assert str(r) == "SomeProject@ git+http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"

    def test_can_dumps_name_at_url_to_wheel(self, parse_requirement_text) -> None:
        text = "SomeProject@http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_name_at_url
        assert r.is_wheel
        assert r.is_archive
        assert not r.is_vcs_url
        assert r.name == "SomeProject"
        assert not r.specifier
        assert r.link.url == "http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.extras == set()
        assert str(r.req) ==  "SomeProject@ http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.dumps() == text

    def test_can_dumps_name_at_url_to_wheel_with_space(self, parse_requirement_text) -> None:
        text = "SomeProject@ http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_name_at_url
        assert r.is_wheel
        assert r.is_archive
        assert not r.is_vcs_url
        assert r.name == "SomeProject"
        assert not r.specifier
        assert r.link.url == "http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.extras == set()
        assert str(r.req) == "SomeProject@ http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.dumps() == "SomeProject@http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"

    def test_can_dumps_name_at_vcs_url_to_wheel(self, parse_requirement_text) -> None:
        text = "SomeProject@git+http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_name_at_url
        assert r.is_wheel
        assert r.is_archive
        assert r.req.url == "git+http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.is_vcs_url
        assert r.name == "SomeProject"
        assert not r.specifier
        assert r.link.url == "git+http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.extras == set()
        assert r.dumps() == text

    def test_can_dumps_name_at_url_to_wheel_with_space2(self, parse_requirement_text) -> None:
        text = "SomeProject@http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert r.is_name_at_url
        assert r.is_wheel
        assert r.is_archive
        assert not r.is_vcs_url
        assert not r.specifier
        assert r.name == "SomeProject"
        assert r.req.name == "SomeProject"
        assert r.link.url == "http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.req.url == "http://my.package.repo/SomeProject2-1.2.3-py33-none-any.whl"
        assert r.extras == set()
        assert r.dumps() == text

    def test_can_collect_invalid_top_options_mixed_on_req_line(self, parse_requirement_text) -> None:
        text = "psycopg2>=2.7.4 --no-binary psycopg2"
        rf = parse_requirement_text(text)
        assert not rf.requirements
        assert rf.invalid_lines[0].line == text
        assert rf.invalid_lines[0].error_message==(
            "Invalid global options, not supported with a requirement spec: --no-binary psycopg2"
        )

    def test_can_process_comment_with_colon(self, parse_requirement_text) -> None:
        text = "# No closing quotation: works because we do not validate hashes"
        rf = parse_requirement_text(text)
        co = rf.comments[0]
        assert co.line == "# No closing quotation: works because we do not validate hashes"

    def test_can_process_trailing_quotes(self, parse_requirement_text) -> None:
        text = "FooProject==1.2 --hash=sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\","
        rf = parse_requirement_text(text)
        assert not rf.requirements
        il = rf.invalid_lines[0]
        assert il.error_message == "No closing quotation"

    def test_can_dumps_vcs_editable_with_egg_extras_and_other_query_string_args(self, parse_requirement_text) -> None:
        text = "--editable git+https://github.com/techalchemy/pythonfinder.git@master#egg=pythonfinder[dev]&subdirectory=mysubdir"
        rf = parse_requirement_text(text)
        r = rf.requirements[0]
        assert not r.is_name_at_url
        assert r.is_vcs_url
        assert not r.specifier
        assert r.name == "pythonfinder"
        assert r.link.url == "git+https://github.com/techalchemy/pythonfinder.git@master#egg=pythonfinder[dev]&subdirectory=mysubdir"
        assert r.extras == {"dev"}
        assert r.dumps() == text


class TestProcessLine:

    def test_parser_can_detect_editable_egg(self, parse_requirement_line) -> None:
        result = parse_requirement_line(
            "-e path/to/AnotherProject#egg=AnotherProject", "file", 1)
        assert len(result) == 1
        req = result[0]

        requirement_line = RequirementLine(
            line='-e path/to/AnotherProject#egg=AnotherProject',
            line_number=1,
            filename='file',
        )
        assert req.requirement_line == requirement_line
        assert isinstance(req, InstallRequirement)

        assert req.is_editable
        assert req.link.url == "path/to/AnotherProject#egg=AnotherProject" 

    def test_parser_error(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--bogus", "file", 1)
        expected = InvalidRequirementLine(
            requirement_line=RequirementLine(
                line='--bogus',
                line_number=1,
                filename='file',
            ),
            error_message='pip_requirements_parser: error: no such option: --bogus\n',
        )
        assert result == [expected]

    def test_parse_requirement_to_dict(self, parse_requirement_line) -> None:
        line = "pkg==1.0.0 --hash=somehash"
        result = parse_requirement_line(line, "file", 1)[0].to_dict()
        expected = {
            'name': 'pkg',
            'specifier': ['==1.0.0'],
            'extras': [],
            'link': None,
            'marker': None,
            'global_options': [],
            'hash_options': ['somehash'],
            'install_options': [],
            'invalid_options': {},
            
            'is_editable': False,
            'is_constraint': False,
            
            'requirement_line': {
                'line': 'pkg==1.0.0 --hash=somehash',
                'line_number': 1},
            
            'has_egg_fragment': False,
            'is_archive': None,
            'is_local_path': None,
            'is_name_at_url': False,
            'is_pinned': True,
            'is_url': None,
            'is_vcs_url': None,
            'is_wheel': False,
        }
        assert result == expected
 
    def test_parser_non_offending_line(self, parse_requirement_line) -> None:
        try:
            parse_requirement_line("pkg==1.0.0 --hash=sha256:somehash", "file", 1)
        except RequirementsFileParseError:
            pytest.fail("Reported offending line where it should not.")

    def test_only_one_req_per_line(self, parse_requirement_line) -> None:
        reqs = parse_requirement_line(
            line="req1 req2", filename="file", line_number=1
        )
        assert type(reqs[0]) == InvalidRequirementLine

    def test_error_message(self, parse_requirement_line) -> None:
        reqs = parse_requirement_line(
            "my-package=1.0", filename="path/requirements.txt", line_number=3
        )
        assert type(reqs[0]) == InvalidRequirementLine

    def test_yield_line_requirement(self, parse_requirement_line) -> None:
        line = "SomeProject"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_install_req(line, requirement_line=requirement_line)
        assert repr(parse_requirement_line(line, filename, 1)[0]) == repr(req)

    def test_yield_pep440_line_requirement(self, parse_requirement_line) -> None:
        line = "SomeProject @ https://url/SomeProject-py2-py3-none-any.whl"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_install_req(line, requirement_line=requirement_line)
        assert repr(parse_requirement_line(line, filename, 1)[0]) == repr(req)

    def test_yield_line_constraint(self, parse_requirement_line) -> None:
        line = "SomeProject"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_install_req(line, requirement_line=requirement_line, is_constraint=True)
        found_req = parse_requirement_line(line, filename, 1, is_constraint=True)[0]
        assert repr(found_req) == repr(req)
        assert found_req.is_constraint is True

    def test_yield_line_requirement_with_spaces_in_specifier(self, parse_requirement_line) -> None:
        line = "SomeProject >= 2"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_install_req(line, requirement_line=requirement_line)
        assert repr(parse_requirement_line(line, filename, 1)[0]) == repr(req)
        assert req.req is not None
        assert str(req.req.specifier) == ">=2"

    def test_yield_editable_requirement(self, parse_requirement_line) -> None:
        url = "git+https://url#egg=SomeProject"
        line = f"-e {url}"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_editable_req(url, requirement_line=requirement_line)
        assert repr(parse_requirement_line(line, filename, 1)[0]) == repr(req)

    def test_yield_editable_constraint(self, parse_requirement_line) -> None:
        url = "git+https://url#egg=SomeProject"
        line = f"-e {url}"
        filename = "filename"
        requirement_line = RequirementLine(
            filename=filename,
            line_number=1,
            line=line,
        )
        req = build_editable_req(url, requirement_line=requirement_line, is_constraint=True)
        found_req = parse_requirement_line(line, filename, 1, is_constraint=True)[0]
        assert repr(found_req) == repr(req)
        assert found_req.is_constraint is True

    def test_nested_constraints_file(
        self, 
        monkeypatch: pytest.MonkeyPatch,  # NOQA
        tmpdir: Path,
    ) -> None:

        req_name = "hello"
        req_file = tmpdir / "parent" / "req_file.txt"
        req_file.parent.mkdir()
        req_file.write_text("-c reqs.txt")
        req_file.parent.joinpath("reqs.txt").write_text(req_name)

        monkeypatch.chdir(str(tmpdir))

        reqs = get_requirements_and_lines("./parent/req_file.txt", include_nested=True)
        assert len(reqs) == 2
        assert reqs[0].name == req_name
        assert reqs[0].is_constraint

        assert reqs[1].options ==  {'constraints': ["reqs.txt"]}

    def test_options_on_a_requirement_line(self, parse_requirement_line) -> None:
        line = (
            "SomeProject --install-option=yo1 --install-option yo2 "
            '--global-option="yo3" --global-option "yo4"'
        )
        filename = "filename"
        req = parse_requirement_line(line, filename, 1)[0]
        assert req.global_options == ["yo3", "yo4"]
        assert req.install_options == ["yo1", "yo2"]

    def test_hash_options(self, parse_requirement_line) -> None:
        """Test the --hash option: mostly its value storage.

        Make sure it reads and preserve multiple hashes.

        """
        line = (
            "SomeProject --hash=sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b1"
            "61e5c1fa7425e73043362938b9824 "
            "--hash=sha384:59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c"
            "3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f "
            "--hash=sha256:486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8"
            "e5a6c65260e9cb8a7"
        )
        filename = "filename"
        req = parse_requirement_line(line, filename, 1)[0]
        assert sorted(req.hash_options) == [
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "sha256:486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
            "sha384:59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcd"
                "b9c666fa90125a3c79f90397bdf5f6a13de828684f"
        ]

    def test_parse_no_index(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--no-index", "file", 1)
        assert result[0].options == {"no_index": True}

    def test_set_finder_index_url(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--index-url=url", "file", 1)
        assert result[0].options == {"index_url": "url"}

    def test_set_finder_find_links(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--find-links=url", "file", 1)
        assert result[0].options == {"find_links": ["url"]}

    def test_set_finder_extra_index_urls(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--extra-index-url=url", "file", 1)
        assert result[0].options == {"extra_index_urls": ["url"]}

    def test_set_finder_allow_all_prereleases(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--pre", "file", 1)
        assert result[0].options == {"pre": True}

    def test_use_feature(self, parse_requirement_line) -> None:
        """--use-feature can be set in requirements files."""
        result = parse_requirement_line("--use-feature=2020-resolver", "file", 1)
        assert result[0].options == {"use_features": ["2020-resolver"]}

    def test_relative_http_nested_req_files(
        self,
        monkeypatch: pytest.MonkeyPatch,  # NOQA
    ) -> None:
        """
        Test a relative nested req file path is joined with the req file url
        """
        req_name = "hello"
        req_file = "http://me.com/me/req_file.txt"

        def get_file_content(filename: str) ->  str:
            if filename == req_file:
                return "-r reqs.txt"
            elif filename == "http://me.com/me/reqs.txt":
                return req_name
            assert False, f"Unexpected file requested {filename}"

        monkeypatch.setattr(
            pip_requirements_parser, "get_file_content", get_file_content
        )

        result = get_requirements_and_lines(req_file, include_nested=True)
        assert len(result) == 2
        assert result[0].name == req_name
        assert not result[0].is_constraint

        assert result[1].options ==  {'requirements': ["reqs.txt"]}

    def test_relative_local_nested_req_files(
        self,
        monkeypatch: pytest.MonkeyPatch,  # NOQA
        tmpdir: Path,
    ) -> None:
        """
        Test a relative nested req file path is joined with the req file dir
        """
        req_name = "hello"
        req_file = tmpdir / "parent" / "req_file.txt"
        req_file.parent.mkdir()
        req_file.write_text("-r reqs.txt")
        req_file.parent.joinpath("reqs.txt").write_text(req_name)

        monkeypatch.chdir(str(tmpdir))

        reqs = get_requirements_and_lines("./parent/req_file.txt", include_nested=True)
        assert len(reqs) == 2
        assert reqs[0].name == req_name
        assert not reqs[0].is_constraint

        assert reqs[1].options ==  {'requirements': ["reqs.txt"]}

    def test_absolute_local_nested_req_files(self, tmpdir: Path) -> None:
        """
        Test an absolute nested req file path
        """
        req_name = "hello"
        req_file = tmpdir / "parent" / "req_file.txt"
        req_file.parent.mkdir()
        other_req_file = tmpdir / "other" / "reqs.txt"
        other_req_file.parent.mkdir()
        # POSIX-ify the path, since Windows backslashes aren't supported.
        other_req_file_str = str(other_req_file).replace("\\", "/")

        req_file.write_text(f"-r {other_req_file_str}")
        other_req_file.write_text(req_name)

        # TODO: also test nested parsing!

        reqs = get_requirements_and_lines(str(req_file), include_nested=True)
        assert len(reqs) == 2
        assert reqs[0].name == req_name
        assert not reqs[0].is_constraint

        assert reqs[1].options ==  {'requirements': [other_req_file_str]}


    def test_absolute_http_nested_req_file_in_local(
        self,
        monkeypatch: pytest.MonkeyPatch,  # NOQA
        tmpdir: Path,
    ) -> None:
        """
        Test a nested req file url in a local req file
        """
        req_name = "hello"
        req_file = tmpdir / "req_file.txt"
        nested_req_file = "http://me.com/me/req_file.txt"

        def get_file_content(filename: str) -> str:
            if filename == str(req_file):
                return f"-r {nested_req_file}"
            elif filename == nested_req_file:
                return req_name

            assert False, f"Unexpected file requested {filename}"

        monkeypatch.setattr(
            pip_requirements_parser, "get_file_content", get_file_content
        )

        result = get_requirements_and_lines(req_file, include_nested=True)
        assert len(result) == 2
        
        assert result[0].name == req_name
        assert not result[0].is_constraint

        assert result[1].options == {'requirements': ['http://me.com/me/req_file.txt']}


class TestBreakOptionsArgs:
    def test_no_args(self) -> None:
        assert ("", "--option") == break_args_options("--option")

    def test_no_options(self) -> None:
        assert ("arg arg", "") == break_args_options("arg arg")

    def test_args_short_options(self) -> None:
        result = break_args_options("arg arg -s")
        assert ("arg arg", "-s") == result

    def test_args_long_options(self) -> None:
        result = break_args_options("arg arg --long")
        assert ("arg arg", "--long") == result


class TestOptionVariants:

    # this suite is really just testing optparse, but added it anyway

    def test_variant1(self, parse_requirement_line) -> None:
        result = parse_requirement_line("-i url", "file", 1)
        assert result[0].options == {"index_url": "url"}

    def test_variant2(self, parse_requirement_line) -> None:
        result = parse_requirement_line("-i 'url'", "file", 1)
        assert result[0].options == {"index_url": "url"}

    def test_variant3(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--index-url=url", "file", 1)
        assert result[0].options == {"index_url": "url"}

    def test_variant4(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--index-url url", "file", 1)
        assert result[0].options == {"index_url": "url"}

    def test_variant5(self, parse_requirement_line) -> None:
        result = parse_requirement_line("--index-url='url'", "file", 1)
        assert result[0].options == {"index_url": "url"}


class TestParseRequirements:
    """tests for `get_requirements_and_lines`"""

    def test_multiple_appending_options(self, tmpdir: Path) -> None:
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("--extra-index-url url1 \n")
            fp.write("--extra-index-url url2 ")

        
        result = get_requirements_and_lines(tmpdir.joinpath("req1.txt"))
        assert result[0].options =={"extra_index_urls":["url1"]}
        assert result[1].options =={"extra_index_urls":["url2"]}


    def test_expand_missing_env_variables(self, tmpdir: Path) -> None:

        # NOTE: WE DO NOT EXPAND VARS in constrast with PIP
        req_url = (
            "https://${NON_EXISTENT_VARIABLE}:$WRONG_FORMAT@"
            "%WINDOWS_FORMAT%github.com/user/repo/archive/master.zip"
        )

        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write(req_url)

        # Construct the session outside the monkey-patch, since it access the
        # env
        with mock.patch("pip_requirements_parser.os.getenv") as getenv:
            getenv.return_value = ""

            reqs = get_requirements_and_lines(tmpdir.joinpath("req1.txt"))

            assert len(reqs) == 1, "parsing requirement file with env variable failed"
            assert reqs[0].link is not None
            assert (
                reqs[0].link.url == req_url
            ), "ignoring invalid env variable in req file failed"

    def test_join_lines(self, tmpdir: Path) -> None:
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("--extra-index-url url1 \\\n--extra-index-url url2")

        result = get_requirements_and_lines(tmpdir.joinpath("req1.txt"))

        assert result[0].options =={"extra_index_urls":['url1', 'url2']}

    def test_req_file_parse_no_only_binary(self, data: TestData) -> None:
        """
        # default is no constraints
        # We're not testing the format control logic here, just that the options are
        # accepted
        --no-binary fred
        --only-binary wilma
        """
        result = get_requirements_and_lines(
            data.reqfiles.joinpath("supported_options2.txt")
        )
        assert len(result) == 5
        assert all(isinstance(r, CommentRequirementLine) for r in result[:3])
        assert result[3].options == {'no_binary': ['fred']}
        assert result[4].options == {'only_binary': ['wilma']}

    def test_req_file_parse_comment_start_of_line(self, tmpdir: Path) -> None:
        """
        Test parsing comments in a requirements file
        """
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("# Comment ")

        result = get_requirements_and_lines(tmpdir.joinpath("req1.txt"))
        assert len(result) ==1
        assert isinstance(result[0], CommentRequirementLine)
        assert result[0].line == "# Comment"

    def test_req_file_parse_comment_end_of_line_with_url(self, tmpdir: Path) -> None:
        """
        Test parsing comments in a requirements file
        """
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("https://example.com/foo.tar.gz # Comment ")

        result = get_requirements_and_lines(tmpdir.joinpath("req1.txt"))
        assert len(result) == 2
        assert result[0].link is not None
        assert result[0].link.url == "https://example.com/foo.tar.gz"
        assert result[1].line == "# Comment"

    def test_req_file_parse_egginfo_end_of_line_with_url(self, tmpdir: Path) -> None:
        """
        Test parsing comments in a requirements file
        """
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("https://example.com/foo.tar.gz#egg=wat")

        result = get_requirements_and_lines(tmpdir.joinpath("req1.txt"))

        assert len(result) == 1
        assert result[0].name == "wat"

    def test_req_file_no_finder(self, tmpdir: Path) -> None:
        """
        Test parsing a requirements file without a finder
        """
        with open(tmpdir.joinpath("req.txt"), "w") as fp:
            fp.write(
                """
    --find-links https://example.com/
    --index-url https://example.com/
    --extra-index-url https://two.example.com/
    --no-use-wheel
    --no-index
            """
            )

        result = get_requirements_and_lines(tmpdir.joinpath("req.txt"))
        assert len(result) == 6
        assert [type(l) for l in result] == [
            OptionLine,
            OptionLine,
            OptionLine,
            OptionLine,
            IncorrectRequirementLine,
            OptionLine,
        ]

    def test_install_requirements_with_options(
        self,
        tmpdir: Path,
    ) -> None:

        global_option = "--dry-run"
        install_option = "--prefix=/opt"

        content = """
        --only-binary :all:
        INITools==2.0 --global-option="{global_option}" \
                        --install-option "{install_option}"
        """.format(
            global_option=global_option, install_option=install_option
        )

        with requirements_file(content, tmpdir) as reqs_file:
            rf = reqs_file.resolve()
            req = get_requirements_and_lines(rf)

        assert len(req) == 2
        assert req[0].options == {'only_binary': [':all:']}
        assert req[1].name == "INITools"
        assert req[1].specifier == SpecifierSet('==2.0')
        assert req[1].global_options == ["--dry-run"]
        assert req[1].install_options == ["--prefix=/opt"]
