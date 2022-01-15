
# Copyright (c) 2008-2021 The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import os
import pathlib
import textwrap
from optparse import Values
from typing import Any, Iterator, List, Optional, Tuple
from unittest import mock

import pytest
from packaging.specifiers import SpecifierSet

import pip_requirements  # this will be monkeypatched
from pip_requirements import InstallationError, RequirementsFileParseError
from pip_requirements import PackageFinder
from pip_requirements import FormatControl
from pip_requirements import (
    install_req_from_editable,
    install_req_from_line,
    install_req_from_parsed_requirement,
)
from pip_requirements import (
    break_args_options,
    ignore_comments,
    join_lines,
    parse_requirements,
    preprocess,
)
from pip_requirements import InstallRequirement
from tests.lib import TestData, make_test_finder, requirements_file
from tests.lib.path import Path


Protocol = object


@pytest.fixture
def finder() -> PackageFinder:
    return make_test_finder()
 
 
@pytest.fixture
def options() -> mock.Mock:
    return mock.Mock(
        isolated_mode=False,
        index_url="default_url",
        format_control=FormatControl(set(), set()),
        features_enabled=[],
    )


def parse_reqfile(
    filename: str,
    finder: PackageFinder = None,
    options: Values = None,
    constraint: bool = False,
    isolated: bool = False,
) -> Iterator[InstallRequirement]:
    # Wrap parse_requirements/install_req_from_parsed_requirement to
    # avoid having to write the same chunk of code in lots of tests.
    for parsed_req in parse_requirements(
        filename,
        finder=finder,
        options=options,
        constraint=constraint,
    ):
        yield install_req_from_parsed_requirement(parsed_req, isolated=isolated)


def test_read_file_url(tmp_path: pathlib.Path) -> None:
    reqs = tmp_path.joinpath("requirements.txt")
    reqs.write_text("foo")
    result = list(parse_requirements(reqs.as_posix()))

    assert len(result) == 1, result
    assert result[0].requirement == "foo"

    # The comes_from value has three parts: -r or -c flag, path, and line.
    # The path value in the middle needs some special logic due to our path
    # normalization logic.
    assert result[0].comes_from[:3] == "-r "
    assert result[0].comes_from[-9:] == " (line 1)"
    assert os.path.samefile(result[0].comes_from[3:-9], str(reqs))


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
        assert list(result) == [(1, "req1"), (3, "req2")]

    def test_comments_and_joins_case2(self) -> None:
        content = textwrap.dedent(
            """\
          req1\\
          # comment
        """
        )
        result = preprocess(content)
        assert list(result) == [(1, "req1")]

    def test_comments_and_joins_case3(self) -> None:
        content = textwrap.dedent(
            """\
          req1 \\
          # comment
          req2
        """
        )
        result = preprocess(content)
        assert list(result) == [(1, "req1"), (3, "req2")]


class TestIgnoreComments:
    """tests for `ignore_comment`"""

    def test_ignore_line(self) -> None:
        lines = [(1, ""), (2, "req1"), (3, "req2")]
        result = ignore_comments(lines)
        assert list(result) == [(2, "req1"), (3, "req2")]

    def test_ignore_comment(self) -> None:
        lines = [(1, "req1"), (2, "# comment"), (3, "req2")]
        result = ignore_comments(lines)
        assert list(result) == [(1, "req1"), (3, "req2")]

    def test_strip_comment(self) -> None:
        lines = [(1, "req1"), (2, "req # comment"), (3, "req2")]
        result = ignore_comments(lines)
        assert list(result) == [(1, "req1"), (2, "req"), (3, "req2")]


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


class LineProcessor(Protocol):
    def __call__(
        self,
        line: str,
        filename: str,
        line_number: int,
        finder: Optional[PackageFinder] = None,
        options: Optional[Values] = None,
        constraint: bool = False,
    ) -> List[InstallRequirement]:
        ...


@pytest.fixture
def line_processor(monkeypatch: pytest.MonkeyPatch, tmpdir: Path) -> LineProcessor:
    def process_line(
        line: str,
        filename: str,
        line_number: int,
        finder: Optional[PackageFinder] = None,
        options: Optional[Values] = None,
        constraint: bool = False,
    ) -> List[InstallRequirement]:

        prefix = "\n" * (line_number - 1)
        path = tmpdir.joinpath(filename)
        path.parent.mkdir(exist_ok=True)
        path.write_text(prefix + line)
        monkeypatch.chdir(str(tmpdir))
        return list(
            parse_reqfile(
                filename,
                finder=finder,
                options=options,
                constraint=constraint,
                isolated=options.isolated_mode if options else False,
            )
        )

    return process_line


class TestProcessLine:
    """tests for `process_line`"""

    def test_parser_error(self, line_processor: LineProcessor) -> None:
        with pytest.raises(RequirementsFileParseError):
            line_processor("--bogus", "file", 1)

    def test_parser_offending_line(self, line_processor: LineProcessor) -> None:
        line = "pkg==1.0.0 --hash=somehash"
        with pytest.raises(RequirementsFileParseError) as err:
            line_processor(line, "file", 1)
        assert line in str(err.value)

    def test_parser_non_offending_line(self, line_processor: LineProcessor) -> None:
        try:
            line_processor("pkg==1.0.0 --hash=sha256:somehash", "file", 1)
        except RequirementsFileParseError:
            pytest.fail("Reported offending line where it should not.")

    def test_only_one_req_per_line(self, line_processor: LineProcessor) -> None:
        # pkg_resources raises the ValueError
        with pytest.raises(InstallationError):
            line_processor("req1 req2", "file", 1)

    def test_error_message(self, line_processor: LineProcessor) -> None:
        """
        Test the error message if a parsing error occurs (all of path,
        line number, and hint).
        """
        with pytest.raises(InstallationError) as exc:
            line_processor(
                "my-package=1.0", filename="path/requirements.txt", line_number=3
            )

        expected = (
            "Invalid requirement: 'my-package=1.0' "
            "(from line 3 of path/requirements.txt)\n"
            "Hint: = is not a valid operator. Did you mean == ?"
        )
        assert str(exc.value) == expected

    def test_yield_line_requirement(self, line_processor: LineProcessor) -> None:
        line = "SomeProject"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_line(line, comes_from=comes_from)
        assert repr(line_processor(line, filename, 1)[0]) == repr(req)

    def test_yield_pep440_line_requirement(self, line_processor: LineProcessor) -> None:
        line = "SomeProject @ https://url/SomeProject-py2-py3-none-any.whl"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_line(line, comes_from=comes_from)
        assert repr(line_processor(line, filename, 1)[0]) == repr(req)

    def test_yield_line_constraint(self, line_processor: LineProcessor) -> None:
        line = "SomeProject"
        filename = "filename"
        comes_from = "-c {} (line {})".format(filename, 1)
        req = install_req_from_line(line, comes_from=comes_from, constraint=True)
        found_req = line_processor(line, filename, 1, constraint=True)[0]
        assert repr(found_req) == repr(req)
        assert found_req.constraint is True

    def test_yield_line_requirement_with_spaces_in_specifier(
        self, line_processor: LineProcessor
    ) -> None:
        line = "SomeProject >= 2"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_line(line, comes_from=comes_from)
        assert repr(line_processor(line, filename, 1)[0]) == repr(req)
        assert req.req is not None
        assert str(req.req.specifier) == ">=2"

    def test_yield_editable_requirement(self, line_processor: LineProcessor) -> None:
        url = "git+https://url#egg=SomeProject"
        line = f"-e {url}"
        filename = "filename"
        comes_from = f"-r {filename} (line 1)"
        req = install_req_from_editable(url, comes_from=comes_from)
        assert repr(line_processor(line, filename, 1)[0]) == repr(req)

    def test_yield_editable_constraint(self, line_processor: LineProcessor) -> None:
        url = "git+https://url#egg=SomeProject"
        line = f"-e {url}"
        filename = "filename"
        comes_from = "-c {} (line {})".format(filename, 1)
        req = install_req_from_editable(url, comes_from=comes_from, constraint=True)
        found_req = line_processor(line, filename, 1, constraint=True)[0]
        assert repr(found_req) == repr(req)
        assert found_req.constraint is True

    def test_nested_constraints_file(
        self, monkeypatch: pytest.MonkeyPatch, tmpdir: Path
    ) -> None:
        req_name = "hello"
        req_file = tmpdir / "parent" / "req_file.txt"
        req_file.parent.mkdir()
        req_file.write_text("-c reqs.txt")
        req_file.parent.joinpath("reqs.txt").write_text(req_name)

        monkeypatch.chdir(str(tmpdir))

        reqs = list(parse_reqfile("./parent/req_file.txt"))
        assert len(reqs) == 1
        assert reqs[0].name == req_name
        assert reqs[0].constraint

    def test_options_on_a_requirement_line(self, line_processor: LineProcessor) -> None:
        line = (
            "SomeProject --install-option=yo1 --install-option yo2 "
            '--global-option="yo3" --global-option "yo4"'
        )
        filename = "filename"
        req = line_processor(line, filename, 1)[0]
        assert req.global_options == ["yo3", "yo4"]
        assert req.install_options == ["yo1", "yo2"]

    def test_hash_options(self, line_processor: LineProcessor) -> None:
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
        req = line_processor(line, filename, 1)[0]
        assert req.hash_options == {
            "sha256": [
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
            ],
            "sha384": [
                "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcd"
                "b9c666fa90125a3c79f90397bdf5f6a13de828684f"
            ],
        }

    def test_set_isolated(
        self, line_processor: LineProcessor, options: mock.Mock
    ) -> None:
        line = "SomeProject"
        filename = "filename"
        options.isolated_mode = True
        result = line_processor(line, filename, 1, options=options)
        assert result[0].isolated

    def test_set_finder_no_index(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--no-index", "file", 1, finder=finder)
        assert finder.index_urls == []

    def test_set_finder_index_url(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--index-url=url", "file", 1, finder=finder)
        assert finder.index_urls == ["url"]

    def test_set_finder_find_links(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--find-links=url", "file", 1, finder=finder)
        assert finder.find_links == ["url"]

    def test_set_finder_extra_index_urls(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor(
            "--extra-index-url=url", "file", 1, finder=finder
        )
        assert finder.index_urls == ["url"]

    def test_set_finder_allow_all_prereleases(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--pre", "file", 1, finder=finder)
        assert finder.allow_all_prereleases

    def test_use_feature(
        self, line_processor: LineProcessor, options: mock.Mock
    ) -> None:
        """--use-feature can be set in requirements files."""
        line_processor("--use-feature=2020-resolver", "filename", 1, options=options)
        assert "2020-resolver" in options.features_enabled

    def test_relative_local_find_links(
        self,
        line_processor: LineProcessor,
        finder: PackageFinder,
        monkeypatch: pytest.MonkeyPatch,
        tmpdir: Path,
    ) -> None:
        """
        Test a relative find_links path is joined with the req file directory
        """
        base_path = tmpdir / "path"

        def normalize(path: Path) -> str:
            return os.path.normcase(os.path.abspath(os.path.normpath(str(path))))

        # Make sure the test also passes on windows
        req_file = normalize(base_path / "req_file.txt")
        nested_link = normalize(base_path / "rel_path")
        exists_ = os.path.exists

        def exists(path: str) -> bool:
            if path == nested_link:
                return True
            else:
                return exists_(path)

        monkeypatch.setattr(os.path, "exists", exists)
        line_processor("--find-links=rel_path", req_file, 1, finder=finder)
        assert finder.find_links == [nested_link]

    def test_relative_http_nested_req_files(
        self,
        finder: PackageFinder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        Test a relative nested req file path is joined with the req file url
        """
        req_name = "hello"
        req_file = "http://me.com/me/req_file.txt"

        def get_file_content(
            filename: str, *args: Any, **kwargs: Any
        ) -> Tuple[None, str]:
            if filename == req_file:
                return None, "-r reqs.txt"
            elif filename == "http://me.com/me/reqs.txt":
                return None, req_name
            assert False, f"Unexpected file requested {filename}"

        monkeypatch.setattr(
            pip_requirements, "get_file_content", get_file_content
        )

        result = list(parse_reqfile(req_file, ))
        assert len(result) == 1
        assert result[0].name == req_name
        assert not result[0].constraint

    def test_relative_local_nested_req_files(
        self, monkeypatch: pytest.MonkeyPatch, tmpdir: Path
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

        reqs = list(parse_reqfile("./parent/req_file.txt")) # session=session))
        assert len(reqs) == 1
        assert reqs[0].name == req_name
        assert not reqs[0].constraint

    def test_absolute_local_nested_req_files(
        self, tmpdir: Path
    ) -> None:
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

        reqs = list(parse_reqfile(str(req_file)))
        assert len(reqs) == 1
        assert reqs[0].name == req_name
        assert not reqs[0].constraint

    def test_absolute_http_nested_req_file_in_local(
        self, monkeypatch: pytest.MonkeyPatch, tmpdir: Path
    ) -> None:
        """
        Test a nested req file url in a local req file
        """
        req_name = "hello"
        req_file = tmpdir / "req_file.txt"
        nested_req_file = "http://me.com/me/req_file.txt"

        def get_file_content(
            filename: str, *args: Any, **kwargs: Any
        ) -> Tuple[None, str]:
            if filename == str(req_file):
                return None, f"-r {nested_req_file}"
            elif filename == nested_req_file:
                return None, req_name
            assert False, f"Unexpected file requested {filename}"

        monkeypatch.setattr(
            pip_requirements, "get_file_content", get_file_content
        )

        result = list(parse_reqfile(req_file))
        assert len(result) == 1
        assert result[0].name == req_name
        assert not result[0].constraint


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

    def test_variant1(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("-i url", "file", 1, finder=finder)
        assert finder.index_urls == ["url"]

    def test_variant2(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("-i 'url'", "file", 1, finder=finder)
        assert finder.index_urls == ["url"]

    def test_variant3(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--index-url=url", "file", 1, finder=finder)
        assert finder.index_urls == ["url"]

    def test_variant4(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--index-url url", "file", 1, finder=finder)
        assert finder.index_urls == ["url"]

    def test_variant5(
        self, line_processor: LineProcessor, finder: PackageFinder
    ) -> None:
        line_processor("--index-url='url'", "file", 1, finder=finder)
        assert finder.index_urls == ["url"]


class TestParseRequirements:
    """tests for `parse_reqfile`"""

    def test_multiple_appending_options(
        self, tmpdir: Path, finder: PackageFinder, options: mock.Mock
    ) -> None:
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("--extra-index-url url1 \n")
            fp.write("--extra-index-url url2 ")

        list(
            parse_reqfile(
                tmpdir.joinpath("req1.txt"),
                finder=finder,
                options=options,
            )
        )

        assert finder.index_urls == ["url1", "url2"]

    def test_expand_missing_env_variables(
        self, tmpdir: Path, finder: PackageFinder
    ) -> None:
        req_url = (
            "https://${NON_EXISTENT_VARIABLE}:$WRONG_FORMAT@"
            "%WINDOWS_FORMAT%github.com/user/repo/archive/master.zip"
        )

        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write(req_url)

        # Construct the session outside the monkey-patch, since it access the
        # env
        with mock.patch("pip_requirements.os.getenv") as getenv:
            getenv.return_value = ""

            reqs = list(
                parse_reqfile(
                    tmpdir.joinpath("req1.txt"), finder=finder
                )
            )

            assert len(reqs) == 1, "parsing requirement file with env variable failed"
            assert reqs[0].link is not None
            assert (
                reqs[0].link.url == req_url
            ), "ignoring invalid env variable in req file failed"

    def test_join_lines(self, tmpdir: Path, finder: PackageFinder) -> None:
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("--extra-index-url url1 \\\n--extra-index-url url2")

        list(
            parse_reqfile(
                tmpdir.joinpath("req1.txt"), finder=finder
            )
        )

        assert finder.index_urls == ["url1", "url2"]

    def test_req_file_parse_no_only_binary(
        self, data: TestData, finder: PackageFinder
    ) -> None:
        list(
            parse_reqfile(
                data.reqfiles.joinpath("supported_options2.txt"),
                finder=finder,
            )
        )
        expected = FormatControl({"fred"}, {"wilma"})
        assert finder.format_control == expected

    def test_req_file_parse_comment_start_of_line(
        self, tmpdir: Path, finder: PackageFinder
    ) -> None:
        """
        Test parsing comments in a requirements file
        """
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("# Comment ")

        reqs = list(
            parse_reqfile(
                tmpdir.joinpath("req1.txt"), finder=finder
            )
        )

        assert not reqs

    def test_req_file_parse_comment_end_of_line_with_url(
        self, tmpdir: Path, finder: PackageFinder
    ) -> None:
        """
        Test parsing comments in a requirements file
        """
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("https://example.com/foo.tar.gz # Comment ")

        reqs = list(
            parse_reqfile(
                tmpdir.joinpath("req1.txt"), finder=finder
            )
        )

        assert len(reqs) == 1
        assert reqs[0].link is not None
        assert reqs[0].link.url == "https://example.com/foo.tar.gz"

    def test_req_file_parse_egginfo_end_of_line_with_url(
        self, tmpdir: Path, finder: PackageFinder
    ) -> None:
        """
        Test parsing comments in a requirements file
        """
        with open(tmpdir.joinpath("req1.txt"), "w") as fp:
            fp.write("https://example.com/foo.tar.gz#egg=wat")

        reqs = list(
            parse_reqfile(
                tmpdir.joinpath("req1.txt"), finder=finder
            )
        )

        assert len(reqs) == 1
        assert reqs[0].name == "wat"

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

        parse_reqfile(tmpdir.joinpath("req.txt"))

    def test_install_requirements_with_options(
        self,
        tmpdir: Path,
        finder: PackageFinder,
        options: mock.Mock,
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
            req = list(
                parse_reqfile(
                    reqs_file.resolve(), finder=finder, options=options
                )
            )

        assert len(req) == 1
        assert req[0].name == "INITools"
        assert req[0].specifier == SpecifierSet('==2.0')
