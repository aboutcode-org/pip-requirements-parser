
# Originally from:
#     author="Dustin Ingram",
#     author_email="di@python.org",
#     description="An unofficial, importable pip API",
#     url="http://github.com/di/pip-api",
# 
# Copyright (c) Dustin Ingram <di@python.org> and others
# 
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
# This is a modified subst of the tests from https://github.com/di/pip-api/
# adapted to work with our pip requirement parser.

from typing import NamedTuple

import pytest
from pip_requirements_parser import RequirementsFile
from pip_requirements_parser import InvalidRequirementLine
from pip_requirements_parser import RequirementLine
from pathlib import Path

@pytest.fixture
def create_requirement_files(
    monkeypatch: pytest.MonkeyPatch,  # NOQA
    tmpdir,
):
    """
    Return a callable to process some mapping of {filename: [list of lines]
    as if it were requirements file, writing the content to temp files.
    Return a mapping of {filename: actual file path}
    """
    def create_files(file_data):
        created = {}
        for filename, lines in file_data.items():
            path = tmpdir.joinpath(filename)
            path.parent.mkdir(exist_ok=True)
            path.write_text("".join(lines))
            created[filename] = path
        monkeypatch.chdir(str(tmpdir))
        return created

    return create_files


def test_parse_requirements(create_requirement_files):
    files = {"a.txt": ["foo==1.2.3\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert set(r.name for r in result.requirements) == {"foo"}
    assert str(result.requirements[0].req) == "foo==1.2.3"


def test_parse_requirements_with_comments(create_requirement_files):
    files = {"a.txt": ["# a comment\n", "foo==1.2.3 # this is a comment\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert set(r.name for r in result.requirements) == {"foo"}
    assert str(result.requirements[0].req) == "foo==1.2.3"
    assert [(c.line_number, c.line) for c in result.comments] == [
        (1, '# a comment'), (2, '# this is a comment')
    ] 

@pytest.mark.parametrize(
    "flag", ["-i", "--index-url", "--extra-index-url", "-f", "--find-links"]
)
def test_parse_requirements_with_index_url(create_requirement_files, flag):
    files = {
        "a.txt": ["{} https://example.com/pypi/simple\n".format(flag), "foo==1.2.3\n"]
    }
    paths_by_name = create_requirement_files(files)
    result = RequirementsFile.from_file(paths_by_name["a.txt"])

    assert set(r.name for r in result.requirements) == {"foo"}
    assert str(result.requirements[0].req) == "foo==1.2.3"
    assert len(result.options) == 1
    assert list(result.options[0].options.values()) in (
        ['https://example.com/pypi/simple'],
        [['https://example.com/pypi/simple']],
    )


class Pep508Test(NamedTuple):
    identifier: int
    line: str
    req_name: str
    req_url: str
    link_url: str
    req_string: str
    req_spec: str
    invalid_lines_len: int = 0


@pytest.mark.parametrize(
    "test_508",
    [
        Pep508Test(
            identifier=1,
            line="pip @ https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4\n",
            req_name="pip",
            req_url="https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            link_url="https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            # Note extra space after @
            req_string="pip@ https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            req_spec="",
        ),
        Pep508Test(
            identifier=2,
            line="pip@https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4\n",
            req_name="pip",
            req_url="https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            link_url="https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            # Note extra space after @
            req_string="pip@ https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            req_spec="",
        ),
        Pep508Test(
            identifier=3,
            # Version and URL can't be combined so this all gets parsed as a legacy version
            line="pip==1.3.1@https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4\n",
            req_name="pip",
            req_url=None,
            link_url=None,
            # Note no extra space after @
            req_string="pip==1.3.1@https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            req_spec="==1.3.1@https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4",
            invalid_lines_len = 1,
        ),
        Pep508Test(
            identifier=4,
            line="git+ssh://git@github.com/pypa/pip.git@da9234ee9982d4#egg=pip",
            req_name="pip",
            req_url=None,
            link_url="git+ssh://git@github.com/pypa/pip.git@da9234ee9982d4#egg=pip",
            req_string="pip",
            req_spec="",
        ),
        Pep508Test(
            identifier=5,
            line="ssh://git@github.com/pypa/pip.git@da9234ee9982d4#egg=pip",
            req_name="pip",
            req_url=None,
            link_url="ssh://git@github.com/pypa/pip.git@da9234ee9982d4#egg=pip",
            req_string="pip",
            req_spec="",
        ),
        Pep508Test(
            identifier=6,
            line="https://github.com/pypa/pip/archive/pip-1.3.1-py2.py3-none-any.whl",
            req_name="pip",
            req_url=None,
            link_url="https://github.com/pypa/pip/archive/pip-1.3.1-py2.py3-none-any.whl",
            req_string="pip==1.3.1",
            req_spec="==1.3.1",
        ),
        Pep508Test(
            identifier=7,
            line="file://tmp/pip-1.3.1.zip#egg=pip",
            req_name="pip",
            req_url=None,
            link_url="file://tmp/pip-1.3.1.zip#egg=pip",
            req_string="pip",
            req_spec="",
        ),
        Pep508Test(
            identifier=8,
            line="file://tmp/pip-1.3.1-py2.py3-none-any.whl",
            req_name="pip",
            req_url=None,
            link_url="file://tmp/pip-1.3.1-py2.py3-none-any.whl",
            req_string="pip==1.3.1",
            req_spec="==1.3.1"
        ),
    ],
)
def test_parse_requirements_PEP508(create_requirement_files, test_508):
    files = {"a.txt": [test_508.line]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert len(result.invalid_lines) == test_508.invalid_lines_len
    if test_508.invalid_lines_len:
        return
    assert len(result.requirements) == 1
    ireq = result.requirements[0]
    assert str(ireq.name) == test_508.req_name
    assert str(ireq.req.specifier) == test_508.req_spec
    assert str(ireq.req) == test_508.req_string
    assert ireq.req.url == test_508.req_url
    if ireq.link or test_508.link_url:
        assert ireq.link.url == test_508.link_url


def test_parse_requirements_vcs(create_requirement_files):
    requirement_text = "git+https://github.com/bar/foo"
    files = {"a.txt": [requirement_text + "\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert len(result.requirements) == 1
    assert result.requirements[0].req is None
    assert result.requirements[0].link.url == requirement_text
    assert result.invalid_lines == []


def test_include_invalid_requirement(create_requirement_files):
    requirement_text = "git+https://github.com/bar/foo"
    files = {"a.txt": [requirement_text + "\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert len(result.requirements) == 1
    # we do not validate for "Missing egg fragment in URL: {requirement_text}"
    assert result.requirements[0].req is None
    assert result.requirements[0].link.url == requirement_text
    assert result.invalid_lines == []


@pytest.mark.parametrize("flag", ["-r", "--requirements"])
def test_parse_requirements_recursive(create_requirement_files, flag):
    # https://github.com/di/pip-api/commit/7e2f1e8693da249156b99ec593af1e61192c611a#r64188234
    # --requirements is not a valid pip option
    files = {"a.txt": ["{} b.txt\n".format(flag)], "b.txt": ["foo==1.2.3\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"], include_nested=True)
    assert len(result.requirements) == 1
    assert str(result.requirements[0].req) == "foo==1.2.3"
    assert result.options[0].options == {"requirements": ["b.txt"]}


def test_parse_requirements_double_raises(create_requirement_files):
    # we accept duplicated requirements
    # "Double requirement given: foo==3.2.1 (already in foo==1.2.3, name='foo')",
    files = {"a.txt": ["foo==1.2.3\n", "foo==3.2.1\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert len(result.requirements) == 2
    assert str(result.requirements[0].req) == "foo==1.2.3"
    assert str(result.requirements[1].req) == "foo==3.2.1"


def test_parse_requirements_multiline1(create_requirement_files):
    # we do not accept unknown options
    files = {
        "a.txt": ["foo==1.2.3 \\\n", "    --whatever=blahblah\n"], 
    }
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"], include_nested=True)
    assert result.requirements == []
    assert "no such option: --whatever" in result.invalid_lines[0].error_message

def test_parse_requirements_multiline2(create_requirement_files):
    files = {
        "b.txt": ["foo==1.2.3\n"],
    }
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["b.txt"], include_nested=True)
    assert len(result.requirements) == 1

    assert str(result.requirements[0].req) == "foo==1.2.3"
    assert result.invalid_lines == []
    assert set(r.name for r in result.requirements) == {"foo"}


def test_parse_requirements_multiline3(create_requirement_files):
    files = {"a.txt": ["-r \\\n", "    b.txt\n"], "b.txt": ["foo==1.2.3\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"], include_nested=True)
    assert len(result.requirements) == 1
    assert str(result.requirements[0].req) == "foo==1.2.3"

    assert result.invalid_lines == []
    assert set(r.name for r in result.requirements) == {"foo"}


def test_parse_requirements_editable(create_requirement_files):
    files = {
        "a.txt": ["Django==1.11\n" "-e git+https://github.com/foo/deal.git#egg=deal\n"]
    }
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])

    assert set(r.name for r in result.requirements) == {"deal", "Django"}
    assert str(result.requirements[0].req) == "Django==1.11"

    assert str(result.requirements[1].req) == "deal"
    assert result.requirements[1].link.url == "git+https://github.com/foo/deal.git#egg=deal"
    assert result.requirements[1].is_editable


def test_parse_requirements_editable_file(create_requirement_files):
    files = {"a.txt": ["Django==1.11\n" "-e .\n"]}
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])

    assert set(r.name for r in result.requirements) == {None, "Django"}
    
    assert str(result.requirements[0].req) == "Django==1.11"
    # we actually do not load/build the thing behind the "dot"
    assert result.requirements[1].req is None
    assert result.requirements[1].link.url == "."
    assert result.requirements[1].is_editable


def test_parse_requirements_with_relative_references(create_requirement_files):
    files = {
        "reqs/base.txt": ["django==1.11\n"],
        "reqs/test.txt": ["-r base.txt\n"],
        "reqs/dev.txt": ["-r base.txt\n" "-r test.txt\n"],
    }
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["reqs/dev.txt"], include_nested=True)
    assert set(r.name for r in result.requirements) == {"django"}


def test_parse_requirements_with_environment_marker(create_requirement_files):
    files = {
        "a.txt": [
            "foo==1.2.3 ; python_version <= '2.7'\n",
            "foo==3.2.1 ; python_version > '2.7'\n",
        ]
    }
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])

    # We don't support such old Python versions, so if we've managed to run these tests, we should
    # have chosen foo==3.2.1
    assert set(r.name for r in result.requirements) == {"foo"}
    assert str(result.requirements[0].req) == "foo==1.2.3"
    assert str(result.requirements[0].marker) == 'python_version <= "2.7"'
    assert str(result.requirements[1].req) == 'foo==3.2.1'
    assert str(result.requirements[1].marker) == 'python_version > "2.7"'


def test_parse_requirements_with_invalid_wheel_filename(create_requirement_files):
    INVALID_WHEEL_NAME = "pip-1.3.1-invalid-format.whl"
    files = {
        "a.txt": ["https://github.com/pypa/pip/archive/" + INVALID_WHEEL_NAME],
    }
    paths_by_name = create_requirement_files(files)
    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert len(result.invalid_lines) == 1
    irl = result.invalid_lines[0]
    assert irl.error_message == "pip-1.3.1-invalid-format.whl is not a valid wheel filename."


def test_parse_requirements_with_missing_egg_suffix(create_requirement_files):
    # Without a package name, an `#egg=foo` suffix is required to know the package name
    files = {
        "a.txt": ["https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4"],
    }
    paths_by_name = create_requirement_files(files)

    result = RequirementsFile.from_file(paths_by_name["a.txt"])
    assert result.invalid_lines == []
    req = result.requirements[0]
    assert req.req is None
    assert req.link.url == "https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4"
