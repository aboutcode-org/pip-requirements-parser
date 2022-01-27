#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for `dparse.parser`"""

# Originally from:
#     name="dparse",
#     description="A parser for Python dependency files",
#     author="Jannis Gebauer",
#     author_email="support@pyup.io",
#     url="https://github.com/pyupio/dparse",
#
# MIT License
#
# Copyright (c) 2017, Jannis Gebauer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from pip_requirements_parser_tests.unit.test_req_file import parse_requirement_text


def test_requirements_with_invalid_requirement(parse_requirement_text):
    content = "in=vali===d{}{}{"
    rf = parse_requirement_text(content)
    assert rf.invalid_lines[0].requirement_line.line == content


def test_index_urls_1(parse_requirement_text):
    line = "--index-url https://some.foo/"
    assert parse_requirement_text(line).options[0].options == {"index_url": "https://some.foo/"}


def test_index_urls_2(parse_requirement_text):
    line = "-i https://some.foo/"
    assert parse_requirement_text(line).options[0].options == {"index_url": "https://some.foo/"}


def test_index_urls_3(parse_requirement_text):
    line = "--extra-index-url https://some.foo/"
    assert parse_requirement_text(line).options[0].options == {"extra_index_urls": ["https://some.foo/"]}


def test_index_urls_4(parse_requirement_text):
    line = "--extra-index-url https://some.foo"
    assert parse_requirement_text(line).options[0].options == {"extra_index_urls": ["https://some.foo"]}


def test_index_urls_5(parse_requirement_text):
    line = "--extra-index-url https://some.foo # some lousy comment"
    assert parse_requirement_text(line).options[0].options == {"extra_index_urls": ["https://some.foo"]}
    assert parse_requirement_text(line).comments[0].line == "# some lousy comment"


def test_index_urls_6(parse_requirement_text):
    line = "-i\t\t https://some.foo \t\t    # some lousy comment"
    assert parse_requirement_text(line).options[0].options == {"index_url": "https://some.foo"}
    assert parse_requirement_text(line).comments[0].line == "# some lousy comment"


def test_index_urls_7(parse_requirement_text):
    line = "--index-url"
    assert parse_requirement_text(line).options == []
    rfi = parse_requirement_text(line).invalid_lines
    assert rfi
    assert "--index-url option" in rfi[0].error_message


def test_index_urls_8(parse_requirement_text):
    line = "--index-url=https://some.foo/"
    assert parse_requirement_text(line).options[0].options == {"index_url": "https://some.foo/"}


def test_index_urls_9(parse_requirement_text):
    line = "-i=https://some.foo/"
    assert parse_requirement_text(line).options[0].options == {"index_url": "https://some.foo/"}


def test_index_urls_10(parse_requirement_text):
    line = "--extra-index-url=https://some.foo/"
    assert parse_requirement_text(line).options[0].options == {"extra_index_urls": ["https://some.foo/"]}


def test_index_urls_11(parse_requirement_text):
    line = "--extra-index-url=https://some.foo"
    assert parse_requirement_text(line).options[0].options == {"extra_index_urls": ["https://some.foo"]}


def test_index_urls_12(parse_requirement_text):
    line = "--extra-index-url=https://some.foo # some lousy comment"
    assert parse_requirement_text(line).options[0].options == {"extra_index_urls": ["https://some.foo"]}
    assert parse_requirement_text(line).comments[0].line == "# some lousy comment"


def test_index_urls_13(parse_requirement_text):
    line = "-i\t\t =https://some.foo \t\t    # some lousy comment"
    assert parse_requirement_text(line).options[0].options == {"index_url": "https://some.foo"}
    assert parse_requirement_text(line).comments[0].line == "# some lousy comment"


def test_requirements_package_with_index_server(parse_requirement_text):
    content = """-i https://some.foo/\ndjango"""
    dep_file = parse_requirement_text(content)
    assert dep_file.options[0].options == {"index_url": "https://some.foo/"}

    dep = dep_file.requirements[0]
    assert dep.name == "django"


def test_requirements_parse_empty_line(parse_requirement_text):
    content = """
    """
    dep_file = parse_requirement_text(content)
    assert dep_file.requirements == []
    assert dep_file.comments == []
    assert dep_file.invalid_lines == []
    assert dep_file.options == []


def test_requirements_parse_unsupported_line_start(parse_requirement_text):
    content = "-f foo\n" \
              "--find-links bla\n" \
              "-i bla\n" \
              "--index-url bla\n" \
              "--extra-index-url bla\n" \
              "--no-index bla\n" \
              "--allow-external\n" \
              "--allow-unverified\n" \
              "-Z\n" \
              "--always-unzip\n"

    dep_file = parse_requirement_text(content)
    assert dep_file.requirements == []
    assert [o.options for o in dep_file.options] == [
        {"find_links": ["foo"]},
        {"find_links": ["bla"]},
        {"index_url": "bla"},
        {"index_url": "bla"},
        {"extra_index_urls": ["bla"]},
        {"no_index": True},
        {"always_unzip": True},
        {"always_unzip": True},
    ]

    # these are legacy or invalid pip options
    expected = [
        '--no-index bla',
        '--allow-external',
        '--allow-unverified',
        '-Z', '--always-unzip',
    ]
    assert [iv.requirement_line.line for iv in dep_file.invalid_lines] == expected


def test_file_resolver(parse_requirement_text):
    content = (
        "-r production/requirements.txt\n"
        "--requirement test.txt\n"
    )
    dep_file = parse_requirement_text(content)
    opts = [o.options for o in dep_file.options]
    assert opts == [
        {"requirements": ["production/requirements.txt"]},
        {"requirements": ["test.txt"]},
    ]
