#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for `dparse.parser`

MIT License

Copyright (c) 2017, Jannis Gebauer

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


from packaging.specifiers import SpecifierSet


def test_requirements_with_invalid_requirement():

    content = "in=vali===d{}{}{"
    dep_file = parse(content)
    assert len(dep_file.dependencies) == 0


def test_index_server():
    line = "--index-url https://some.foo/"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "-i https://some.foo/"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--extra-index-url https://some.foo/"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--extra-index-url https://some.foo"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--extra-index-url https://some.foo # some lousy comment"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "-i\t\t https://some.foo \t\t    # some lousy comment"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--index-url"
    assert Parser.parse_index_server(line) is None

    line = "--index-url=https://some.foo/"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "-i=https://some.foo/"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--extra-index-url=https://some.foo/"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--extra-index-url=https://some.foo"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "--extra-index-url=https://some.foo # some lousy comment"
    assert Parser.parse_index_server(line) == "https://some.foo/"

    line = "-i\t\t =https://some.foo \t\t    # some lousy comment"
    assert Parser.parse_index_server(line) == "https://some.foo/"


def test_requirements_package_with_index_server():
    content = """-i https://some.foo/\ndjango"""

    dep_file = parse(content=content)
    dep = dep_file.dependencies[0]

    assert dep.name == "django"
    assert dep.index_server == "https://some.foo/"


def test_requirements_parse_empty_line():
    content = """
    """

    dep_file = parse(content=content)
    assert dep_file.dependencies == []
    assert dep_file.resolved_files == []


def test_requirements_parse_unsupported_line_start():
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

    dep_file = parse(content=content)
    assert dep_file.dependencies == []
    assert dep_file.resolved_files == []


def test_file_resolver():
    content = "-r production/requirements.txt\n" \
              "--requirement test.txt\n"

    dep_file = parse(content=content, path="/")

    assert dep_file.resolved_files == [
        "/production/requirements.txt",
        "/test.txt"
    ]

    dep_file = parse(content=content)

    assert dep_file.resolved_files == []
