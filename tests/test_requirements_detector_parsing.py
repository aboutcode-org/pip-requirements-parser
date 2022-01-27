
# Originally from:
#     name="requirements-detector",
#     url="https://github.com/landscapeio/requirements-detector",
#     author="landscape.io",
#     author_email="code@landscape.io",

# SPDX-License-Identifier: MIT
#
# The MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import tempfile
from unittest import TestCase

from pip_requirements_parser import RequirementsFile

from pip_requirements_parser_tests.lib.path import Path
from pip_requirements_parser_tests.lib import requirements_file
from pip_requirements_parser_tests.unit.misc import rmtree


class TestRequirementParsing(TestCase):

    def setUp(self) -> None:
        self.tmpdir = Path(str(tempfile.mkdtemp()))

    def tearDown(self) -> None:
        rmtree(self.tmpdir)

    def _check_req(
        self,
        requirement,
        name=None,
        version_specs=None,
        url=None,
        comment=None
    ):
        """
        Parse ``requirement`` as a RequirementsFile and check the provided
        arguments against the parserd results.
        """
        with requirements_file(contents=requirement, tmpdir=self.tmpdir) as rf:
            reqf = RequirementsFile.from_file(rf)
            assert len(reqf.requirements) == 1
            assert not reqf.invalid_lines
            assert not reqf.options

            req = reqf.requirements[0]
            assert req.name == name

            if not version_specs:
                assert not req.specifier
            else:
                expected = sorted((vers, op) for op, vers in version_specs)
                result = sorted((spec.version, spec.operator) for spec in req.specifier)
                assert result == expected

            if url:
                assert req.link.url
            else:
                assert not req.link

            if comment:
                assert len(reqf.comments) == 1
                assert reqf.comments[0].line == comment

    def test_basic_requirement(self):
        self._check_req(requirement="Django", name="Django")
        self._check_req(requirement="celery", name="celery")

    def test_requirement_with_versions(self):
        self._check_req(
            requirement="Django==1.5.2",
            name="Django",
            version_specs=[("==", "1.5.2")],
        )

    def test_requirement_with_versions2(self):
        self._check_req(
            requirement="South>0.8",
            name="South",
            version_specs=[(">", "0.8")],
        )

    def test_requirement_with_versions3(self):
        self._check_req(
            requirement="django-gubbins!=1.1.1,>1.1",
            name="django-gubbins",
            version_specs=[("!=", "1.1.1"), (">", "1.1")],
        )

    def test_relative_file_path(self):
        self._check_req(requirement="../somelib", url="../somelib")

    def test_vcs_url(self):
        self._check_req(
            requirement="git+ssh://git@github.com/something/somelib.git",
            url="git+ssh://git@github.com/something/somelib.git",
        )

    def test_vcs_url1(self):
        self._check_req(
            requirement="git+ssh://git@github.com/something/somelib.git#egg=somelib",
            name="somelib",
            url="git+ssh://git@github.com/something/somelib.git",
        )

    def test_vcs_url2(self):
        self._check_req(
            requirement="git://github.com/peeb/django-mollie-ideal.git#egg=mollie",
            name="mollie",
            url="git+git://github.com/peeb/django-mollie-ideal.git",
        )

    def test_archive_url(self):
        self._check_req(
            requirement="http://example.com/somelib.tar.gz",
            url="http://example.com/somelib.tar.gz",
        )

        self._check_req(
            requirement="http://example.com/somelib.tar.gz#egg=somelib",
            name="somelib",
            url="http://example.com/somelib.tar.gz",
        )

    def test_editable_relative_path(self):
        self._check_req(
            requirement="-e ../somelib",
            url="../somelib",
        )

    def test_editable_vcs_url(self):
        self._check_req(
            requirement="--editable git+ssh://git@github.com/something/somelib.git#egg=somelib",
            name="somelib",
            url="git+ssh://git@github.com/something/somelib.git",
        )

    def test_comments1(self):
        self._check_req(
            requirement="celery == 0.1 # comment",
            name="celery",
            version_specs=[("==", "0.1")],
            comment="# comment",
        )

    def test_comments2(self):
        self._check_req(
            requirement="celery == 0.1\t# comment",
            name="celery",
            version_specs=[("==", "0.1")],
            comment="# comment",
        )

    def test_comments3(self):
        self._check_req(
            requirement="somelib == 0.15 # pinned to 0.15 (https://github.com/owner/repo/issues/111)",
            name="somelib",
            version_specs=[("==", "0.15")],
            comment="# pinned to 0.15 (https://github.com/owner/repo/issues/111)",
        )

    def test_comments4(self):
        self._check_req(
            requirement="http://example.com/somelib.tar.gz # comment",
            url="http://example.com/somelib.tar.gz",
            comment="# comment",
        )

    def test_comments5(self):
        self._check_req(
            requirement="http://example.com/somelib.tar.gz#egg=somelib # url comment http://foo.com/bar",
            name="somelib",
            url="http://example.com/somelib.tar.gz",
            comment="# url comment http://foo.com/bar",
        )
