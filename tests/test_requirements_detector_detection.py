
# Originally from:
#     name="requirements-detector",
#     url="https://github.com/landscapeio/requirements-detector",
#     author="landscape.io",
#     author_email="code@landscape.io",
#
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

import os
from unittest import TestCase

from pip_requirements_parser import RequirementsFile


class DependencyDetectionTest(TestCase):

    def test_requirements_txt_parsing(self):
        filepath = os.path.join(os.path.dirname(__file__), "requirements_detector/test1/requirements.txt")
        dependencies = RequirementsFile.from_file(filepath)
        results = [str(r.req) for r in dependencies.requirements]

        expected = ["Django>=1.5.0", "South==0.8.2", "amqp!=1.0.13", "six<1.4,>=1.3.0"]

        assert results == expected
        assert dependencies.options[0].options == {"index_url": "https://example.com/custom/pypi"}
        assert dependencies.comments[0]. line == "# we want six too"

    def test_requirements_dir_parsing1(self):
        filepath = os.path.join(os.path.dirname(__file__), "requirements_detector/test2/requirements/base.txt")
        dependencies = RequirementsFile.from_file(filepath)
        results = [str(r.req) for r in dependencies.requirements]

        expected = [
            "amqp==1.0.13",
            "anyjson==0.3.3",
        ]

        assert results == expected

    def test_requirements_dir_parsing2(self):
        filepath = os.path.join(os.path.dirname(__file__), "requirements_detector/test2/requirements/webui.pip")
        dependencies = RequirementsFile.from_file(filepath)
        results = [str(r.req) for r in dependencies.requirements]

        expected = [
            "Django==1.5.2",
            "South==0.8.2",
        ]

        assert results == expected

    def test_invalid_requirements_txt(self):
        filepath = os.path.join(os.path.dirname(__file__), "requirements_detector/test5/invalid_requirements.txt")
        dependencies = RequirementsFile.from_file(filepath)
        results = [str(r.req) for r in dependencies.requirements]

        expected = ["django<1.6", "django"]
        assert results == expected
        errors = [i.requirement_line.line for i in dependencies.invalid_lines]
        assert errors == ["<<<<<<< HEAD", "=======", ">>>>>>>"]
