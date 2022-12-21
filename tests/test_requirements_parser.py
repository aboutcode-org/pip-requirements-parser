# encoding: utf-8

# Originally from:
#     name = "requirements-parser"
#     description = "This is a small Python module for parsing Pip requirement files."
#     authors = [
#         "Paul Horton <simplyecommerce@gmail.com>",
#         "David Fischer (@davidfischer)",
#         "Trey Hunner (@treyhunner)",
#         "Dima Veselov (@dveselov)",
#         "Sascha Peilicke (@saschpe)",
#         "Jayson Reis (@jaysonsantos)",
#         "Max Shenfield (@mshenfield)",
#         "Nicolas Delaby (@ticosax)",
#         "Stéphane Bidoul (@sbidoul)"
#     ]
#     maintainers = ["Paul Horton <simplyecommerce@gmail.com>"]
#     homepage = "https://github.com/madpah/requirements-parser"

# This file is part of requirements-parser library.
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
# SPDX-License-Identifier: Apache-2.0

# this has been significantly modified to use our own JSON tests
# instead of the original ones

import json
import os

import pytest

import pip_requirements_parser

REQFILES_DIR = os.path.join(
    os.path.dirname(__file__),
    "requirements_parser_reqfiles",
)

ALL_REQFILES = [
    os.path.join(REQFILES_DIR, rf)
    for rf in os.listdir(REQFILES_DIR)
    if rf.endswith(".txt")
]


@pytest.mark.parametrize("test_file", ALL_REQFILES)
def test_RequirementsFile_to_dict(
    test_file: str,
    regen=False,
) -> None:

    expected_file = test_file + "-expected.json"
    results = pip_requirements_parser.RequirementsFile.from_file(test_file).to_dict()
    if regen:
        with open (expected_file, 'w') as outp:
            json.dump(results, outp, indent=2)
        expected = results
    else:
        with open (expected_file) as inp:
            expected = json.load(inp)

    assert results == expected
