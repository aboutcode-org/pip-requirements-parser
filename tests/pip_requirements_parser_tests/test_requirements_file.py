
# Copyright (c) nexB Inc.
# SPDX-License-Identifier: MIT

import json

import pytest

import pip_requirements_parser

from pip_requirements_parser_tests.lib import ALL_REQFILES
from pip_requirements_parser_tests.lib import MORE_REQFILES
from pip_requirements_parser_tests.lib import SC_REQFILES

"""
Parse many requirements files and verify the expected JSON output
"""

all_test_requirements_files = ALL_REQFILES + MORE_REQFILES + SC_REQFILES


@pytest.mark.parametrize("test_file", all_test_requirements_files)
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


@pytest.mark.parametrize("test_file", all_test_requirements_files)
def test_RequirementsFile_dumps_unparse(
    test_file: str,
    regen=False,
) -> None:

    dumped = pip_requirements_parser.RequirementsFile.from_file(test_file).dumps(
        preserve_one_empty_line=True,
    )

    expected_file = test_file + "-expected.dumps"

    if regen:
        with open(expected_file, "w") as out:
            out.write(dumped)
        expected = dumped
    else:
        with open(expected_file) as inp:
            expected = inp.read()

    assert dumped == expected
