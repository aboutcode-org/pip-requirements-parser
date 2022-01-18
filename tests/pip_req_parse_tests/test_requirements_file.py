
# Copyright (c) nexB Inc.
# SPDX-License-Identifier: MIT

import json

import pytest

import pip_requirements

from pip_req_parse_tests.lib import ALL_REQFILES

"""
Parse many requirements files and verify the expected JSON output
"""


@pytest.mark.parametrize("test_file", ALL_REQFILES)
def test_parse_requirement_file(
    test_file: str,
    regen=False,
) -> None:

    expected_file = test_file + "-expected.json"
    results = pip_requirements.RequirementsFile(test_file).to_dict()
    if regen:
        with open (expected_file, 'w') as outp:
            json.dump(results, outp, indent=2)
        expected = results
    else:
        with open (expected_file) as inp:
            expected = json.load(inp)

    assert results == expected
