
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

from typing import Iterator

import py.path
import pytest

from pip_requirements_parser_tests.lib import TestData
from pip_requirements_parser_tests.lib.path import Path



@pytest.fixture
def tmpdir(
    request: pytest.FixtureRequest,  # NOQA
    tmpdir: py.path.local,
) -> Iterator[Path]:
    """
    Return a temporary directory path object which is unique to each test
    function invocation, created as a sub directory of the base temporary
    directory. The returned object is a ``tests.lib.path.Path`` object.

    This uses the built-in tmpdir fixture from pytest itself but modified
    to return our typical path object instead of py.path.local as well as
    deleting the temporary directories at the end of each test case.
    """
    assert tmpdir.isdir()
    yield Path(str(tmpdir))
    # Clear out the temporary directory after the test has finished using it.
    # This should prevent us from needing a multiple gigabyte temporary
    # directory while running the tests.
    tmpdir.remove(ignore_errors=True)


@pytest.fixture
def data(tmpdir: Path) -> TestData:
    return TestData.copy(tmpdir.joinpath("data"))
