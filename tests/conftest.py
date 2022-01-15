import compileall
import fnmatch
import io
import os
import re
import shutil
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from typing import TYPE_CHECKING, Callable, Dict, Iterable, Iterator, List, Optional
from unittest.mock import patch

import py.path
import pytest

# Config will be available from the public API in pytest >= 7.0.0:
# https://github.com/pytest-dev/pytest/commit/88d84a57916b592b070f4201dc84f0286d1f9fef
from _pytest.config import Config

# Parser will be available from the public API in pytest >= 7.0.0:
# https://github.com/pytest-dev/pytest/commit/538b5c24999e9ebb4fab43faabc8bcc28737bcdf
from setuptools.wheel import Wheel

from tests.lib import DATA_DIR, SRC_DIR, PipTestEnvironment, TestData
from tests.lib.path import Path


def pytest_collection_modifyitems(config: Config, items: List[pytest.Item]) -> None:
    for item in items:
        if not hasattr(item, "module"):  # e.g.: DoctestTextfile
            continue

        if item.get_closest_marker("search") and not config.getoption("--run-search"):
            item.add_marker(pytest.mark.skip("pip search test skipped"))

        if "CI" in os.environ:
            # Mark network tests as flaky
            if item.get_closest_marker("network") is not None:
                item.add_marker(pytest.mark.flaky(reruns=3, reruns_delay=2))

        if item.get_closest_marker("incompatible_with_test_venv") and config.getoption(
            "--use-venv"
        ):
            item.add_marker(pytest.mark.skip("Incompatible with test venv"))
        if (
            item.get_closest_marker("incompatible_with_venv")
            and sys.prefix != sys.base_prefix
        ):
            item.add_marker(pytest.mark.skip("Incompatible with venv"))

        if item.get_closest_marker("incompatible_with_sysconfig") and _USE_SYSCONFIG:
            item.add_marker(pytest.mark.skip("Incompatible with sysconfig"))

        # "Item" has no attribute "module"
        module_file = item.module.__file__  # type: ignore[attr-defined]
        module_path = os.path.relpath(
            module_file, os.path.commonprefix([__file__, module_file])
        )

        module_root_dir = module_path.split(os.pathsep)[0]
        if (
            module_root_dir.startswith("functional")
            or module_root_dir.startswith("integration")
            or module_root_dir.startswith("lib")
        ):
            item.add_marker(pytest.mark.integration)
        elif module_root_dir.startswith("unit"):
            item.add_marker(pytest.mark.unit)
        else:
            raise RuntimeError(f"Unknown test type (filename = {module_path})")


@pytest.fixture(scope="session")
def tmpdir_factory(
    request: pytest.FixtureRequest, tmpdir_factory: pytest.TempdirFactory
) -> Iterator[pytest.TempdirFactory]:
    """Modified `tmpdir_factory` session fixture
    that will automatically cleanup after itself.
    """
    yield tmpdir_factory
    if not request.config.getoption("--keep-tmpdir"):
        shutil.rmtree(
            tmpdir_factory.getbasetemp(),
            ignore_errors=True,
        )


@pytest.fixture
def tmpdir(request: pytest.FixtureRequest, tmpdir: py.path.local) -> Iterator[Path]:
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
