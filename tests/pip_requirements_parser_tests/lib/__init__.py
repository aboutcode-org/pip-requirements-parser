
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import os
import shutil

from contextlib import contextmanager
from typing import (
    Iterator,
    List,
    Optional,
)

from pip_requirements_parser_tests.lib.path import Path


DATA_DIR = Path(__file__).parent.parent.joinpath("data").resolve()
SRC_DIR = Path(__file__).resolve().parent.parent.parent

REQFILES_DIR = DATA_DIR.joinpath("requirements")

ALL_REQFILES = [
    REQFILES_DIR.joinpath(rf) 
    for rf in os.listdir(REQFILES_DIR)
    if rf.endswith(".txt")
]


MORE_REQFILES_DIR = DATA_DIR.joinpath("more-requirements")

MORE_REQFILES = [
    MORE_REQFILES_DIR.joinpath(rf) 
    for rf in os.listdir(MORE_REQFILES_DIR)
    if rf.endswith(".txt")
]


SC_REQFILES_DIR = DATA_DIR.joinpath("sc-requirements")

SC_REQFILES = [
    SC_REQFILES_DIR.joinpath(rf) 
    for rf in os.listdir(SC_REQFILES_DIR)
    if rf.endswith(".txt")
]



class TestData:
    """
    Represents a bundle of pre-created test data.

    This copies a pristine set of test data into a root location that is
    designed to be test specific. The reason for this is when running the tests
    concurrently errors can be generated because the related tooling uses
    the directory as a work space. This leads to two concurrent processes
    trampling over each other. This class gets around that by copying all
    data into a directory and operating on the copied data.
    """

    __test__ = False

    def __init__(self, root: str, source: Optional[Path] = None) -> None:
        self.source = source or DATA_DIR
        self.root = Path(root).resolve()

    @classmethod
    def copy(cls, root: str) -> "TestData":
        obj = cls(root)
        obj.reset()
        return obj

    def reset(self) -> None:
        # Check explicitly for the target directory to avoid overly-broad
        # try/except.
        if self.root.exists():
            shutil.rmtree(self.root)
        shutil.copytree(self.source, self.root, symlinks=True)

    @property
    def packages(self) -> Path:
        return self.root.joinpath("packages")

    @property
    def reqfiles(self) -> Path:
        return self.root.joinpath("reqfiles")


@contextmanager
def requirements_file(contents: str, tmpdir: Path) -> Iterator[Path]:
    """Return a Path to a requirements file of given contents.

    As long as the context manager is open, the requirements file will exist.

    :param tmpdir: A Path to the folder in which to create the file

    """
    path = tmpdir / "reqs.txt"
    path.write_text(contents)
    yield path
    path.unlink()
