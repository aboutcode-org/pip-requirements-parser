import json
import os
import pathlib
import re
import shutil
import site
import subprocess
import sys
import textwrap
from base64 import urlsafe_b64encode
from contextlib import contextmanager
from hashlib import sha256
from io import BytesIO
from textwrap import dedent
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
    cast,
)
from zipfile import ZipFile

import pytest
from pip._vendor.packaging.utils import canonicalize_name
from scripttest import FoundDir, FoundFile, ProcResult, TestFileEnvironment

from pip._internal.index.collector import LinkCollector
from pip._internal.index.package_finder import PackageFinder
from pip._internal.locations import get_major_minor_version
from pip._internal.models.search_scope import SearchScope
from pip._internal.models.selection_prefs import SelectionPreferences
from pip._internal.models.target_python import TargetPython
from pip._internal.network.session import PipSession
from pip._internal.utils.deprecation import DEPRECATION_MSG_PREFIX
from tests.lib.path import Path, curdir
from tests.lib.venv import VirtualEnvironment
from tests.lib.wheel import make_wheel

if TYPE_CHECKING:
    # Literal was introduced in Python 3.8.
    from typing import Literal

    ResolverVariant = Literal["resolvelib", "legacy"]
else:
    ResolverVariant = str

DATA_DIR = Path(__file__).parent.parent.joinpath("data").resolve()
SRC_DIR = Path(__file__).resolve().parent.parent.parent

pyversion = get_major_minor_version()

CURRENT_PY_VERSION_INFO = sys.version_info[:3]

_Test = Callable[..., None]
_FilesState = Dict[str, Union[FoundDir, FoundFile]]


def assert_paths_equal(actual: str, expected: str) -> None:
    assert os.path.normpath(actual) == os.path.normpath(expected)


def path_to_url(path: str) -> str:
    """
    Convert a path to URI. The path will be made absolute and
    will not have quoted path parts.
    (adapted from pip.util)
    """
    path = os.path.normpath(os.path.abspath(path))
    drive, path = os.path.splitdrive(path)
    filepath = path.split(os.path.sep)
    url = "/".join(filepath)
    if drive:
        # Note: match urllib.request.pathname2url's
        # behavior: uppercase the drive letter.
        return "file:///" + drive.upper() + url
    return "file://" + url


def _test_path_to_file_url(path: Path) -> str:
    """
    Convert a test Path to a "file://" URL.

    Args:
      path: a tests.lib.path.Path object.
    """
    return "file://" + path.resolve().replace("\\", "/")


def create_file(path: str, contents: Optional[str] = None) -> None:
    """Create a file on the path, with the given contents"""
    from pip._internal.utils.misc import ensure_dir

    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        if contents is not None:
            f.write(contents)
        else:
            f.write("\n")


def make_test_search_scope(
    find_links: Optional[List[str]] = None,
    index_urls: Optional[List[str]] = None,
) -> SearchScope:
    if find_links is None:
        find_links = []
    if index_urls is None:
        index_urls = []

    return SearchScope.create(find_links=find_links, index_urls=index_urls)


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
    def packages2(self) -> Path:
        return self.root.joinpath("packages2")

    @property
    def packages3(self) -> Path:
        return self.root.joinpath("packages3")

    @property
    def src(self) -> Path:
        return self.root.joinpath("src")

    @property
    def indexes(self) -> Path:
        return self.root.joinpath("indexes")

    @property
    def reqfiles(self) -> Path:
        return self.root.joinpath("reqfiles")

    @property
    def completion_paths(self) -> Path:
        return self.root.joinpath("completion_paths")

    @property
    def find_links(self) -> str:
        return path_to_url(self.packages)

    @property
    def find_links2(self) -> str:
        return path_to_url(self.packages2)

    @property
    def find_links3(self) -> str:
        return path_to_url(self.packages3)

    @property
    def backends(self) -> str:
        return path_to_url(self.root.joinpath("backends"))

    def index_url(self, index: str = "simple") -> str:
        return path_to_url(self.root.joinpath("indexes", index))


class TestFailure(AssertionError):
    """
    An "assertion" failed during testing.
    """

    pass


def _one_or_both(a: Optional[str], b: Any) -> str:
    """Returns f"{a}\n{b}" if a is truthy, else returns str(b)."""
    if not a:
        return str(b)

    return f"{a}\n{b}"


def make_check_stderr_message(stderr: str, line: str, reason: str) -> str:
    """
    Create an exception message to use inside check_stderr().
    """
    return dedent(
        """\
    {reason}:
     Caused by line: {line!r}
     Complete stderr: {stderr}
    """
    ).format(stderr=stderr, line=line, reason=reason)


def _create_main_file(
    dir_path: Path, name: Optional[str] = None, output: Optional[str] = None
) -> None:
    """
    Create a module with a main() function that prints the given output.
    """
    if name is None:
        name = "version_pkg"
    if output is None:
        output = "0.1"
    text = textwrap.dedent(
        f"""
        def main():
            print({output!r})
        """
    )
    filename = f"{name}.py"
    dir_path.joinpath(filename).write_text(text)


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


def urlsafe_b64encode_nopad(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_really_basic_wheel(name: str, version: str) -> bytes:
    def digest(contents: bytes) -> str:
        return "sha256={}".format(urlsafe_b64encode_nopad(sha256(contents).digest()))

    def add_file(path: str, text: str) -> None:
        contents = text.encode("utf-8")
        z.writestr(path, contents)
        records.append((path, digest(contents), str(len(contents))))

    dist_info = f"{name}-{version}.dist-info"
    record_path = f"{dist_info}/RECORD"
    records = [(record_path, "", "")]
    buf = BytesIO()
    with ZipFile(buf, "w") as z:
        add_file(f"{dist_info}/WHEEL", "Wheel-Version: 1.0")
        add_file(
            f"{dist_info}/METADATA",
            dedent(
                """\
                Metadata-Version: 2.1
                Name: {}
                Version: {}
                """.format(
                    name, version
                )
            ),
        )
        z.writestr(record_path, "\n".join(",".join(r) for r in records))
    buf.seek(0)
    return buf.read()
