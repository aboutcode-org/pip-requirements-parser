
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

# The following comment should be removed at some point in the future.
# mypy: strict-optional=False

import errno
import logging
import os
import shutil
import stat
from types import TracebackType
from typing import (
    Any,
    Callable,
    Optional,
    Tuple,
    Type,
    TypeVar,
)


logger = logging.getLogger(__name__)

T = TypeVar("T")
ExcInfo = Tuple[Type[BaseException], BaseException, TracebackType]
VersionInfo = Tuple[int, int, int]
NetlocTuple = Tuple[str, Tuple[Optional[str], Optional[str]]]


def ensure_dir(path: str) -> None:
    """os.path.makedirs without EEXIST."""
    try:
        os.makedirs(path)
    except OSError as e:
        # Windows can raise spurious ENOTEMPTY errors. See #6426.
        if e.errno != errno.EEXIST and e.errno != errno.ENOTEMPTY:
            raise


def rmtree(directory: str, ignore_errors: bool = False) -> None:
    shutil.rmtree(directory, ignore_errors=ignore_errors, onerror=rmtree_errorhandler)


def rmtree_errorhandler(func: Callable[..., Any], path: str, exc_info: ExcInfo) -> None:
    """On Windows, the files in .svn are read-only, so when rmtree() tries to
    remove them, an exception is thrown.  We catch that here, remove the
    read-only attribute, and hopefully continue without problems."""
    try:
        has_attr_readonly = not (os.stat(path).st_mode & stat.S_IWRITE)
    except OSError:
        # it's equivalent to os.path.exists
        return

    if has_attr_readonly:
        # convert to read/write
        os.chmod(path, stat.S_IWRITE)
        # use the original function to repeat the operation
        func(path)
        return
    else:
        raise


# Simulates an enum
def enum(*sequential: Any, **named: Any) -> Type[Any]:
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = {value: key for key, value in enums.items()}
    enums["reverse_mapping"] = reverse
    return type("Enum", (), enums)

