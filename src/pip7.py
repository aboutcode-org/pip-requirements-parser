
BOMS: List[Tuple[bytes, str]] = [
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF32, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
]

ENCODING_RE = re.compile(br"coding[:=]\s*([-\w.]+)")


def auto_decode(data: bytes) -> str:
    """Check a bytes string for a BOM to correctly detect the encoding

    Fallback to locale.getpreferredencoding(False) like open() on Python3"""
    for bom, encoding in BOMS:
        if data.startswith(bom):
            return data[len(bom) :].decode(encoding)
    # Lets check the first two lines as in PEP263
    for line in data.split(b"\n")[:2]:
        if line[0:1] == b"#" and ENCODING_RE.search(line):
            result = ENCODING_RE.search(line)
            assert result is not None
            encoding = result.groups()[0].decode("ascii")
            return data.decode(encoding)
    return data.decode(
        locale.getpreferredencoding(False) or sys.getdefaultencoding(),
    )

class PackageIndex:
    """Represents a Package Index and provides easier access to endpoints"""

    __slots__ = ["url", "netloc", "simple_url", "pypi_url", "file_storage_domain"]

    def __init__(self, url: str, file_storage_domain: str) -> None:
        super().__init__()
        self.url = url
        self.netloc = urllib.parse.urlsplit(url).netloc
        self.simple_url = self._url_for_path("simple")
        self.pypi_url = self._url_for_path("pypi")

        # This is part of a temporary hack used to block installs of PyPI
        # packages which depend on external urls only necessary until PyPI can
        # block such packages themselves
        self.file_storage_domain = file_storage_domain

    def _url_for_path(self, path: str) -> str:
        return urllib.parse.urljoin(self.url, path)


PyPI = PackageIndex("https://pypi.org/", file_storage_domain="files.pythonhosted.org")
TestPyPI = PackageIndex(
    "https://test.pypi.org/", file_storage_domain="test-files.pythonhosted.org"
)

class PipError(Exception):
    """The base pip error."""


class InstallationError(PipError):
    """General exception during installation"""


class DistributionNotFound(InstallationError):
    """Raised when a distribution cannot be found to satisfy a requirement"""


class RequirementsFileParseError(InstallationError):
    """Raised when a general error occurs parsing a requirements file line."""


class CommandError(PipError):
    """Raised when there is an error in command-line arguments"""


class InvalidWheelFilename(InstallationError):
    """Invalid wheel filename."""


class HashError(InstallationError):
    """
    A failure to verify a package against known-good hashes
    """


class VcsHashUnsupported(HashError):
    """A hash was provided for a version-control-system-based requirement, but
    we don't have a method for hashing those."""


class DirectoryUrlHashUnsupported(HashError):
    """A hash was provided for a version-control-system-based requirement, but
    we don't have a method for hashing those."""


class HashMissing(HashError):
    """A hash was needed for a requirement but is absent."""


class HashUnpinned(HashError):
    """A requirement had a hash specified but was not pinned to a specific
    version."""


class HashMismatch(HashError):
    """
    Distribution file hash values don't match.
    """


class FormatControl:
    """Helper for managing formats from which a package can be installed."""

    __slots__ = ["no_binary", "only_binary"]

    def __init__(
        self,
        no_binary: Optional[Set[str]] = None,
        only_binary: Optional[Set[str]] = None,
    ) -> None:
        if no_binary is None:
            no_binary = set()
        if only_binary is None:
            only_binary = set()

        self.no_binary = no_binary
        self.only_binary = only_binary

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented

        if self.__slots__ != other.__slots__:
            return False

        return all(getattr(self, k) == getattr(other, k) for k in self.__slots__)

    def __repr__(self) -> str:
        return "{}({}, {})".format(
            self.__class__.__name__, self.no_binary, self.only_binary
        )

    @staticmethod
    def handle_mutual_excludes(value: str, target: Set[str], other: Set[str]) -> None:
        if value.startswith("-"):
            raise CommandError(
                "--no-binary / --only-binary option requires 1 argument."
            )
        new = value.split(",")
        while ":all:" in new:
            other.clear()
            target.clear()
            target.add(":all:")
            del new[: new.index(":all:") + 1]
            # Without a none, we want to discard everything as :all: covers it
            if ":none:" not in new:
                return
        for name in new:
            if name == ":none:":
                target.clear()
                continue
            name = canonicalize_name(name)
            other.discard(name)
            target.add(name)

    def get_allowed_formats(self, canonical_name: str) -> FrozenSet[str]:
        result = {"binary", "source"}
        if canonical_name in self.only_binary:
            result.discard("source")
        elif canonical_name in self.no_binary:
            result.discard("binary")
        elif ":all:" in self.only_binary:
            result.discard("source")
        elif ":all:" in self.no_binary:
            result.discard("binary")
        return frozenset(result)

    def disallow_binaries(self) -> None:
        self.handle_mutual_excludes(
            ":all:",
            self.no_binary,
            self.only_binary,
        )

class SearchScope:

    """
    Encapsulates the locations that pip is configured to search.
    """

    __slots__ = ["find_links", "index_urls"]

    def __init__(
        self,
        find_links: List[str],
        index_urls: List[str],
    ) -> None:
        self.find_links = find_links
        self.index_urls = index_urls

def check_install_build_global(
    options: Values, check_options: Optional[Values] = None
) -> None:
    """Disable wheels if per-setup.py call options are set.

    :param options: The OptionParser options to update.
    :param check_options: The options to check, if not supplied defaults to
        options.
    """
    if check_options is None:
        check_options = options

    def getname(n: str) -> Optional[Any]:
        return getattr(check_options, n, None)

    names = ["build_options", "global_options", "install_options"]
    if any(map(getname, names)):
        control = options.format_control
        control.disallow_binaries()
        warnings.warn(
            "Disabling all use of wheels due to the use of --build-option "
            "/ --global-option / --install-option.",
            stacklevel=2,
        )


def check_dist_restriction(options: Values, check_target: bool = False) -> None:
    """Function for determining if custom platform options are allowed.

    :param options: The OptionParser options.
    :param check_target: Whether or not to check if --target is being used.
    """
    dist_restriction_set = any(
        [
            options.python_version,
            options.platforms,
            options.abis,
            options.implementation,
        ]
    )

    binary_only = FormatControl(set(), {":all:"})
    sdist_dependencies_allowed = (
        options.format_control != binary_only and not options.ignore_dependencies
    )

    # Installations or downloads using dist restrictions must not combine
    # source distributions and dist-specific wheels, as they are not
    # guaranteed to be locally compatible.
    if dist_restriction_set and sdist_dependencies_allowed:
        raise CommandError(
            "When restricting platform and interpreter constraints using "
            "--python-version, --platform, --abi, or --implementation, "
            "either --no-deps must be set, or --only-binary=:all: must be "
            "set and --no-binary must not be set (or must be set to "
            ":none:)."
        )

    if check_target:
        if dist_restriction_set and not options.target_dir:
            raise CommandError(
                "Can not use any platform or abi specific options unless "
                "installing via '--target'"
            )


def _path_option_check(option: Option, opt: str, value: str) -> str:
    return os.path.expanduser(value)


def _package_name_option_check(option: Option, opt: str, value: str) -> str:
    return canonicalize_name(value)


class PipOption(Option):
    TYPES = Option.TYPES + ("path", "package_name")
    TYPE_CHECKER = Option.TYPE_CHECKER.copy()
    TYPE_CHECKER["package_name"] = _package_name_option_check
    TYPE_CHECKER["path"] = _path_option_check


###########
# options #
###########

help_: Callable[..., Option] = partial(
    Option,
    "-h",
    "--help",
    dest="help",
    action="help",
    help="Show help.",
)

debug_mode: Callable[..., Option] = partial(
    Option,
    "--debug",
    dest="debug_mode",
    action="store_true",
    default=False,
    help=(
        "Let unhandled exceptions propagate outside the main subroutine, "
        "instead of logging them to stderr."
    ),
)

isolated_mode: Callable[..., Option] = partial(
    Option,
    "--isolated",
    dest="isolated_mode",
    action="store_true",
    default=False,
    help=(
        "Run pip in an isolated mode, ignoring environment variables and user "
        "configuration."
    ),
)

require_virtualenv: Callable[..., Option] = partial(
    Option,
    "--require-virtualenv",
    "--require-venv",
    dest="require_venv",
    action="store_true",
    default=False,
    help=(
        "Allow pip to only run in a virtual environment; "
        "exit with an error otherwise."
    ),
)

verbose: Callable[..., Option] = partial(
    Option,
    "-v",
    "--verbose",
    dest="verbose",
    action="count",
    default=0,
    help="Give more output. Option is additive, and can be used up to 3 times.",
)

no_color: Callable[..., Option] = partial(
    Option,
    "--no-color",
    dest="no_color",
    action="store_true",
    default=False,
    help="Suppress colored output.",
)

version: Callable[..., Option] = partial(
    Option,
    "-V",
    "--version",
    dest="version",
    action="store_true",
    help="Show version and exit.",
)

quiet: Callable[..., Option] = partial(
    Option,
    "-q",
    "--quiet",
    dest="quiet",
    action="count",
    default=0,
    help=(
        "Give less output. Option is additive, and can be used up to 3"
        " times (corresponding to WARNING, ERROR, and CRITICAL logging"
        " levels)."
    ),
)

progress_bar: Callable[..., Option] = partial(
    Option,
    "--progress-bar",
    dest="progress_bar",
    type="choice",
    choices=list(BAR_TYPES.keys()),
    default="on",
    help=(
        "Specify type of progress to be displayed ["
        + "|".join(BAR_TYPES.keys())
        + "] (default: %default)"
    ),
)

log: Callable[..., Option] = partial(
    PipOption,
    "--log",
    "--log-file",
    "--local-log",
    dest="log",
    metavar="path",
    type="path",
    help="Path to a verbose appending log.",
)

no_input: Callable[..., Option] = partial(
    Option,
    # Don't ask for input
    "--no-input",
    dest="no_input",
    action="store_true",
    default=False,
    help="Disable prompting for input.",
)

proxy: Callable[..., Option] = partial(
    Option,
    "--proxy",
    dest="proxy",
    type="str",
    default="",
    help="Specify a proxy in the form [user:passwd@]proxy.server:port.",
)

retries: Callable[..., Option] = partial(
    Option,
    "--retries",
    dest="retries",
    type="int",
    default=5,
    help="Maximum number of retries each connection should attempt "
    "(default %default times).",
)

timeout: Callable[..., Option] = partial(
    Option,
    "--timeout",
    "--default-timeout",
    metavar="sec",
    dest="timeout",
    type="float",
    default=15,
    help="Set the socket timeout (default %default seconds).",
)


def exists_action() -> Option:
    return Option(
        # Option when path already exist
        "--exists-action",
        dest="exists_action",
        type="choice",
        choices=["s", "i", "w", "b", "a"],
        default=[],
        action="append",
        metavar="action",
        help="Default action when a path already exists: "
        "(s)witch, (i)gnore, (w)ipe, (b)ackup, (a)bort.",
    )


cert: Callable[..., Option] = partial(
    PipOption,
    "--cert",
    dest="cert",
    type="path",
    metavar="path",
    help=(
        "Path to PEM-encoded CA certificate bundle. "
        "If provided, overrides the default. "
        "See 'SSL Certificate Verification' in pip documentation "
        "for more information."
    ),
)

client_cert: Callable[..., Option] = partial(
    PipOption,
    "--client-cert",
    dest="client_cert",
    type="path",
    default=None,
    metavar="path",
    help="Path to SSL client certificate, a single file containing the "
    "private key and the certificate in PEM format.",
)

index_url: Callable[..., Option] = partial(
    Option,
    "-i",
    "--index-url",
    "--pypi-url",
    dest="index_url",
    metavar="URL",
    default=PyPI.simple_url,
    help="Base URL of the Python Package Index (default %default). "
    "This should point to a repository compliant with PEP 503 "
    "(the simple repository API) or a local directory laid out "
    "in the same format.",
)


def extra_index_url() -> Option:
    return Option(
        "--extra-index-url",
        dest="extra_index_urls",
        metavar="URL",
        action="append",
        default=[],
        help="Extra URLs of package indexes to use in addition to "
        "--index-url. Should follow the same rules as "
        "--index-url.",
    )


no_index: Callable[..., Option] = partial(
    Option,
    "--no-index",
    dest="no_index",
    action="store_true",
    default=False,
    help="Ignore package index (only looking at --find-links URLs instead).",
)


def find_links() -> Option:
    return Option(
        "-f",
        "--find-links",
        dest="find_links",
        action="append",
        default=[],
        metavar="url",
        help="If a URL or path to an html file, then parse for links to "
        "archives such as sdist (.tar.gz) or wheel (.whl) files. "
        "If a local path or file:// URL that's a directory, "
        "then look for archives in the directory listing. "
        "Links to VCS project URLs are not supported.",
    )


def trusted_host() -> Option:
    return Option(
        "--trusted-host",
        dest="trusted_hosts",
        action="append",
        metavar="HOSTNAME",
        default=[],
        help="Mark this host or host:port pair as trusted, even though it "
        "does not have valid or any HTTPS.",
    )


def constraints() -> Option:
    return Option(
        "-c",
        "--constraint",
        dest="constraints",
        action="append",
        default=[],
        metavar="file",
        help="Constrain versions using the given constraints file. "
        "This option can be used multiple times.",
    )


def requirements() -> Option:
    return Option(
        "-r",
        "--requirement",
        dest="requirements",
        action="append",
        default=[],
        metavar="file",
        help="Install from the given requirements file. "
        "This option can be used multiple times.",
    )


def editable() -> Option:
    return Option(
        "-e",
        "--editable",
        dest="editables",
        action="append",
        default=[],
        metavar="path/url",
        help=(
            "Install a project in editable mode (i.e. setuptools "
            '"develop mode") from a local project path or a VCS url.'
        ),
    )


def _handle_src(option: Option, opt_str: str, value: str, parser: OptionParser) -> None:
    value = os.path.abspath(value)
    setattr(parser.values, option.dest, value)


src: Callable[..., Option] = partial(
    PipOption,
    "--src",
    "--source",
    "--source-dir",
    "--source-directory",
    dest="src_dir",
    type="path",
    metavar="dir",
    default=get_src_prefix(),
    action="callback",
    callback=_handle_src,
    help="Directory to check out editable projects into. "
    'The default in a virtualenv is "<venv path>/src". '
    'The default for global installs is "<current dir>/src".',
)


def _get_format_control(values: Values, option: Option) -> Any:
    """Get a format_control object."""
    return getattr(values, option.dest)


def _handle_no_binary(
    option: Option, opt_str: str, value: str, parser: OptionParser
) -> None:
    existing = _get_format_control(parser.values, option)
    FormatControl.handle_mutual_excludes(
        value,
        existing.no_binary,
        existing.only_binary,
    )


def _handle_only_binary(
    option: Option, opt_str: str, value: str, parser: OptionParser
) -> None:
    existing = _get_format_control(parser.values, option)
    FormatControl.handle_mutual_excludes(
        value,
        existing.only_binary,
        existing.no_binary,
    )


def no_binary() -> Option:
    format_control = FormatControl(set(), set())
    return Option(
        "--no-binary",
        dest="format_control",
        action="callback",
        callback=_handle_no_binary,
        type="str",
        default=format_control,
        help="Do not use binary packages. Can be supplied multiple times, and "
        'each time adds to the existing value. Accepts either ":all:" to '
        'disable all binary packages, ":none:" to empty the set (notice '
        "the colons), or one or more package names with commas between "
        "them (no colons). Note that some packages are tricky to compile "
        "and may fail to install when this option is used on them.",
    )


def only_binary() -> Option:
    format_control = FormatControl(set(), set())
    return Option(
        "--only-binary",
        dest="format_control",
        action="callback",
        callback=_handle_only_binary,
        type="str",
        default=format_control,
        help="Do not use source packages. Can be supplied multiple times, and "
        'each time adds to the existing value. Accepts either ":all:" to '
        'disable all source packages, ":none:" to empty the set, or one '
        "or more package names with commas between them. Packages "
        "without binary distributions will fail to install when this "
        "option is used on them.",
    )


platforms: Callable[..., Option] = partial(
    Option,
    "--platform",
    dest="platforms",
    metavar="platform",
    action="append",
    default=None,
    help=(
        "Only use wheels compatible with <platform>. Defaults to the "
        "platform of the running system. Use this option multiple times to "
        "specify multiple platforms supported by the target interpreter."
    ),
)


# This was made a separate function for unit-testing purposes.
def _convert_python_version(value: str) -> Tuple[Tuple[int, ...], Optional[str]]:
    """
    Convert a version string like "3", "37", or "3.7.3" into a tuple of ints.

    :return: A 2-tuple (version_info, error_msg), where `error_msg` is
        non-None if and only if there was a parsing error.
    """
    if not value:
        # The empty string is the same as not providing a value.
        return (None, None)

    parts = value.split(".")
    if len(parts) > 3:
        return ((), "at most three version parts are allowed")

    if len(parts) == 1:
        # Then we are in the case of "3" or "37".
        value = parts[0]
        if len(value) > 1:
            parts = [value[0], value[1:]]

    try:
        version_info = tuple(int(part) for part in parts)
    except ValueError:
        return ((), "each version part must be an integer")

    return (version_info, None)


def _handle_python_version(
    option: Option, opt_str: str, value: str, parser: OptionParser
) -> None:
    """
    Handle a provided --python-version value.
    """
    version_info, error_msg = _convert_python_version(value)
    if error_msg is not None:
        msg = "invalid --python-version value: {!r}: {}".format(
            value,
            error_msg,
        )
        raise_option_error(parser, option=option, msg=msg)

    parser.values.python_version = version_info


python_version: Callable[..., Option] = partial(
    Option,
    "--python-version",
    dest="python_version",
    metavar="python_version",
    action="callback",
    callback=_handle_python_version,
    type="str",
    default=None,
    help=dedent(
        """\
    The Python interpreter version to use for wheel and "Requires-Python"
    compatibility checks. Defaults to a version derived from the running
    interpreter. The version can be specified using up to three dot-separated
    integers (e.g. "3" for 3.0.0, "3.7" for 3.7.0, or "3.7.3"). A major-minor
    version can also be given as a string without dots (e.g. "37" for 3.7.0).
    """
    ),
)


implementation: Callable[..., Option] = partial(
    Option,
    "--implementation",
    dest="implementation",
    metavar="implementation",
    default=None,
    help=(
        "Only use wheels compatible with Python "
        "implementation <implementation>, e.g. 'pp', 'jy', 'cp', "
        " or 'ip'. If not specified, then the current "
        "interpreter implementation is used.  Use 'py' to force "
        "implementation-agnostic wheels."
    ),
)


abis: Callable[..., Option] = partial(
    Option,
    "--abi",
    dest="abis",
    metavar="abi",
    action="append",
    default=None,
    help=(
        "Only use wheels compatible with Python abi <abi>, e.g. 'pypy_41'. "
        "If not specified, then the current interpreter abi tag is used. "
        "Use this option multiple times to specify multiple abis supported "
        "by the target interpreter. Generally you will need to specify "
        "--implementation, --platform, and --python-version when using this "
        "option."
    ),
)


def add_target_python_options(cmd_opts: OptionGroup) -> None:
    cmd_opts.add_option(platforms())
    cmd_opts.add_option(python_version())
    cmd_opts.add_option(implementation())
    cmd_opts.add_option(abis())


def make_target_python(options: Values) -> TargetPython:
    target_python = TargetPython(
        platforms=options.platforms,
        py_version_info=options.python_version,
        abis=options.abis,
        implementation=options.implementation,
    )

    return target_python


def prefer_binary() -> Option:
    return Option(
        "--prefer-binary",
        dest="prefer_binary",
        action="store_true",
        default=False,
        help="Prefer older binary packages over newer source packages.",
    )


cache_dir: Callable[..., Option] = partial(
    PipOption,
    "--cache-dir",
    dest="cache_dir",
    default=USER_CACHE_DIR,
    metavar="dir",
    type="path",
    help="Store the cache data in <dir>.",
)


def _handle_no_cache_dir(
    option: Option, opt: str, value: str, parser: OptionParser
) -> None:
    """
    Process a value provided for the --no-cache-dir option.

    This is an optparse.Option callback for the --no-cache-dir option.
    """
    # The value argument will be None if --no-cache-dir is passed via the
    # command-line, since the option doesn't accept arguments.  However,
    # the value can be non-None if the option is triggered e.g. by an
    # environment variable, like PIP_NO_CACHE_DIR=true.
    if value is not None:
        # Then parse the string value to get argument error-checking.
        try:
            strtobool(value)
        except ValueError as exc:
            raise_option_error(parser, option=option, msg=str(exc))

    # Originally, setting PIP_NO_CACHE_DIR to a value that strtobool()
    # converted to 0 (like "false" or "no") caused cache_dir to be disabled
    # rather than enabled (logic would say the latter).  Thus, we disable
    # the cache directory not just on values that parse to True, but (for
    # backwards compatibility reasons) also on values that parse to False.
    # In other words, always set it to False if the option is provided in
    # some (valid) form.
    parser.values.cache_dir = False


no_cache: Callable[..., Option] = partial(
    Option,
    "--no-cache-dir",
    dest="cache_dir",
    action="callback",
    callback=_handle_no_cache_dir,
    help="Disable the cache.",
)

no_deps: Callable[..., Option] = partial(
    Option,
    "--no-deps",
    "--no-dependencies",
    dest="ignore_dependencies",
    action="store_true",
    default=False,
    help="Don't install package dependencies.",
)

ignore_requires_python: Callable[..., Option] = partial(
    Option,
    "--ignore-requires-python",
    dest="ignore_requires_python",
    action="store_true",
    help="Ignore the Requires-Python information.",
)

no_build_isolation: Callable[..., Option] = partial(
    Option,
    "--no-build-isolation",
    dest="build_isolation",
    action="store_false",
    default=True,
    help="Disable isolation when building a modern source distribution. "
    "Build dependencies specified by PEP 518 must be already installed "
    "if this option is used.",
)


def _handle_no_use_pep517(
    option: Option, opt: str, value: str, parser: OptionParser
) -> None:
    """
    Process a value provided for the --no-use-pep517 option.

    This is an optparse.Option callback for the no_use_pep517 option.
    """
    # Since --no-use-pep517 doesn't accept arguments, the value argument
    # will be None if --no-use-pep517 is passed via the command-line.
    # However, the value can be non-None if the option is triggered e.g.
    # by an environment variable, for example "PIP_NO_USE_PEP517=true".
    if value is not None:
        msg = """A value was passed for --no-use-pep517,
        probably using either the PIP_NO_USE_PEP517 environment variable
        or the "no-use-pep517" config file option. Use an appropriate value
        of the PIP_USE_PEP517 environment variable or the "use-pep517"
        config file option instead.
        """
        raise_option_error(parser, option=option, msg=msg)

    # Otherwise, --no-use-pep517 was passed via the command-line.
    parser.values.use_pep517 = False


use_pep517: Any = partial(
    Option,
    "--use-pep517",
    dest="use_pep517",
    action="store_true",
    default=None,
    help="Use PEP 517 for building source distributions "
    "(use --no-use-pep517 to force legacy behaviour).",
)

no_use_pep517: Any = partial(
    Option,
    "--no-use-pep517",
    dest="use_pep517",
    action="callback",
    callback=_handle_no_use_pep517,
    default=None,
    help=SUPPRESS_HELP,
)

install_options: Callable[..., Option] = partial(
    Option,
    "--install-option",
    dest="install_options",
    action="append",
    metavar="options",
    help="Extra arguments to be supplied to the setup.py install "
    'command (use like --install-option="--install-scripts=/usr/local/'
    'bin"). Use multiple --install-option options to pass multiple '
    "options to setup.py install. If you are using an option with a "
    "directory path, be sure to use absolute path.",
)

build_options: Callable[..., Option] = partial(
    Option,
    "--build-option",
    dest="build_options",
    metavar="options",
    action="append",
    help="Extra arguments to be supplied to 'setup.py bdist_wheel'.",
)

global_options: Callable[..., Option] = partial(
    Option,
    "--global-option",
    dest="global_options",
    action="append",
    metavar="options",
    help="Extra global options to be supplied to the setup.py "
    "call before the install or bdist_wheel command.",
)

no_clean: Callable[..., Option] = partial(
    Option,
    "--no-clean",
    action="store_true",
    default=False,
    help="Don't clean up build directories.",
)

pre: Callable[..., Option] = partial(
    Option,
    "--pre",
    action="store_true",
    default=False,
    help="Include pre-release and development versions. By default, "
    "pip only finds stable versions.",
)

disable_pip_version_check: Callable[..., Option] = partial(
    Option,
    "--disable-pip-version-check",
    dest="disable_pip_version_check",
    action="store_true",
    default=False,
    help="Don't periodically check PyPI to determine whether a new version "
    "of pip is available for download. Implied with --no-index.",
)


def _handle_merge_hash(
    option: Option, opt_str: str, value: str, parser: OptionParser
) -> None:
    """Given a value spelled "algo:digest", append the digest to a list
    pointed to in a dict by the algo name."""
    if not parser.values.hashes:
        parser.values.hashes = {}
    try:
        algo, digest = value.split(":", 1)
    except ValueError:
        parser.error(
            "Arguments to {} must be a hash name "  # noqa
            "followed by a value, like --hash=sha256:"
            "abcde...".format(opt_str)
        )
    if algo not in STRONG_HASHES:
        parser.error(
            "Allowed hash algorithms for {} are {}.".format(  # noqa
                opt_str, ", ".join(STRONG_HASHES)
            )
        )
    parser.values.hashes.setdefault(algo, []).append(digest)


hash: Callable[..., Option] = partial(
    Option,
    "--hash",
    # Hash values eventually end up in InstallRequirement.hashes due to
    # __dict__ copying in process_line().
    dest="hashes",
    action="callback",
    callback=_handle_merge_hash,
    type="string",
    help="Verify that the package's archive matches this "
    "hash before installing. Example: --hash=sha256:abcdef...",
)


require_hashes: Callable[..., Option] = partial(
    Option,
    "--require-hashes",
    dest="require_hashes",
    action="store_true",
    default=False,
    help="Require a hash to check each requirement against, for "
    "repeatable installs. This option is implied when any package in a "
    "requirements file has a --hash option.",
)


list_path: Callable[..., Option] = partial(
    PipOption,
    "--path",
    dest="path",
    type="path",
    action="append",
    help="Restrict to the specified installation path for listing "
    "packages (can be used multiple times).",
)


def check_list_path_option(options: Values) -> None:
    if options.path and (options.user or options.local):
        raise CommandError("Cannot combine '--path' with '--user' or '--local'")


list_exclude: Callable[..., Option] = partial(
    PipOption,
    "--exclude",
    dest="excludes",
    action="append",
    metavar="package",
    type="package_name",
    help="Exclude specified package from the output",
)


no_python_version_warning: Callable[..., Option] = partial(
    Option,
    "--no-python-version-warning",
    dest="no_python_version_warning",
    action="store_true",
    default=False,
    help="Silence deprecation warnings for upcoming unsupported Pythons.",
)


use_new_feature: Callable[..., Option] = partial(
    Option,
    "--use-feature",
    dest="features_enabled",
    metavar="feature",
    action="append",
    default=[],
    choices=["2020-resolver", "fast-deps", "in-tree-build"],
    help="Enable new functionality, that may be backward incompatible.",
)

class PackageFinder:
    """This finds packages.

    This is meant to match easy_install's technique for looking for
    packages, by reading pages and looking for appropriate links.
    """

    def __init__(
        self,
        link_collector: LinkCollector,
        target_python: TargetPython,
        allow_yanked: bool,
        format_control: Optional[FormatControl] = None,
        candidate_prefs: Optional[CandidatePreferences] = None,
        ignore_requires_python: Optional[bool] = None,
    ) -> None:
        """
        This constructor is primarily meant to be used by the create() class
        method and from tests.

        :param format_control: A FormatControl object, used to control
            the selection of source packages / binary packages when consulting
            the index and links.
        :param candidate_prefs: Options to use when creating a
            CandidateEvaluator object.
        """
        if candidate_prefs is None:
            candidate_prefs = CandidatePreferences()

        format_control = format_control or FormatControl(set(), set())

        self._allow_yanked = allow_yanked
        self._candidate_prefs = candidate_prefs
        self._ignore_requires_python = ignore_requires_python
        self._link_collector = link_collector
        self._target_python = target_python

        self.format_control = format_control

        # These are boring links that have already been logged somehow.
        self._logged_links: Set[Link] = set()

    # Don't include an allow_yanked default value to make sure each call
    # site considers whether yanked releases are allowed. This also causes
    # that decision to be made explicit in the calling code, which helps
    # people when reading the code.
    @classmethod
    def create(
        cls,
        link_collector: LinkCollector,
        selection_prefs: SelectionPreferences,
        target_python: Optional[TargetPython] = None,
    ) -> "PackageFinder":
        """Create a PackageFinder.

        :param selection_prefs: The candidate selection preferences, as a
            SelectionPreferences object.
        :param target_python: The target Python interpreter to use when
            checking compatibility. If None (the default), a TargetPython
            object will be constructed from the running Python.
        """
        if target_python is None:
            target_python = TargetPython()

        candidate_prefs = CandidatePreferences(
            prefer_binary=selection_prefs.prefer_binary,
            allow_all_prereleases=selection_prefs.allow_all_prereleases,
        )

        return cls(
            candidate_prefs=candidate_prefs,
            link_collector=link_collector,
            target_python=target_python,
            allow_yanked=selection_prefs.allow_yanked,
            format_control=selection_prefs.format_control,
            ignore_requires_python=selection_prefs.ignore_requires_python,
        )

    @property
    def target_python(self) -> TargetPython:
        return self._target_python

    @property
    def search_scope(self) -> SearchScope:
        return self._link_collector.search_scope

    @search_scope.setter
    def search_scope(self, search_scope: SearchScope) -> None:
        self._link_collector.search_scope = search_scope

    @property
    def find_links(self) -> List[str]:
        return self._link_collector.find_links

    @property
    def index_urls(self) -> List[str]:
        return self.search_scope.index_urls

    @property
    def trusted_hosts(self) -> Iterable[str]:
        for host_port in self._link_collector.session.pip_trusted_origins:
            yield build_netloc(*host_port)

    @property
    def allow_all_prereleases(self) -> bool:
        return self._candidate_prefs.allow_all_prereleases

    def set_allow_all_prereleases(self) -> None:
        self._candidate_prefs.allow_all_prereleases = True

    @property
    def prefer_binary(self) -> bool:
        return self._candidate_prefs.prefer_binary

    def set_prefer_binary(self) -> None:
        self._candidate_prefs.prefer_binary = True
