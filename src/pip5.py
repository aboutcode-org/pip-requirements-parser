
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
