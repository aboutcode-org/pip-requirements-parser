
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

