
NormalizedExtra = NewType("NormalizedExtra", str)


@functools.lru_cache(maxsize=512)
def get_requirement(req_string: str) -> Requirement:
    """Construct a packaging.Requirement object with caching"""
    # Parsing requirement strings is expensive, and is also expected to happen
    # with a low diversity of different arguments (at least relative the number
    # constructed). This method adds a cache to requirement object creation to
    # minimize repeated parsing of the same string to construct equivalent
    # Requirement objects.
    return Requirement(req_string)


def safe_extra(extra: str) -> NormalizedExtra:
    """Convert an arbitrary string to a standard 'extra' name

    Any runs of non-alphanumeric characters are replaced with a single '_',
    and the result is always lowercased.

    This function is duplicated from ``pkg_resources``. Note that this is not
    the same to either ``canonicalize_name`` or ``_egg_link_name``.
    """
    return cast(NormalizedExtra, re.sub("[^A-Za-z0-9.-]+", "_", extra).lower())
