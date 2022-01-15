
def is_url(name: str) -> bool:
    """
    Return true if the name looks like a URL.
    """
    scheme = get_url_scheme(name)
    if scheme is None:
        return False
    return scheme in ["http", "https", "file", "ftp"] + vcs.all_schemes

