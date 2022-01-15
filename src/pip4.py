
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
