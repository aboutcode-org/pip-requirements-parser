
class InstallRequirement:
    """
    Represents something that may be installed later on, may have information
    about where to fetch the relevant requirement and also contains logic for
    installing the said requirement.
    """

    def __init__(
        self,
        req: Optional[Requirement],
        comes_from: Optional[Union[str, "InstallRequirement"]],
        editable: bool = False,
        link: Optional[Link] = None,
        markers: Optional[Marker] = None,
        use_pep517: Optional[bool] = None,
        isolated: bool = False,
        install_options: Optional[List[str]] = None,
        global_options: Optional[List[str]] = None,
        hash_options: Optional[Dict[str, List[str]]] = None,
        constraint: bool = False,
        extras: Collection[str] = (),
        user_supplied: bool = False,
        permit_editable_wheels: bool = False,
    ) -> None:
        assert req is None or isinstance(req, Requirement), req
        self.req = req
        self.comes_from = comes_from
        self.constraint = constraint
        self.editable = editable
        self.permit_editable_wheels = permit_editable_wheels
        self.legacy_install_reason: Optional[int] = None

        # source_dir is the local directory where the linked requirement is
        # located, or unpacked. In case unpacking is needed, creating and
        # populating source_dir is done by the RequirementPreparer. Note this
        # is not necessarily the directory where pyproject.toml or setup.py is
        # located - that one is obtained via unpacked_source_directory.
        self.source_dir: Optional[str] = None
        if self.editable:
            assert link
            if link.is_file:
                self.source_dir = os.path.normpath(os.path.abspath(link.file_path))

        if link is None and req and req.url:
            # PEP 508 URL requirement
            link = Link(req.url)
        self.link = self.original_link = link
        self.original_link_is_in_wheel_cache = False

        # Path to any downloaded or already-existing package.
        self.local_file_path: Optional[str] = None
        if self.link and self.link.is_file:
            self.local_file_path = self.link.file_path

        if extras:
            self.extras = extras
        elif req:
            self.extras = {safe_extra(extra) for extra in req.extras}
        else:
            self.extras = set()
        if markers is None and req:
            markers = req.marker
        self.markers = markers

        # This holds the Distribution object if this requirement is already installed.
        self.satisfied_by: Optional[BaseDistribution] = None
        # Whether the installation process should try to uninstall an existing
        # distribution before installing this requirement.
        self.should_reinstall = False
        # Temporary build location
        self._temp_build_dir: Optional[TempDirectory] = None
        # Set to True after successful installation
        self.install_succeeded: Optional[bool] = None
        # Supplied options
        self.install_options = install_options if install_options else []
        self.global_options = global_options if global_options else []
        self.hash_options = hash_options if hash_options else {}
        # Set to True after successful preparation of this requirement
        self.prepared = False
        # User supplied requirement are explicitly requested for installation
        # by the user via CLI arguments or requirements files, as opposed to,
        # e.g. dependencies, extras or constraints.
        self.user_supplied = user_supplied

        self.isolated = isolated
        self.build_env: BuildEnvironment = NoOpBuildEnvironment()

        # For PEP 517, the directory where we request the project metadata
        # gets stored. We need this to pass to build_wheel, so the backend
        # can ensure that the wheel matches the metadata (see the PEP for
        # details).
        self.metadata_directory: Optional[str] = None

        # The static build requirements (from pyproject.toml)
        self.pyproject_requires: Optional[List[str]] = None

        # Build requirements that we will check are available
        self.requirements_to_check: List[str] = []

        # The PEP 517 backend we should use to build the project
        self.pep517_backend: Optional[Pep517HookCaller] = None

        # Are we using PEP 517 for this requirement?
        # After pyproject.toml has been loaded, the only valid values are True
        # and False. Before loading, None is valid (meaning "use the default").
        # Setting an explicit value before loading pyproject.toml is supported,
        # but after loading this flag should be treated as read only.
        self.use_pep517 = use_pep517

        # This requirement needs more preparation before it can be built
        self.needs_more_preparation = False

    def __str__(self) -> str:
        if self.req:
            s = str(self.req)
            if self.link:
                s += " from {}".format(redact_auth_from_url(self.link.url))
        elif self.link:
            s = redact_auth_from_url(self.link.url)
        else:
            s = "<InstallRequirement>"
        if self.satisfied_by is not None:
            s += " in {}".format(display_path(self.satisfied_by.location))
        if self.comes_from:
            if isinstance(self.comes_from, str):
                comes_from: Optional[str] = self.comes_from
            else:
                comes_from = self.comes_from.from_path()
            if comes_from:
                s += f" (from {comes_from})"
        return s

    def __repr__(self) -> str:
        return "<{} object: {} editable={!r}>".format(
            self.__class__.__name__, str(self), self.editable
        )


    # Things that are valid for all kinds of requirements?
    @property
    def name(self) -> Optional[str]:
        if self.req is None:
            return None
        return self.req.name


    @property
    def specifier(self) -> SpecifierSet:
        return self.req.specifier

    @property
    def is_pinned(self) -> bool:
        """Return whether I am pinned to an exact version.

        For example, some-package==1.2 is pinned; some-package>1.2 is not.
        """
        specifiers = self.specifier
        return len(specifiers) == 1 and next(iter(specifiers)).operator in {"==", "==="}

    def match_markers(self, extras_requested: Optional[Iterable[str]] = None) -> bool:
        if not extras_requested:
            # Provide an extra to safely evaluate the markers
            # without matching any extra
            extras_requested = ("",)
        if self.markers is not None:
            return any(
                self.markers.evaluate({"extra": extra}) for extra in extras_requested
            )
        else:
            return True

    @property
    def has_hash_options(self) -> bool:
        """Return whether any known-good hashes are specified as options.

        These activate --require-hashes mode; hashes specified as part of a
        URL do not.

        """
        return bool(self.hash_options)

    def hashes(self, trust_internet: bool = True) -> Hashes:
        """Return a hash-comparer that considers my option- and URL-based
        hashes to be known-good.

        Hashes in URLs--ones embedded in the requirements file, not ones
        downloaded from an index server--are almost peers with ones from
        flags. They satisfy --require-hashes (whether it was implicitly or
        explicitly activated) but do not activate it. md5 and sha224 are not
        allowed in flags, which should nudge people toward good algos. We
        always OR all hashes together, even ones from URLs.

        :param trust_internet: Whether to trust URL-based (#md5=...) hashes
            downloaded from the internet, as by populate_link()

        """
        good_hashes = self.hash_options.copy()
        link = self.link if trust_internet else self.original_link
        if link and link.hash:
            good_hashes.setdefault(link.hash_name, []).append(link.hash)
        return Hashes(good_hashes)

    def from_path(self) -> Optional[str]:
        """Format a nice indicator to show where this "comes from" """
        if self.req is None:
            return None
        s = str(self.req)
        if self.comes_from:
            if isinstance(self.comes_from, str):
                comes_from = self.comes_from
            else:
                comes_from = self.comes_from.from_path()
            if comes_from:
                s += "->" + comes_from
        return s

    # Things valid for wheels
    @property
    def is_wheel(self) -> bool:
        if not self.link:
            return False
        return self.link.is_wheel

    @property
    def metadata(self) -> Any:
        if not hasattr(self, "_metadata"):
            self._metadata = self.get_dist().metadata

        return self._metadata
