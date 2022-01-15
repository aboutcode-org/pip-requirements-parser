
# Copyright (c) 2008-2021 The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

import os
import tempfile

import pytest
from packaging.requirements import Requirement

from pip_requirements import InstallationError
from pip_requirements import (
    install_req_from_line,
    install_req_from_req_string,
)
from pip_requirements import InstallRequirement


class TestInstallRequirementFrom:
    def test_install_req_from_string_invalid_requirement(self) -> None:
        """
        Requirement strings that cannot be parsed by
        packaging.requirements.Requirement raise an InstallationError.
        """
        with pytest.raises(InstallationError) as excinfo:
            install_req_from_req_string("http:/this/is/invalid")

        assert str(excinfo.value) == ("Invalid requirement: 'http:/this/is/invalid'")

    def test_install_req_from_string_without_comes_from(self) -> None:
        """
        Test to make sure that install_req_from_string succeeds
        when called with URL (PEP 508) but without comes_from.
        """
        # Test with a PEP 508 url install string:
        wheel_url = (
            "https://download.pytorch.org/whl/cu90/"
            "torch-1.0.0-cp36-cp36m-win_amd64.whl"
        )
        install_str = "torch@ " + wheel_url
        install_req = install_req_from_req_string(install_str)

        assert isinstance(install_req, InstallRequirement)
        assert install_req.link is not None
        assert install_req.link.url == wheel_url
        assert install_req.req is not None
        assert install_req.req.url == wheel_url
        assert install_req.comes_from is None
        assert install_req.is_wheel

    def test_install_req_from_string_with_comes_from_without_link(self) -> None:
        """
        Test to make sure that install_req_from_string succeeds
        when called with URL (PEP 508) and comes_from
        does not have a link.
        """
        # Test with a PEP 508 url install string:
        wheel_url = (
            "https://download.pytorch.org/whl/cu90/"
            "torch-1.0.0-cp36-cp36m-win_amd64.whl"
        )
        install_str = "torch@ " + wheel_url

        # Dummy numpy "comes_from" requirement without link:
        comes_from = InstallRequirement(Requirement("numpy>=1.15.0"), comes_from=None)

        # Attempt install from install string comes:
        install_req = install_req_from_req_string(install_str, comes_from=comes_from)

        assert isinstance(install_req, InstallRequirement)
        assert isinstance(install_req.comes_from, InstallRequirement)
        assert install_req.comes_from.link is None
        assert install_req.link is not None
        assert install_req.link.url == wheel_url
        assert install_req.req is not None
        assert install_req.req.url == wheel_url
        assert install_req.is_wheel
