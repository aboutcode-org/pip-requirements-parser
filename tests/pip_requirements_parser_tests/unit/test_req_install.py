
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

from typing import Optional

import pytest
from packaging.requirements import Requirement
from packaging.requirements import InvalidRequirement

from pip_requirements_parser import InstallationError
from pip_requirements_parser import InstallRequirement
from pip_requirements_parser import RequirementLine


def install_req_from_req_string(
    req_string: str,
    requirement_line: Optional[RequirementLine] = None,
) -> InstallRequirement:

    try:
        req = Requirement(req_string)
    except InvalidRequirement:
        # FIXME: return invalidreq line instead
        raise InstallationError(f"Invalid requirement: '{req_string}'")

    return InstallRequirement(req=req, requirement_line=requirement_line)



class TestInstallRequirementFrom:
    def test_install_req_from_string_invalid_requirement(self) -> None:
        """
        Requirement strings that cannot be parsed by
        packaging.requirements.Requirement raise an InstallationError.
        """
        with pytest.raises(InstallationError) as excinfo:
            install_req_from_req_string("http:/this/is/invalid")

        assert str(excinfo.value) == ("Invalid requirement: 'http:/this/is/invalid'")

    def test_install_req_from_string_without_requirement_line(self) -> None:
        """
        Test to make sure that install_req_from_string succeeds
        when called with URL (PEP 508) but without requirement_line.
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
        assert install_req.requirement_line is None
        assert install_req.is_wheel

    def test_install_req_from_string_with_requirement_line_without_link(self) -> None:
        """
        Test to make sure that install_req_from_string succeeds
        when called with URL (PEP 508) and requirement_line
        does not have a link.
        """
        # Test with a PEP 508 url install string:
        wheel_url = (
            "https://download.pytorch.org/whl/cu90/"
            "torch-1.0.0-cp36-cp36m-win_amd64.whl"
        )
        install_str = "torch@ " + wheel_url

        # Dummy numpy "requirement_line" requirement without link:
        requirement_line = RequirementLine(line="foo bar")

        # Attempt install from install string comes:
        install_req = install_req_from_req_string(install_str, requirement_line=requirement_line)

        assert isinstance(install_req, InstallRequirement)
        assert isinstance(install_req.requirement_line, RequirementLine)
        assert install_req.link is not None
        assert install_req.link.url == wheel_url
        assert install_req.req is not None
        assert install_req.req.url == wheel_url
        assert install_req.is_wheel
