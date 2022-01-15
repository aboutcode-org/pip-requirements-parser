pip requirements - the only correct pip requirements parsing library
=====================================================================

# Copyright (c) nexB Inc. and others
# Copyright (c) The pip developers (see AUTHORS.txt file)
# SPDX-License-Identifier: MIT

pip is the ``package installer`` for Python and isusing "requirements" text
files that list the packages to install.

pip requirements are notoriously difficult to parse right because:

- pip does not have a public API and therefore cannot be reliably used as a
  stable library.

- The pip requirements file syntax is closely aligned with pip's command line
  interface and command line options. In some ways a pip requirements file is a
  list of pip command line arguments. Therefore, it is hard to parse these short
  of reproducing the pip command line options parsing.

This ``pip_requirements`` Python library is yet another pip requirements files
parser, but this time doing it correctly and doing as well as pip does it,
because this is using pip's own code.

The ``pip_requirements`` library offers these key advantages:

- Other requirements parsers typically do not work in all the cases that ``pip``
  supports: parsing any requirement as seen in the wild will fail to process
  some valid pip requirements. Since the ``pip_requirements`` library is based
  on pip's own code, it works **exactly** like pip and will parse all the
  requirements files that pip can parse.

- The ``pip_requirements`` library is a single file that can easily be copied
  around as needed for easy vendoring. This is useful as requirements parsing
  is often needed to bootstrap in a constrained environment.

- The ``pip_requirements`` library has only one external dependency on the
  common "packaging" package. Otherwise it uses only the standard library. The
  benefits are the same as being a single file: fewer moving parts helps with
  using it in more cases.

- The ``pip_requirements`` library reuses and passes the full subset of the pip
  test suite that deals with requirements. This is a not really surprising since
  this is pip's own code. The suite suite has been carefully ported and adjusted
  to work with the updated code subset.

- The standard pip requirements parser depends on the ``requests`` HTTP library
  and makes network connection to PyPI and other referenced repositories when
  parsing. The ``pip_requirements`` libraryworks entirely offline and the
  requests dependency and calling has been entirely removed.

- The ``pip_requirements`` library has preserved the complete pip git history
  for the subset of the code we kept. The original pip code was merged from
  multiple modules keeping all the git history at the line/blame level using
  some git fu and git filter repo. The benefit is that we will be able to more
  easily track and merge future pip updates.
