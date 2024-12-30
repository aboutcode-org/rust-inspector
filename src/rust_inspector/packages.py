# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/rust-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from packageurl import PackageURL

from rust_inspector.binary import get_rust_packages_data
from rust_inspector.binary import is_executable_binary

"""
Extract packages information from Rust binaries using Lief.
This gets packages from binaries which are built using `cargo-auditable`.
See https://github.com/rust-secure-code/cargo-auditable for more info
on `cargo-auditable`.
"""


def collect_rust_packages(location, package_only=False, **kwargs):
    """
    Yield cargo PackageData found in the Rust binary file at ``location``.
    """
    binary_data = get_rust_packages_data(location=location)
    yield from collect_rust_packages_from_data(
        binary_data=binary_data,
        package_only=package_only,
        location=location,
    )


def collect_rust_packages_from_data(binary_data, package_only=False, **kwargs):
    """
    Yield all the cargo PackageData with their dependencies found in the Rust binary file
    from ``binary_data`` present in a rust binary.

    The data has this shape::
        {
            "name": "cargo_dependencies",
            "version": "0.1.0",
            "source": "local",
            "dependencies": [
                1,
                6,
                10
            ],
            "root": true
        },
        {
            "name": "kernel32-sys",
            "version": "0.2.2",
            "source": "crates.io",
            "dependencies": [
                12,
                13
            ]
        },
    """

    packages_data = binary_data.get("packages")
    if not packages_data:
        return

    packages_by_index = {}
    for i, package_data in enumerate(packages_data):
        if package_data.get("root", False):
            continue

        dependency = get_dependent_package(package_data)
        packages_by_index[i] = dependency

    for package_data in packages_data:
        yield from get_rust_package_from_data(
            package_data=package_data,
            packages_by_index=packages_by_index,
            package_only=package_only,
        )


def get_rust_package_from_data(package_data, packages_by_index, package_only=False):
    """
    Yield a PackageData with it's dependencies from a data mapping `package_data`
    containing package and dependencies information for a single cargo package.

    `packages_by_index` is a mapping of DependentPackage objects by their index in
    the list of packages present in the rust binary.
    """
    from packagedcode.models import PackageData

    name = package_data.get("name")
    version = package_data.get("version")

    repository_homepage_url = None
    repository_download_url = None
    api_data_url = None
    is_private = False

    if package_data.get("source") == "local":
        is_private = True

    elif package_data.get("source") == "crates.io":
        repository_homepage_url = name and f"https://crates.io/crates/{name}"
        repository_download_url = (
            name and version and f"https://crates.io/api/v1/crates/{name}/{version}/download"
        )
        api_data_url = name and f"https://crates.io/api/v1/crates/{name}"

    dependencies = []
    for dependency_index in package_data.get("dependencies", []):
        dependencies.append(packages_by_index[dependency_index])

    package_data = dict(
        datasource_id="rust_binary",
        type="cargo",
        name=name,
        version=version,
        primary_language="Rust",
        is_private=is_private,
        repository_homepage_url=repository_homepage_url,
        repository_download_url=repository_download_url,
        api_data_url=api_data_url,
        dependencies=dependencies,
    )
    yield PackageData.from_data(package_data, package_only)


def get_dependent_package(package_data):
    """
    Get a DependentPackage object from a cargo `package_data` mapping.
    """
    from packagedcode.models import DependentPackage

    name = package_data.get("name")
    version = package_data.get("version")

    return DependentPackage(
        purl=PackageURL(
            type="cargo",
            name=name,
            version=version,
        ).to_string(),
        scope="build-dependencies",
        is_runtime=True,
        is_optional=False,
        is_pinned=True,
    )


def get_rust_binary_handler():
    """
    Return `RustBinaryHandler` class to parse and get packages information from
    rust binary files.
    """
    from packagedcode import models

    class RustBinaryHandler(models.DatafileHandler):
        """
        ScanCode handler for Rust binary. We use the standard assemble
        AND this is "activated" with a conditional import in
        ScanCode Toolkit packagedcode.__init__.py
        """

        datasource_id = "rust_binary"
        # filetypes = tuple()
        default_package_type = "cargo"
        default_primary_language = "Rust"
        description = "Rust binary"
        documentation_url = (
            "https://github.com/rust-secure-code/cargo-auditable/blob/master/PARSING.md"
        )

        @classmethod
        def is_datafile(cls, location):
            return is_executable_binary(location)

        @classmethod
        def parse(cls, location, package_only=False):
            """
            Yield Rust cargo PackageData objects given a package data file at
            ``location``.
            """
            yield from collect_rust_packages(location, package_only)

    return RustBinaryHandler
