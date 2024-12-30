# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/rust-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import json
import os

from commoncode.testcase import FileDrivenTesting
from scancode.cli_test_utils import check_json
from scancode_config import REGEN_TEST_FIXTURES

from rust_inspector import packages

test_env = FileDrivenTesting()
test_env.test_data_dir = os.path.join(os.path.dirname(__file__), "data")


def test_can_collect_rust_packages_from_data():
    packages_data_file = test_env.get_test_loc("binary-with-deps/cargo_dependencies-packages.json")
    with open(packages_data_file) as res:
        rust_packages_data = json.load(res)

    parsed_packages = [
        package.to_dict()
        for package in packages.collect_rust_packages_from_data(rust_packages_data)
    ]
    expected = test_env.get_test_loc("binary-with-deps/cargo_dependencies-scancode-packages.json")
    check_json(expected, parsed_packages, regen=REGEN_TEST_FIXTURES)
