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

import lief
import pytest
from commoncode.testcase import FileDrivenTesting
from scancode.cli_test_utils import check_json
from scancode_config import REGEN_TEST_FIXTURES

from rust_inspector import binary
from rust_inspector.blint_binary import parse_symbols

test_env = FileDrivenTesting()
test_env.test_data_dir = os.path.join(os.path.dirname(__file__), "data")


def test_is_executable_binary():
    rust_binary = test_env.get_test_loc("binary-with-deps/cargo_dependencies")
    assert binary.is_executable_binary(rust_binary)


def test_parse_rust_binary_does_not_fail():
    go_binary = test_env.get_test_loc("binary-with-deps/cargo_dependencies")
    binary.parse_rust_binary(go_binary)


def test_parsed_rust_binary_has_symbols():
    go_binary = test_env.get_test_loc("binary-with-deps/cargo_dependencies")
    parsed_binary = binary.parse_rust_binary(go_binary)
    assert parsed_binary.symtab_symbols


def test_can_parse_and_demangle_rust_binary_symbols():
    go_binary = test_env.get_test_loc("binary-with-deps/cargo_dependencies")
    parsed_binary = binary.parse_rust_binary(go_binary)
    parsed_rust_symbols = parse_symbols(parsed_binary.symtab_symbols)
    expected = test_env.get_test_loc("binary-with-deps/cargo_dependencies-symbols.json")
    check_json(expected, parsed_rust_symbols, regen=REGEN_TEST_FIXTURES)


def test_get_rust_packages_data():
    go_binary = test_env.get_test_loc("binary-with-deps/cargo_dependencies")
    rust_packages_data = binary.get_rust_packages_data(go_binary)
    expected = test_env.get_test_loc("binary-with-deps/cargo_dependencies-packages.json")
    check_json(expected, rust_packages_data, regen=REGEN_TEST_FIXTURES)


def test_can_parse_and_demangle_rust_binary_symbols_large():
    go_binary = test_env.get_test_loc("trustier/trustier")
    parsed_binary = binary.parse_rust_binary(go_binary)
    parsed_rust_symbols = parse_symbols(parsed_binary.symtab_symbols)
    expected = test_env.get_test_loc("trustier/trustier-symbols.json")
    check_json(expected, parsed_rust_symbols, regen=REGEN_TEST_FIXTURES)


def test_get_rust_packages_data_large():
    go_binary = test_env.get_test_loc("trustier/trustier")
    rust_packages_data = binary.get_rust_packages_data(go_binary)
    expected = test_env.get_test_loc("trustier/trustier-packages.json")
    check_json(expected, rust_packages_data, regen=REGEN_TEST_FIXTURES)


@pytest.mark.parametrize(
    "split_strings,split_char,expected_split_strings",
    [
        (
            ["core::ptr::drop_in_place<cyclonedx_bom::specs::common::bom::v1_5::Bom>"],
            "::",
            [
                "core",
                "ptr",
                "drop_in_place<cyclonedx_bom",
                "specs",
                "common",
                "bom",
                "v1_5",
                "Bom>",
            ],
        ),
    ],
)
def test_split_strings_by_char(split_strings, split_char, expected_split_strings):
    final_split_strings = binary.split_strings_by_char(split_strings, split_char)
    assert final_split_strings == expected_split_strings


@pytest.mark.parametrize(
    "strings_to_split,expected_split_strings",
    [
        (
            ["core::ptr::drop_in_place<cyclonedx_bom::specs::common::bom::v1_5::Bom>"],
            [
                "core",
                "ptr",
                "drop_in_place",
                "cyclonedx_bom",
                "specs",
                "common",
                "bom",
                "v1_5",
                "Bom",
            ],
        ),
    ],
)
def test_split_strings_into_rust_symbols(strings_to_split, expected_split_strings):
    final_split_strings = binary.split_strings_into_rust_symbols(strings_to_split)
    assert final_split_strings == expected_split_strings


@pytest.mark.parametrize(
    "strings_to_split,symbols",
    [
        (
            ["async_io::reactor::Reactor::process_timers::__CALLSITE::META"],
            ["async_io", "reactor", "Reactor", "process_timers"],
        ),
    ],
)
def test_split_strings_into_cleaned_rust_symbols(strings_to_split, symbols):
    final_split_strings = binary.split_strings_into_rust_symbols(strings_to_split)
    rust_symbols = binary.cleanup_symbols(final_split_strings, unique=False)
    assert rust_symbols == symbols


def test_might_have_rust_symbols():
    strings_with_symbols = ["async_io::reactor::Reactor::process_timers::__CALLSITE::META"]
    final_split_strings = binary.split_strings_into_rust_symbols(strings_with_symbols)
    assert (
        sum([binary.might_have_rust_symbols(split_string) for split_string in final_split_strings])
        == 4
    )


def test_extract_strings_with_symbols():
    symbols_data_file = test_env.get_test_loc("binary-with-deps/cargo_dependencies-symbols.json")
    with open(symbols_data_file) as res:
        rust_symbols_data = json.load(res)

    extracted_symbols = binary.extract_strings_with_symbols(
        symbols_data=rust_symbols_data, sort_symbols=True
    )
    expected = test_env.get_test_loc("binary-with-deps/cargo_dependencies-symbols-cleaned.json")
    check_json(expected, extracted_symbols, regen=REGEN_TEST_FIXTURES)


def test_extract_strings_with_symbols_large():
    symbols_data_file = test_env.get_test_loc("trustier/trustier-symbols.json")
    with open(symbols_data_file) as res:
        rust_symbols_data = json.load(res)

    extracted_symbols = binary.extract_strings_with_symbols(
        symbols_data=rust_symbols_data, sort_symbols=True
    )
    expected = test_env.get_test_loc("trustier/trustier-symbols-cleaned.json")
    check_json(expected, extracted_symbols, regen=REGEN_TEST_FIXTURES)
