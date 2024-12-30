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
import zlib

import lief
from typecode import contenttype
from typecode.contenttype import get_type

from rust_inspector.blint_binary import parse_symbols
from rust_inspector.config import SPLIT_CHARACTERS_RUST
from rust_inspector.config import STANDARD_SYMBOLS_RUST


def is_macho(location):
    """
    Return True if the file at ``location`` is in macOS/Darwin's Mach-O format, otherwise False.
    """
    t = get_type(location)
    return t.filetype_file.lower().startswith("mach-o") or t.mimetype_file.lower().startswith(
        "application/x-mach-binary"
    )


def is_executable_binary(location):
    """
    Return True if the file at ``location`` is an executable binary.
    """
    if not os.path.exists(location):
        return False

    if not os.path.isfile(location):
        return False

    typ = contenttype.Type(location)

    if not (typ.is_elf or typ.is_winexe or is_macho(location=location)):
        return False

    return True


def parse_rust_binary(location):
    """
    Get a parsed lief._lief.ELF.Binary object from parsing the Rust binary
    present at `location`.
    """
    return lief.parse(location)


def get_rust_packages_data(location):
    """
    Given a rust binary present at location, parse and return packages
    data present in the binary.

    This get packages data only if it is present in the rust binary, i.e.
    if the rust binary was built using `cargo-auditable` which adds a section
    to the rust binary with data on packages and dependencies.
    See https://github.com/rust-secure-code/cargo-auditable for more info.

    Code for parsing rust binaries to get package data is from
    https://github.com/rust-secure-code/cargo-auditable/blob/master/PARSING.md
    """
    if not is_executable_binary(location):
        return

    parsed_binary = parse_rust_binary(location)

    section_deps = None
    for section in parsed_binary.sections:
        if section.name == ".dep-v0":
            section_deps = section
            break

    decompressed_data = zlib.decompress(section_deps.content)
    packages_data = json.loads(decompressed_data)

    return packages_data


def might_have_rust_symbols(string_with_symbols):
    """
    Given a demangled symbol string obtained from a rust binary, return True if
    there are rust symbols present in the string which could be mapped to rust
    source symbols potentially, return False otherwise.
    """
    if not string_with_symbols:
        return False

    if not len(string_with_symbols) > 1:
        return False

    # Commonly encountered strings which are not rust symbols
    ignore_strings = ["GCC_except_table", "anonymous", "SAFESEH"]
    if string_with_symbols in ignore_strings:
        return False

    # We have sometimes strings which are all uppercase alphabets, these are
    # usually not symbols?
    # Examples: `__CALLSITE::META`, `tracing_core::dispatcher::NO_SUBSCRIBER`,
    # `encoding_rs::SHIFT_JIS_INIT::hd4a3d8ee69a4c88a` etc
    string_without_underscore = string_with_symbols.replace("_", "")
    is_all_uppercase = string_without_underscore.isupper() and string_without_underscore.isalpha()
    if is_all_uppercase:
        return False

    # fully numberic strings are not rust symbols
    if string_with_symbols.isnumeric():
        return False

    # TODO: also filter checksum like values (entropy/randomness?)
    # TODO: also filter Uppercase Alphabets + Numbers
    # Example: encoding_rs::UTF_16LE_INIT::h47f34b513cc70084

    return True


def remove_standard_symbols(rust_symbols, standard_symbols=STANDARD_SYMBOLS_RUST):
    """
    Remove standard symbols usually found in rust binaries. Given a list of rust
    symbol strings, return a list of symbol strings which are most likely non-standard.
    """
    return [symbol for symbol in rust_symbols if symbol not in standard_symbols]


def split_strings_by_char(split_strings, split_char):
    """
    Given a list of strings, return another list of strings with all
    the substrings from each string, split by the `split_char`.
    """
    final_split_strings = []
    for split_str in split_strings:
        if split_char in split_str:
            split_strings = split_str.split(split_char)
            final_split_strings.extend(split_strings)
        else:
            final_split_strings.append(split_str)

    return [split_string for split_string in final_split_strings if split_string]


def split_strings_into_rust_symbols(strings_to_split, split_by_chars=SPLIT_CHARACTERS_RUST):
    """
    Given a list of strings containing a group of rust symbols, get a list
    of strings with the extracted individual symbol strings, using a list of
    `split_by_chars` which are common characters found between rust symbols in
    demangled rust string containing multiple symbols.
    """
    split_strings = []
    split_strings_log = []
    for split_char in split_by_chars:
        if not split_strings:
            split_strings = strings_to_split

        split_strings = split_strings_by_char(split_strings, split_char)
        split_strings_log.append(split_strings)

    return split_strings


def cleanup_symbols(symbols, include_stdlib=False, unique=True, sort_symbols=False):
    """
    Given a list of `symbols` strings, return a list of cleaned up
    symbol strings, removing strings which does not have symbols.

    If `include_stdlib` is False, remove standard rust symbols.
    If `unique` is True, only return unique symbol strings.
    If `sort_symbols` is True, return a sorted list of symbols.
    """
    rust_symbols = []
    for split_string in symbols:
        if might_have_rust_symbols(split_string):
            rust_symbols.append(split_string)

    if not include_stdlib:
        rust_symbols = remove_standard_symbols(rust_symbols)

    if unique:
        rust_symbols = list(set(rust_symbols))

    if sort_symbols:
        rust_symbols = sorted(rust_symbols)

    return rust_symbols


def extract_strings_with_symbols(
    symbols_data, include_stdlib=False, unique=True, sort_symbols=False
):
    """
    From a list of rust symbols data parsed and demangled from a binary,
    return a list of individual symbols (after cleanup) found in the strings.
    """
    strings_with_symbols = []

    ignore_types = ["NOTYPE", "TLS"]

    for symbol_data in symbols_data:

        if not symbol_data.get("name"):
            continue

        if symbol_data.get("type") in ignore_types:
            continue

        # These are usually like the following:
        # - memcpy@GLIBC_2.14
        # - UI_method_set_writer@OPENSSL_3.0.0
        # So these doesn't have source symbols
        if symbol_data.get("is_imported"):
            continue

        # These are usually like the following:
        # `getrandom@GLIBC_2.25`, `__umodti3`, `_ITM_registerTMCloneTable`
        # So these doesn't have source symbols
        if symbol_data.get("binding") == "WEAK":
            continue

        # file/module names are also source symbols as they
        # are imported in source code files
        if symbol_data.get("type") == "FILE":
            file_string = symbol_data.get("name")
            file_segments = file_string.split(".")
            if not file_segments:
                continue

            # These are usually like following:
            # cyclonedx_bom.4f845c900a9ac4e1-cgu.11
            # only the first part are symbols
            filename = file_segments[0]
            strings_with_symbols.append(filename)

        # Symbols which are Objects and Functions by type are collections of
        # rust symbols and misc strings
        if symbol_data.get("type") in ["OBJECT", "FUNC"]:
            file_string = symbol_data.get("name")
            strings_with_symbols.append(file_string)

    split_symbols = split_strings_into_rust_symbols(strings_to_split=strings_with_symbols)
    rust_symbols = cleanup_symbols(
        symbols=split_symbols,
        include_stdlib=include_stdlib,
        unique=unique,
        sort_symbols=sort_symbols,
    )

    return rust_symbols


def collect_and_parse_rust_symbols(location, include_stdlib=False, sort_symbols=True, **kwargs):
    """
    Return a mapping of Rust symbols of interest for the Rust binary file at ``location``.
    Return an empty mapping if there is no symbols or if this is not a binary.
    """
    if not is_executable_binary(location):
        return

    rust_data = parse_rust_binary(location=location)
    return collect_and_parse_rust_symbols_from_data(
        rust_data=rust_data,
        include_stdlib=include_stdlib,
        unique=True,
        sort_symbols=sort_symbols,
    )


def collect_and_parse_rust_symbols_from_data(
    rust_data, include_stdlib=False, unique=True, sort_symbols=False, **kwargs
):
    """
    Return a mapping of Rust symbols of interest for the mapping of Rust binary of ``rust_data``.
    Return an empty mapping if there is no symbols or if this is not a binary.
    """
    if not rust_data:
        return {}

    # Extract and demangle symbol strings from rust binary parsed object
    # These are collections of symbol and module strings with stdlib objects
    extracted_symbols = parse_symbols(rust_data.symtab_symbols)

    # Cleanup and get individual symbols which could be rust symbols
    symbol_strings = extract_strings_with_symbols(
        symbols_data=extracted_symbols,
        include_stdlib=include_stdlib,
        unique=unique,
        sort_symbols=sort_symbols,
    )

    return dict(rust_symbols=symbol_strings)
