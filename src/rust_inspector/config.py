# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/rust-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


# Symbols are often surrounded by these character/char sequences after demangling
# For example:
# core::ptr::drop_in_place<core::result::Result<cyclonedx_bom::specs::v1_5::formulation::Formula,serde_json::error::Error>>
# We need to split by these characters to get individual symbol strings for matching
SPLIT_CHARACTERS_RUST = ["::", "_<", "<", ">", "(", ")", ",", " as ", " for "]


# Standard symbols present in rust binaries which are not usually from rust
# source files, and sometimes they are standard library symbols
STANDARD_SYMBOLS_RUST = [
    "std",
    "vector",
]
