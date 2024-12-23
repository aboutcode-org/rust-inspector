# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/rust-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging

import attr
from commoncode.cliutils import SCAN_GROUP
from commoncode.cliutils import PluggableCommandLineOption
from plugincode.scan import ScanPlugin
from plugincode.scan import scan_impl

from rust_inspector.binary import collect_and_parse_rust_symbols

"""
Extract symbols information from Rust binaries.
"""
logger = logging.getLogger(__name__)


@scan_impl
class RustSymbolScannerPlugin(ScanPlugin):
    """
    Scan a Rust binary for symbols using blint, lief and symbolic.
    """

    resource_attributes = dict(
        rust_symbols=attr.ib(default=attr.Factory(dict), repr=False),
    )

    options = [
        PluggableCommandLineOption(
            ("--rust-symbol",),
            is_flag=True,
            default=False,
            help="Collect Rust symbols from rust binaries.",
            help_group=SCAN_GROUP,
            sort_order=100,
        ),
    ]

    def is_enabled(self, rust_symbol, **kwargs):
        return rust_symbol

    def get_scanner(self, **kwargs):
        return collect_and_parse_rust_symbols
