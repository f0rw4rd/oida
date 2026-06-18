#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File-over-EtherCAT (FoE) Shared Data

Pure data module — no transport dependencies (no pysoem, no pyads).
Used by both the EtherCAT (pysoem) and ADS (pyads) scanners.

License: AGPL-3.0-or-later
"""

from typing import List

# ---------------------------------------------------------------------------
# Common FoE filenames for probing — ETG.1000 / vendor-specific
# ---------------------------------------------------------------------------

FOE_COMMON_FILENAMES: List[str] = [
    # Generic firmware/boot files
    "firmware.bin",
    "firmware.efw",
    "firmware.hex",
    "bootloader.bin",
    "bootdata",
    "fwupdate.bin",
    # Configuration
    "config.xml",
    "config.bin",
    "config.dat",
    "startup.bin",
    "startup.xml",
    "param.bin",
    "param.dat",
    # EtherCAT standard
    "esi.xml",
    # Safety/diagnostic (from pcap analysis)
    "systrace",
    # Certificates/licenses
    "license.dat",
    "license.xml",
    "certificate.pem",
    "certificate.der",
    # Application images
    "app.bin",
    "application.bin",
]
