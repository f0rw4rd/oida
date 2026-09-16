#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TASE.2/ICCP Protocol Module

NXC-style module for TASE.2/ICCP protocol security testing.
TASE.2 is used for inter-control center communications in the electric
utility industry.

Usage:
    oida tase2 192.168.1.100
    oida tase2 192.168.1.100 --enumerate-points
    oida tase2 192.168.1.100 --test-rbe --test-control
"""

from ...utils.lazy_import import lazy_import

from .scanner import TASE2Scanner
from .cli_runner import tase2

_pyiec61850_tase2 = lazy_import(
    "pyiec61850.tase2", "TASE.2", install_hint="pip install oida-ics[tase2]"
)

__all__ = ["tase2", "TASE2Scanner"]
