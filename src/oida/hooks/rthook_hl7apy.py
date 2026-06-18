# PyInstaller runtime hook for hl7apy
# hl7apy._discover_libraries() uses os.listdir() on its package dir
# which fails in one-file PyInstaller bundles. Patch with known values.

import os
import sys

if getattr(sys, "frozen", False):
    _meipass = getattr(sys, "_MEIPASS", None)
    if _meipass:
        hl7apy_dir = os.path.join(_meipass, "hl7apy")
        # Create v2_* directories so os.listdir() finds them
        _versions = [
            "v2_1",
            "v2_2",
            "v2_3",
            "v2_3_1",
            "v2_4",
            "v2_5",
            "v2_5_1",
            "v2_6",
            "v2_7",
            "v2_8",
            "v2_8_1",
            "v2_8_2",
        ]
        for v in _versions:
            d = os.path.join(hl7apy_dir, v)
            os.makedirs(d, exist_ok=True)
