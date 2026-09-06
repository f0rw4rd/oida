"""
DICOM Protocol Scanner

Scans DICOM (Digital Imaging and Communications in Medicine) endpoints for:
- C-ECHO (DICOM ping/verification)
- C-FIND (query patients, studies, series, images)
- C-GET (retrieve images)
- C-STORE (upload images)
- C-MOVE (transfer images to destination)
- AE Title enumeration and brute force
- TLS/security assessment
- Wildcard search capability testing

CLI examples:
    oida dicom 192.168.1.100              # C-ECHO discovery
    oida dicom 192.168.1.100 --aet PACS   # Specify calling AE Title
    oida dicom 192.168.1.100 --aet-brute  # Brute force AE Titles
    oida dicom 192.168.1.100 --find       # C-FIND enumeration
    oida dicom 192.168.1.100 --find --patient-name "*"  # Wildcard search
    oida dicom 192.168.1.100 --find --query-level STUDY  # Study-level query
    oida dicom 192.168.1.100 --get --study-uid 1.2.3.4  # Retrieve images
    oida dicom 192.168.1.100 --store --store-file img.dcm  # Upload image
    oida dicom 192.168.1.100 --move --study-uid 1.2.3 --dest-aet OTHER  # Transfer
"""

# Re-export NXC-style class and constants from nxc_connection
from .nxc_connection import (
    dicom,
    PYNETDICOM_AVAILABLE,
    PHI_TAGS,
    DEFAULT_AET_WORDLIST,
    DICOM_VENDOR_MAP,
)


# Module-level symbols for unit-test patchability. Tests use
# @patch("oida.protocols.dicom.AE") and friends. unittest.mock.patch's
# get_original() walks __dict__, not __getattr__, so we have to bind
# real attributes here. Use placeholders when pynetdicom isn't
# installed so the patch decorator's lookup succeeds in dev environments
# without the optional dep.
try:
    from pynetdicom import AE  # type: ignore  # noqa: F401
    from pynetdicom.sop_class import Verification  # type: ignore  # noqa: F401
    from pydicom.dataset import Dataset  # type: ignore  # noqa: F401
except ImportError:  # pragma: no cover — optional dep
    AE = None  # type: ignore
    Verification = None  # type: ignore
    Dataset = None  # type: ignore


__all__ = [
    "dicom",
    "PYNETDICOM_AVAILABLE",
    "PHI_TAGS",
    "DEFAULT_AET_WORDLIST",
    "DICOM_VENDOR_MAP",
    "AE",
    "Verification",
    "Dataset",
]
