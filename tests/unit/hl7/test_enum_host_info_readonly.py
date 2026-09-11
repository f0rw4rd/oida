"""enum_host_info() runs on EVERY `oida hl7 <ip>` scan (no flag guards it).
It must therefore only ever transmit a READ-ONLY query, never an ADT
admission or any other state-mutating write.

Regression: enum_host_info used to send ADT^A01, silently creating a fake
patient admission in the target EMR on every scan.
"""

import unittest
from unittest.mock import MagicMock

from tests.unit.hl7.conftest import _make_hl7_instance

# HL7 message types that are read-only queries. Everything else (ADT, ORM,
# RDE/RAS, BAR/DFT, MFN, ...) mutates server state.
READ_ONLY_TYPES = {"QBP", "QRY"}


def _msh9_type(er7_message: str) -> str:
    """Return the MSH-9 message-type code (before the ^) of an ER7 message."""
    msh = er7_message.replace("\n", "\r").split("\r")[0]
    fields = msh.split("|")
    return fields[8].split("^")[0]  # MSH-9, type before trigger


class TestEnumHostInfoReadOnly(unittest.TestCase):
    def test_enum_host_info_sends_only_read_only_query(self):
        args = MagicMock()
        args.tls = True  # suppress the cleartext-PHI finding branch
        scanner = _make_hl7_instance(args, None, "127.0.0.1")
        scanner.logger = MagicMock()

        sent = []
        # Capture the outbound message instead of hitting the wire.
        scanner._send_mllp_message = lambda msg: sent.append(msg) or None

        scanner.enum_host_info()

        self.assertTrue(sent, "enum_host_info() sent nothing to inspect")
        for msg in sent:
            self.assertIn(
                _msh9_type(msg),
                READ_ONLY_TYPES,
                f"enum_host_info transmitted a non-read-only message on a bare scan: {msg!r}",
            )


if __name__ == "__main__":
    unittest.main()
