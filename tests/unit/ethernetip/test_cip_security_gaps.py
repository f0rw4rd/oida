#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP CipSecurityMixin coverage gaps not exercised by
test_cip_security_mixin.py:

- _dump_security_lightweight: reads only 0x5D + 0x5E, never the heavy
  Certificate Management / Password Authenticator dumps; conn guards.
- _download_certificate_instance: state/type/format parsing, raw cert
  base64 + size, X.509 parse hook, not-accessible -> None.
- _parse_certificate_info: real DER cert -> subject/issuer/serial/validity,
  self-signed detection, parse error path.
"""

import base64
import datetime
import struct
import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.cip_security import CipSecurityMixin


class MockSecurityHost(CipSecurityMixin):
    def __init__(self):
        self.logger = MagicMock()
        self.debug = False
        self._attr_responses = {}

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        return self._attr_responses.get((class_id, instance, attr_id))

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data


def _make_der_cert(self_signed=True):
    """Build a small self-signed X.509 certificate in DER bytes."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "plc.example.com")])
    issuer = (
        subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


# =============================================================================
# _dump_security_lightweight
# =============================================================================


class TestDumpSecurityLightweight(unittest.TestCase):
    def setUp(self):
        self.host = MockSecurityHost()

    def test_missing_conn(self):
        result = self.host._dump_security_lightweight(None)
        self.assertEqual(result["cip_security"], None)
        self.assertEqual(result["certificates"], None)

    def test_conn_without_generic_message(self):
        result = self.host._dump_security_lightweight(object())
        self.assertEqual(result["cip_security"], None)

    def test_only_reads_5d_and_5e(self):
        conn = MagicMock()
        # CIP Security (0x5D) configured, EIP Security (0x5E) present
        self.host.set_attr(0x5D, 1, 1, b"\x02")  # state Configured
        self.host.set_attr(0x5E, 1, 1, b"\x01")  # state Configured

        # Spy so we can prove heavy dumps are NOT called
        self.host._dump_certificate_management = MagicMock(return_value={"x": 1})
        self.host._dump_password_authenticator = MagicMock(return_value={"y": 1})

        result = self.host._dump_security_lightweight(conn)

        self.assertIsNotNone(result["cip_security"])
        self.assertEqual(result["cip_security"]["state"], "Configured")
        self.assertIsNotNone(result["eip_security"])
        # heavy reads deliberately skipped
        self.assertIsNone(result["certificates"])
        self.assertIsNone(result["password_auth"])
        self.host._dump_certificate_management.assert_not_called()
        self.host._dump_password_authenticator.assert_not_called()

    def test_objects_absent(self):
        conn = MagicMock()
        # nothing set -> both dump_*_object return None
        result = self.host._dump_security_lightweight(conn)
        self.assertIsNone(result["cip_security"])
        self.assertIsNone(result["eip_security"])


# =============================================================================
# _download_certificate_instance
# =============================================================================


class TestDownloadCertificateInstance(unittest.TestCase):
    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        # state attr (0x5F, inst, 1) returns None
        self.assertIsNone(self.host._download_certificate_instance(self.conn, 2))

    def test_state_type_format_parsed(self):
        self.host.set_attr(0x5F, 1, 1, b"\x01")  # state
        self.host.set_attr(0x5F, 1, 2, b"\x01")  # device type -> CA/Trust Anchor
        self.host.set_attr(0x5F, 1, 3, b"\x01")  # format -> DER
        info = self.host._download_certificate_instance(self.conn, 1)
        self.assertEqual(info["state"], 1)
        self.assertEqual(info["type"], "CA/Trust Anchor")
        self.assertEqual(info["format"], "DER")

    def test_raw_cert_base64_and_parse(self):
        der = _make_der_cert(self_signed=True)
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        # Attr 4: 2-byte array length prefix + cert bytes
        cert_attr = struct.pack("<H", len(der)) + der
        self.host.set_attr(0x5F, 1, 4, cert_attr)

        info = self.host._download_certificate_instance(self.conn, 1)
        self.assertEqual(info["raw_size"], len(der))
        self.assertEqual(base64.b64decode(info["raw"]), der)
        # parse hook populated subject/issuer
        self.assertIn("subject", info)
        self.assertIn("plc.example.com", info["subject"])
        self.assertTrue(info["self_signed"])

    def test_unknown_device_type(self):
        self.host.set_attr(0x5F, 1, 1, b"\x00")
        self.host.set_attr(0x5F, 1, 2, b"\x09")  # not in {0,1,2}
        info = self.host._download_certificate_instance(self.conn, 1)
        self.assertIn("Unknown", info["type"])


# =============================================================================
# _parse_certificate_info
# =============================================================================


class TestParseCertificateInfo(unittest.TestCase):
    def setUp(self):
        self.host = MockSecurityHost()

    def test_self_signed_der(self):
        der = _make_der_cert(self_signed=True)
        info = {}
        self.host._parse_certificate_info(info, der)
        self.assertIn("plc.example.com", info["subject"])
        self.assertEqual(info["subject"], info["issuer"])
        self.assertTrue(info["self_signed"])
        self.assertEqual(info["serial"], format(0x1234ABCD, "x"))
        self.assertIn("not_before", info)
        self.assertIn("not_after", info)

    def test_ca_signed_not_self_signed(self):
        der = _make_der_cert(self_signed=False)
        info = {}
        self.host._parse_certificate_info(info, der)
        self.assertFalse(info["self_signed"])
        self.assertNotEqual(info["subject"], info["issuer"])

    def test_garbage_records_parse_error(self):
        info = {}
        self.host._parse_certificate_info(info, b"not a certificate at all")
        self.assertIn("parse_error", info)
        self.assertNotIn("subject", info)


if __name__ == "__main__":
    unittest.main()
