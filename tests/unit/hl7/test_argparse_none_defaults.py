#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests: argparse None defaults must not reach the wire.

Every ``--rx-*`` / ``--staff-*`` / ``--charge-*`` / ``--transaction-*`` /
``--location`` / ``--obx-*`` flag is declared WITHOUT ``default=``, so argparse
always *sets* the attribute to ``None`` when the flag is absent. Code that read
them as ``getattr(self.args, "rx_units", "mg")`` therefore never got ``"mg"`` --
the getattr fallback was dead and ``None`` flowed into the segment builders,
which either interpolated the literal string ``"None"`` into a field or dropped
the field entirely because ``None`` is falsy.

These tests pin the corrected behaviour: build each message from REAL parsed
args (not a Mock, whose getattr returns a truthy Mock and hides the bug) and
assert the documented defaults actually reach the ER7 output.
"""

import sys
import unittest
from unittest.mock import patch

from tests.unit.hl7.conftest import _make_hl7_instance

BASE_ARGV = ["hl7", "127.0.0.1", "--port", "2575", "-I", "PT001", "--confirm"]


def _parse(extra):
    """Parse argv through the REAL oida parser.

    ``gen_cli_args()`` inspects ``sys.argv`` to decide whether to build full
    per-protocol subparsers or cheap stubs; an argv with a positional forces
    the full build, which is what makes the real ``default=None`` values show up.
    """
    from oida.cli import gen_cli_args

    with patch.object(sys, "argv", ["oida", "zz"]):
        parser = gen_cli_args()
    return parser.parse_args(BASE_ARGV + extra)


def _build(extra, method, *margs):
    scanner = _make_hl7_instance(args=_parse(extra))
    return getattr(scanner, method)(*margs) or ""


class TestNoLiteralNoneOnTheWire(unittest.TestCase):
    """The literal string 'None' must never appear in a generated message."""

    def test_rxo_drug_name_only_has_no_none_drug_code(self):
        """--rx-drug without --rx-code must not emit 'None' as the drug code."""
        er7 = _build(["--send-rx", "--rx-drug", "Amoxicillin"], "_create_rx_message")
        self.assertIn("Amoxicillin", er7)
        self.assertNotIn("None", er7)

    def test_rxo_drug_code_only_has_no_none_drug_name(self):
        """--rx-code without --rx-drug must not emit 'None' as the drug name."""
        er7 = _build(["--send-rx", "--rx-code", "00093"], "_create_rx_message")
        self.assertIn("00093", er7)
        self.assertNotIn("None", er7)


class TestDocumentedDefaultsReachTheWire(unittest.TestCase):
    """Absent value flags must fall back to the documented default, not None."""

    def test_rxo_applies_dose_units_route_quantity_refills(self):
        """RXO carries the documented 10/mg/PO/30/0 defaults."""
        er7 = _build(["--send-rx", "--rx-drug", "Amoxicillin"], "_create_rx_message")
        rxo = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("RXO|")]
        self.assertTrue(rxo, f"no RXO segment in: {er7!r}")
        line = rxo[0]
        for expected in ("10", "mg", "PO", "30"):
            self.assertIn(expected, line, f"{expected!r} missing from {line!r}")

    def test_ras_applies_default_admin_units(self):
        """RXA gets the default 'mg' admin units."""
        er7 = _build(["--send-ras", "--rx-drug", "Morphine"], "_create_ras_message")
        rxa = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("RXA|")]
        self.assertTrue(rxa, f"no RXA segment in: {er7!r}")
        self.assertIn("mg", rxa[0])

    def test_rgv_carries_the_requested_drug(self):
        """--rx-drug reaches RXG-4 (it was previously never forwarded)."""
        er7 = _build(["--send-rgv", "--rx-drug", "Morphine"], "_create_rgv_message")
        rxg = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("RXG|")]
        self.assertTrue(rxg, f"no RXG segment in: {er7!r}")
        self.assertIn("Morphine", rxg[0])

    def test_pcd01_applies_default_location(self):
        """PCD-01 PV1 gets the documented ICU^101^A location."""
        er7 = _build(["--pcd-01"], "_create_pcd01_message")
        self.assertIn("ICU^101^A", er7)

    def test_pcd03_emits_a_body_not_just_msh(self):
        """PCD-03 built a header-only message when rx_units was None."""
        er7 = _build(["--pcd-03", "--rx-drug", "Morphine"], "_create_pcd03_message")
        segments = {ln.split("|", 1)[0] for ln in er7.replace("\r", "\n").split("\n") if "|" in ln}
        self.assertIn("RXG", segments, f"body missing, only got {segments}")
        self.assertIn("Morphine", er7)

    def test_mfn_m02_populates_staff_segment(self):
        """MFN^M02 STF carries the documented staff defaults."""
        er7 = _build(["--send-mfn"], "_create_mfn_message", "M02")
        stf = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("STF|")]
        self.assertTrue(stf, f"no STF segment in: {er7!r}")
        self.assertIn("STF001", stf[0])
        self.assertIn("TEST^STAFF", stf[0])
        self.assertIn("MD", stf[0])

    def test_mfn_m04_populates_charge_segment(self):
        """MFN^M04 PRC was an entirely empty segment."""
        er7 = _build(["--send-mfn"], "_create_mfn_message", "M04")
        prc = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("PRC|")]
        self.assertTrue(prc, f"no PRC segment in: {er7!r}")
        self.assertIn("CHG001", prc[0])
        self.assertIn("100.00", prc[0])

    def test_bar_populates_guarantor_segment(self):
        """BAR GT1 carried only its set-ID before."""
        er7 = _build(["--send-bar"], "_create_bar_message")
        gt1 = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("GT1|")]
        self.assertTrue(gt1, f"no GT1 segment in: {er7!r}")
        self.assertIn("TEST^GUARANTOR", gt1[0])

    def test_dft_populates_transaction_code_and_amount(self):
        """DFT FT1 dropped both the transaction code and the amount."""
        er7 = _build(["--send-dft"], "_create_dft_message")
        ft1 = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("FT1|")]
        self.assertTrue(ft1, f"no FT1 segment in: {er7!r}")
        self.assertIn("99213", ft1[0])
        self.assertIn("100.00", ft1[0])

    def test_oru_obx_applies_default_units(self):
        """--obx-value without --obx-units must still emit the default mg/dL.

        OBX itself is intentionally gated on ``obx_value or obx_id``, so this
        supplies a value; the regression is the *units* field, which used to be
        None because the getattr fallback was dead.
        """
        er7 = _build(
            ["--send-oru", "--obx-value", "7.2"],
            "_create_message_with_segments",
            "ORU",
            "R01",
        )
        obx = [ln for ln in er7.replace("\r", "\n").split("\n") if ln.startswith("OBX|")]
        self.assertTrue(obx, f"no OBX segment in: {er7!r}")
        self.assertIn("7.2", obx[0])
        self.assertIn("mg/dL", obx[0])
        self.assertNotIn("None", obx[0])


if __name__ == "__main__":
    unittest.main()
