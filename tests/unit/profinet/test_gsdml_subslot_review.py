"""Regression test: GSDML SubslotNumber must accept hex form.

GSDML files in the wild encode SubslotNumber either decimally (32768) or
hexadecimally (0x8000 — the standard interface subslot). VendorID, DeviceID
and record Index attributes are all parsed with _parse_hex(); SubslotNumber
was parsed with bare int(), which raises ValueError on "0x8000". That
exception escapes to the parse_gsdml catch-all, so the ENTIRE GSDML
(vendor/device IDs, all modules, all record indices) is silently discarded
and --gsdml degrades to "file ignored" with only a debug log.

The code under test is never monkey-patched.
"""

import unittest

from oida.protocols.profinet.gsdml_parser import parse_gsdml

_HEX_SUBSLOT_GSDML = """<?xml version="1.0" encoding="UTF-8"?>
<ISO15745Profile xmlns="http://www.profibus.com/GSDML/2003/11/DeviceProfile">
  <ProfileHeader>
    <ProfileIdentification>UTOOL</ProfileIdentification>
    <ProfileRevision>1.00</ProfileRevision>
    <ProfileName>Test</ProfileName>
    <ProfileSource>oida</ProfileSource>
    <ProfileClassID>Device</ProfileClassID>
  </ProfileHeader>
  <ProfileBody>
    <DeviceIdentity VendorID="0x00FE" DeviceID="0x0102">
      <VendorName Value="Test Vendor"/>
    </DeviceIdentity>
    <DeviceFunction>
      <Family MainFamily="I/O" ProductFamily="test"/>
    </DeviceFunction>
    <ApplicationProcess>
      <DeviceAccessPointItem ID="DAP 1" ModuleIdent="0x00000001" SubslotNumber="1" AutoConfigure="true">
        <ModuleInfo>
          <Name TextId="T_DAP"/>
        </ModuleInfo>
        <VirtualSubmoduleItem ID="1" SubslotNumber="1" Fixed="true">
          <RecordDataList/>
        </VirtualSubmoduleItem>
        <InterfaceList>
          <SubslotItem SubslotNumber="0x8000" TextId="T_IF"/>
          <SubslotItem SubslotNumber="0x8001" TextId="T_P1"/>
        </InterfaceList>
      </DeviceAccessPointItem>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"""


class TestGsdmlHexSubslotNumber(unittest.TestCase):
    def test_hex_subslot_number_does_not_abort_parse(self):
        import io

        device = parse_gsdml(io.StringIO(_HEX_SUBSLOT_GSDML))
        self.assertIsNotNone(device, "GSDML with hex SubslotNumber must still parse")

    def test_hex_subslot_number_resolved(self):
        import io

        device = parse_gsdml(io.StringIO(_HEX_SUBSLOT_GSDML))
        subslots = [s.subslot for s in device.dap_submodules]
        # One VirtualSubmoduleItem in the fixture -> the first SubslotItem (the
        # 0x8000 interface subslot) is bound to it. The positional mapping of
        # additional SubslotItems is a separate, pre-existing limitation.
        self.assertIn(
            0x8000,
            subslots,
            f"interface subslot 0x8000 must be resolved; got {subslots}",
        )

    def test_vendor_device_ids_still_parsed(self):
        import io

        device = parse_gsdml(io.StringIO(_HEX_SUBSLOT_GSDML))
        self.assertEqual(device.vendor_id, 0x00FE)
        self.assertEqual(device.device_id, 0x0102)


if __name__ == "__main__":
    unittest.main()
