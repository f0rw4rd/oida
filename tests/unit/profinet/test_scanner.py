"""Tests for profinet protocol scanner."""

import pytest
from unittest.mock import MagicMock


class TestProfinetImport:
    """Test profinet module can be imported."""

    def test_import_profinet_module(self):
        """Test importing profinet module."""
        from oida.protocols import profinet

        assert profinet is not None

    def test_import_profinet_device(self):
        """Test importing ProfinetDevice dataclass."""
        from oida.protocols.profinet import ProfinetDevice

        assert ProfinetDevice is not None

    def test_import_profinet_class(self):
        """Test importing profinet connection class."""
        from oida.protocols.profinet import profinet as ProfinetConnection

        assert ProfinetConnection is not None


class TestProfinetDevice:
    """Test ProfinetDevice dataclass."""

    def test_device_creation(self):
        """Test creating a ProfinetDevice."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            name_of_station="test-device",
            ip_address="192.168.1.100",
            device_type="S7-1200",
            vendor_id=0x002A,
            device_id=0x010D,
        )

        assert device.name_of_station == "test-device"
        assert device.ip_address == "192.168.1.100"
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.device_type == "S7-1200"
        assert device.vendor_id == 0x002A
        assert device.device_id == 0x010D

    def test_device_defaults(self):
        """Test ProfinetDevice default values."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")

        assert device.name_of_station == ""
        assert device.ip_address == ""
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.device_type == ""
        assert device.vendor_id == 0
        assert device.device_id == 0
        assert device.device_roles == []
        assert device.device_instance == (0, 0)
        assert device.alias_name == ""

    def test_device_with_roles(self):
        """Test ProfinetDevice with device roles."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            name_of_station="controller",
            device_roles=["IO-Controller", "PN-Supervisor"],
        )

        assert "IO-Controller" in device.device_roles
        assert "PN-Supervisor" in device.device_roles

    def test_device_with_instance(self):
        """Test ProfinetDevice with device instance."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            name_of_station="plc",
            device_instance=(0, 100),
        )

        assert device.device_instance == (0, 100)


class TestProfinetProtoArgs:
    """Test profinet protocol arguments."""

    def test_proto_args_function(self):
        """Test proto_args function exists."""
        from oida.protocols.profinet.proto_args import proto_args
        import argparse

        # Create main parser with subparsers
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)

        # Register profinet subparser
        proto_args(subparsers, [parent])

        # Parse with profinet subcommand
        args = main_parser.parse_args(["profinet", "eth0"])

        assert hasattr(args, "target")
        assert args.target == "eth0"

    def test_rpc_options(self):
        """Test RPC-related options."""
        from oida.protocols.profinet.proto_args import proto_args
        import argparse

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        # Test --no-rpc flag
        args = main_parser.parse_args(["profinet", "eth0", "--no-rpc"])
        assert args.no_rpc is True

    def test_discovery_options(self):
        """Test discovery-related options."""
        from oida.protocols.profinet.proto_args import proto_args
        import argparse

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        # Test --slot option
        args = main_parser.parse_args(["profinet", "eth0", "--slot", "0/1"])
        assert args.slot == "0/1"

    def test_enum_options(self):
        """Test enumeration options."""
        from oida.protocols.profinet.proto_args import proto_args
        import argparse

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])

        # Test --enum-all
        args = main_parser.parse_args(["profinet", "eth0", "--enum-all"])
        assert args.enum_all is True

        # Test --enum-smart
        args = main_parser.parse_args(["profinet", "eth0", "--enum-smart"])
        assert args.enum_smart is True


class TestProfinetDeviceNewFields:
    """Test ProfinetDevice new fields added for 0.6.0."""

    def test_device_topology_default(self):
        """Test topology field defaults to None."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        assert device.topology is None

    def test_device_module_diff_default(self):
        """Test module_diff field defaults to None."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        assert device.module_diff is None

    def test_device_alarms_default(self):
        """Test alarms field defaults to empty list."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        assert device.alarms == []

    def test_device_slots_default(self):
        """Test slots field defaults to empty list."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        assert device.slots == []

    def test_device_firmware_version_default(self):
        """Test firmware_version field defaults to empty string."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        assert device.firmware_version == ""

    def test_device_pn_device_default(self):
        """Test _pn_device field defaults to None."""
        from oida.protocols.profinet import ProfinetDevice

        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        assert device._pn_device is None

    def test_device_with_all_new_fields(self):
        """Test creating device with all new fields populated."""
        from oida.protocols.profinet import ProfinetDevice

        topology = MagicMock()
        module_diff = MagicMock()
        pn_dev = MagicMock()

        device = ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            topology=topology,
            module_diff=module_diff,
            alarms=[{"type": "Process", "slot": 1, "subslot": 1}],
            slots=[(0, 1, 0, 0), (1, 1, 0x10, 0x01)],
            firmware_version="V4.5.0",
            _pn_device=pn_dev,
        )

        assert device.topology is topology
        assert device.module_diff is module_diff
        assert len(device.alarms) == 1
        assert len(device.slots) == 2
        assert device.firmware_version == "V4.5.0"
        assert device._pn_device is pn_dev

    def test_device_alarms_not_shared(self):
        """Test alarms list is not shared between instances."""
        from oida.protocols.profinet import ProfinetDevice

        d1 = ProfinetDevice(mac_address="00:00:00:00:00:01")
        d2 = ProfinetDevice(mac_address="00:00:00:00:00:02")

        d1.alarms.append({"type": "Test"})
        assert d2.alarms == []

    def test_device_slots_not_shared(self):
        """Test slots list is not shared between instances."""
        from oida.protocols.profinet import ProfinetDevice

        d1 = ProfinetDevice(mac_address="00:00:00:00:00:01")
        d2 = ProfinetDevice(mac_address="00:00:00:00:00:02")

        d1.slots.append((0, 1, 0, 0))
        assert d2.slots == []


class TestProfinetArgHelper:
    """Test the _arg() helper method and _parse_slot_arg()."""

    def test_parse_slot_simple(self):
        """Test _parse_slot_arg with slot only."""
        from oida.protocols.profinet import profinet as ProfinetConnection

        assert ProfinetConnection._parse_slot_arg("1") == (1, None)

    def test_parse_slot_with_subslot(self):
        """Test _parse_slot_arg with slot/subslot."""
        from oida.protocols.profinet import profinet as ProfinetConnection

        assert ProfinetConnection._parse_slot_arg("1/1") == (1, 1)

    def test_parse_slot_hex_subslot(self):
        """Test _parse_slot_arg with hex subslot."""
        from oida.protocols.profinet import profinet as ProfinetConnection

        assert ProfinetConnection._parse_slot_arg("0/0x8001") == (0, 0x8001)

    def test_parse_slot_empty(self):
        """Test _parse_slot_arg with empty input."""
        from oida.protocols.profinet import profinet as ProfinetConnection

        assert ProfinetConnection._parse_slot_arg("") == (None, None)

    def test_parse_slot_none(self):
        """Test _parse_slot_arg with None input."""
        from oida.protocols.profinet import profinet as ProfinetConnection

        assert ProfinetConnection._parse_slot_arg(None) == (None, None)

    def test_parse_slot_invalid(self):
        """Invalid --slot must raise, not silently return (None, None).

        A (None, None) fallback reads as "no slot filter", which would widen a
        typo'd targeted probe into a full scan -- callers surface the ValueError
        as a fail message instead.
        """
        import pytest

        from oida.protocols.profinet import profinet as ProfinetConnection

        with pytest.raises(ValueError, match="invalid --slot value"):
            ProfinetConnection._parse_slot_arg("abc")


class TestProfinetNewProtoArgs:
    """Test new proto_args options added for 0.6.0."""

    def _make_parser(self):
        from oida.protocols.profinet.proto_args import proto_args
        import argparse

        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        parent = argparse.ArgumentParser(add_help=False)
        proto_args(subparsers, [parent])
        return main_parser

    def test_topology_flag(self):
        """Test --topology flag."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0", "--topology"])
        assert args.topology is True

    def test_module_diff_flag(self):
        """Test --module-diff flag."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0", "--module-diff"])
        assert args.module_diff is True

    def test_alarms_flag(self):
        """Test --alarms flag."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0", "--alarms"])
        assert args.alarms is True

    def test_write_im1(self):
        """Test --write-im1 with two values."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0", "--write-im1", "Motor A", "Hall 3"])
        assert args.write_im1 == ["Motor A", "Hall 3"]

    def test_write_im2(self):
        """Test --write-im2 with date string."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0", "--write-im2", "2025-01-15"])
        assert args.write_im2 == "2025-01-15"

    def test_write_im3(self):
        """Test --write-im3 with descriptor string."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0", "--write-im3", "Pump Station North"])
        assert args.write_im3 == "Pump Station North"

    def test_defaults_false(self):
        """Test new flags default to False/None."""
        parser = self._make_parser()
        args = parser.parse_args(["profinet", "eth0"])
        assert args.topology is False
        assert args.module_diff is False
        assert args.alarms is False
        assert args.write_im1 is None
        assert args.write_im2 is None
        assert args.write_im3 is None


class TestProfinetVendors:
    """Test vendor ID lookup."""

    def test_siemens_vendor(self):
        """Test Siemens vendor lookup."""
        try:
            from profinet.vendors import get_vendor_name

            name = get_vendor_name(0x002A)
            assert "SIEMENS" in name.upper()
        except ImportError:
            pytest.skip("profinet library not installed")

    def test_unknown_vendor(self):
        """Test unknown vendor ID - use 0xFFFE which is unassigned."""
        try:
            from profinet.vendors import get_vendor_name

            # 0xFFFF is IO-LINK Community; use 0xFFFE which is unassigned
            name = get_vendor_name(0xFFFE)
            assert name is None or "Unknown" in name or name == ""
        except ImportError:
            pytest.skip("profinet library not installed")


class TestProfinetDependencies:
    """Test profinet dependencies."""

    def test_profinet_library_installed(self):
        """Test profinet-py library is available."""
        try:
            import profinet

            assert profinet is not None
        except ImportError:
            pytest.skip("profinet library not installed")

    def test_dcp_module_available(self):
        """Test DCP module is available."""
        try:
            from profinet import dcp

            assert dcp is not None
        except ImportError:
            pytest.skip("profinet library not installed")

    def test_rpc_module_available(self):
        """Test RPC module is available."""
        try:
            from profinet import rpc

            assert rpc is not None
        except ImportError:
            pytest.skip("profinet library not installed")


class TestDCPDeviceDescription:
    """Test DCP device description parsing."""

    def test_parse_siemens_device(self):
        """Test parsing Siemens device response."""
        try:
            from profinet.dcp import DCPDeviceDescription
            from profinet.protocol import PNDCPBlock

            mac = b"\x28\x63\x36\x80\xb1\xf4"
            blocks = {
                PNDCPBlock.NAME_OF_STATION: b"plcxb1d0ed",
                PNDCPBlock.DEVICE_TYPE: b"S7-1200",
                PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x00\xd7\xff\xff\xff\x00\xc0\xa8\x00\x01",
                PNDCPBlock.DEVICE_ID: b"\x00\x2a\x01\x0d",
                PNDCPBlock.DEVICE_ROLE: b"\x02\x00",
                PNDCPBlock.DEVICE_INSTANCE: b"\x00\x64",
            }

            device = DCPDeviceDescription(mac, blocks)

            assert device.name == "plcxb1d0ed"
            assert device.device_type == "S7-1200"
            assert device.ip == "192.168.0.215"
            assert device.vendor_id == 0x002A
            assert "IO-Controller" in device.device_roles
            assert device.device_instance == (0, 100)

        except ImportError:
            pytest.skip("profinet library not installed")

    def test_parse_minimal_device(self):
        """Test parsing device with minimal blocks."""
        try:
            from profinet.dcp import DCPDeviceDescription
            from profinet.protocol import PNDCPBlock

            mac = b"\x00\x11\x22\x33\x44\x55"
            blocks = {
                PNDCPBlock.NAME_OF_STATION: b"minimal-device",
            }

            device = DCPDeviceDescription(mac, blocks)

            assert device.name == "minimal-device"
            assert device.ip == "0.0.0.0"
            assert device.device_type == ""

        except ImportError:
            pytest.skip("profinet library not installed")


class TestWriteOperationsSocketLifecycle:
    """Regression: raw socket must be closed if get_mac() fails after open."""

    def _make_scanner(self, confirm=True):
        from oida.protocols.profinet import profinet as ProfinetConnection

        scanner = ProfinetConnection.__new__(ProfinetConnection)
        scanner.interface = "eth0"
        scanner.timeout = 3.0
        scanner.logger = MagicMock()

        args = {
            "mac_address": "00:11:22:33:44:55",
            "set_name": "newname",
            "confirm": confirm,
        }
        scanner._arg = lambda name, default=None: args.get(name, default)
        return scanner

    def test_socket_closed_when_get_mac_fails(self):
        """If ethernet_socket succeeds but get_mac raises, sock is closed."""
        scanner = self._make_scanner()

        sock = MagicMock()
        profinet_mod = MagicMock()
        profinet_mod.ethernet_socket.return_value = sock
        profinet_mod.get_mac.side_effect = OSError("no mac")

        scanner._write_operations(profinet_mod)

        sock.close.assert_called_once()
        scanner.logger.fail.assert_called_once()

    def test_no_socket_leaked_when_ethernet_socket_fails(self):
        """If ethernet_socket itself raises, nothing to close and no crash."""
        scanner = self._make_scanner()

        profinet_mod = MagicMock()
        profinet_mod.ethernet_socket.side_effect = OSError("no iface")

        scanner._write_operations(profinet_mod)

        profinet_mod.get_mac.assert_not_called()
        scanner.logger.fail.assert_called_once()
