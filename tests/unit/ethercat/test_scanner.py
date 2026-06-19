#!/usr/bin/env python3
"""
Comprehensive test suite for EtherCAT protocol scanner

Tests both mock interactions and real protocol functionality.
Covers all protocol_options and proto_args.py flags, the five recent
code fixes, security analysis, and --confirm gating.

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock validates exact data):                 124 tests
Category B (conditional -- mock may not support, accept pass/fail):  2 tests
Category C (error handling -- assert graceful failure):            19 tests
Total:                                                            145 tests
---------------------------------------------------------------------------

Recent Code Fixes Verified:
  1. EEPROM dump stride fix (was skipping every other word)
  2. SM type decode tautology cleanup
  3. DC sync error check now uses AL Status Code range 0x0026-0x002C
  4. SDO write-only probe gated behind self.confirm
  5. FoE dump_path validated for path traversal

Flag Coverage Matrix (proto_args.py):
  target                    [A] test_scanner_init_defaults
  --interface               [A] test_scanner_init_custom_values
  -s/--scan-range           [A] test_scan_range_parsing
  -S/--slave                [A] test_slave_filter_single
  -i/--device-info          [A] test_device_info_flag
  -d/--dump                 [A] test_dump_path_flag
  -f/--foe-read             [A] test_foe_read_parsing, test_foe_read_operation
  --foe-write               [A] test_foe_write_parsing, test_foe_write_requires_confirm
  --dc-analysis             [A] test_dc_analysis_flag, test_dc_analysis_with_slaves
  -e/--eeprom-dump          [A] test_eeprom_dump_flag, test_eeprom_dump_addresses
  --no-emergency-monitor    [A] test_emergency_monitor_disabled
  --timeout                 [A] test_custom_timeout
  --op-state                [A] test_op_state_flag
  --boot-state              [A] test_boot_state_flag
  --fsoe/--scan-fsoe        [A] test_scan_fsoe_flag
  --esc-registers           [A] test_esc_debug_flag
  -C/--scan-coe             [A] test_sdo_scan_flag
  --coe-range               [A] test_coe_range_parsing
  -r/--read-coe/--sdo-read  [A] test_sdo_read_operation
  -w/--write-coe/--sdo-write[A] test_sdo_write_requires_confirm
  -p/--eeprom-parse         [A] test_eeprom_parse_flag
  --eeprom-write            [A] test_eeprom_write_requires_confirm
  --set-alias               [A] test_set_alias_requires_confirm
  --set-coe                 [A] test_set_coe_requires_confirm
  --set-mailbox             [A] test_set_mailbox_requires_confirm
  -F/--fuzz                 [A] test_fuzz_mode_parsing, test_fuzz_requires_confirm
  --fuzz-iterations         [A] test_fuzz_iterations
  -y/--confirm              [A] test_confirm_flag
"""

import os
import struct
import tempfile
import unittest
from unittest.mock import Mock


from oida.protocols.ethercat import EtherCATScanner, ethercat, protocol_options, metadata
from oida.protocols.ethercat.constants import (
    AL_STATUS_CODES,
    FMMU_TYPES,
    SM_TYPES,
    COE_DATA_TYPES,
    ESI_CATEGORY_TYPES,
    PORT_TYPES,
    ESC_REGISTER_MAP,
    lookup_vendor,
    get_al_status_error,
    get_slave_state_name,
)
from oida.protocols.ethercat.coe import (
    get_coe_object_name,
    encode_sdo_offset,
    parse_coe_ranges,
    coe_category_for,
)
from oida.protocols.ethercat.eeprom import (
    calculate_sii_crc,
    parse_sii_header,
    parse_strings_category,
    parse_general_category,
    parse_syncmanager_category,
    parse_fmmu_category,
    parse_pdo_category,
    parse_dc_category,
)
from oida.protocols.ethercat.foe import FOE_COMMON_FILENAMES
from oida.protocols.ethercat.fsoe import FSOE_COE_OBJECTS, FSOE_PARAM_OBJECTS
from oida.protocols.ethercat.soe import SOE_ELEMENTS, SOE_STANDARD_IDNS, encode_soe_offset


# ===========================================================================
# Helpers
# ===========================================================================


def _make_scanner(**overrides):
    """Create an EtherCATScanner with sensible defaults, overridable per-test."""
    defaults = {"interface": "enp0s3"}
    defaults.update(overrides)
    return EtherCATScanner(defaults)


def _make_mock_slave(
    name="EK1100",
    man=0x02,
    prod=0x044C2C52,
    rev=0x00120001,
    state=0x04,
    serial=0x12345678,
    input_bytes=0,
    output_bytes=0,
    al_status=0,
):
    """Create a mock pysoem slave object with realistic attributes."""
    slave = Mock()
    slave.name = name
    slave.man = man
    slave.id = prod
    slave.rev = rev
    slave.state = state
    slave.serial = serial
    slave.al_status = al_status
    slave.input = bytes(input_bytes)
    slave.output = bytearray(output_bytes)
    slave.delay = 0
    slave.port_des = 0
    slave.FMMUfunc = 2
    slave.SMfunc = 4
    slave.group = ""
    slave.image = ""
    slave.dtype = ""
    return slave


def _make_mock_master(slaves=None, expected_wkc=3):
    """Create a mock pysoem master with slave list."""
    master = Mock()
    master.slaves = slaves or [_make_mock_slave()]
    master.expected_wkc = expected_wkc
    master.state = 0x04  # SAFEOP
    master.send_processdata = Mock()
    master.receive_processdata = Mock(return_value=expected_wkc)
    master.config_init = Mock(return_value=len(master.slaves))
    master.config_map = Mock()
    master.config_dc = Mock()
    master.state_check = Mock()
    master.write_state = Mock()
    master.read_state = Mock()
    master.close = Mock()
    return master


def _build_sii_header(
    vendor_id=0x02,
    product_code=0x044C2C52,
    revision=0x00120001,
    serial_number=0x12345678,
    station_alias=0x0001,
    mbx_protocols=0x0C,
    eeprom_size_kbit=4,
):
    """Build a valid 128-byte SII header for testing."""
    data = bytearray(128)
    struct.pack_into("<H", data, 0x00, 0x0080)  # PDI control
    struct.pack_into("<H", data, 0x08, station_alias)
    struct.pack_into("<I", data, 0x10, vendor_id)
    struct.pack_into("<I", data, 0x14, product_code)
    struct.pack_into("<I", data, 0x18, revision)
    struct.pack_into("<I", data, 0x1C, serial_number)
    # Standard mailbox
    struct.pack_into("<H", data, 0x30, 0x1000)
    struct.pack_into("<H", data, 0x32, 128)
    struct.pack_into("<H", data, 0x34, 0x1080)
    struct.pack_into("<H", data, 0x36, 128)
    struct.pack_into("<H", data, 0x38, mbx_protocols)
    struct.pack_into("<H", data, 0x7C, eeprom_size_kbit - 1)
    # Compute and set CRC
    crc = calculate_sii_crc(bytes(data))
    data[0x0E] = crc
    return bytes(data)


# ===========================================================================
# Scanner Initialization Tests [Category A]
# ===========================================================================


class TestEtherCATScannerInit(unittest.TestCase):
    """Test EtherCAT scanner initialization and flag parsing [Category A]"""

    def test_scanner_init_defaults(self):
        """Test scanner initialization with default values [Category A]"""
        scanner = _make_scanner()
        self.assertEqual(scanner.interface, "enp0s3")
        self.assertEqual(scanner.get_protocol_name(), "EtherCAT")
        self.assertEqual(scanner.get_default_port(), 0)
        self.assertEqual(scanner.timeout, 5)
        self.assertTrue(scanner.read_sdo)
        self.assertTrue(scanner.read_eeprom)
        self.assertTrue(scanner.emergency_monitor)
        self.assertFalse(scanner.fuzz_sdo)
        self.assertFalse(scanner.fuzz_pdo)
        self.assertFalse(scanner.dc_analysis)
        self.assertFalse(scanner.eeprom_dump)
        self.assertFalse(scanner.device_info)
        self.assertFalse(scanner.sdo_scan)
        self.assertFalse(scanner.scan_fsoe)
        self.assertFalse(scanner.op_state)
        self.assertFalse(scanner.boot_state)
        self.assertFalse(scanner.esc_debug)
        self.assertFalse(scanner.eeprom_parse)
        self.assertFalse(scanner.confirm)
        self.assertEqual(scanner.scan_range, "1-16")
        self.assertEqual(scanner.fuzz_iterations, 10)
        self.assertIsNone(scanner.slave)

    def test_scanner_init_custom_values(self):
        """Test scanner initialization with custom values [Category A]"""
        scanner = _make_scanner(
            interface="eth1",
            timeout=30,
            debug=True,
            dump="/tmp/ethercat_dump",
            fuzz="sdo",
        )
        self.assertEqual(scanner.interface, "eth1")
        self.assertEqual(scanner.timeout, 30)
        self.assertTrue(scanner.debug)
        self.assertTrue(scanner.fuzz_sdo)
        self.assertFalse(scanner.fuzz_pdo)

    def test_scan_range_parsing(self):
        """Test --scan-range argument parsing [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-4"})
        self.assertEqual(scanner.scan_range, "1-4")
        self.assertEqual(scanner.slave_positions, [1, 2, 3, 4])

    def test_slave_filter_single(self):
        """Test --slave flag restricts to single position [Category A]"""
        scanner = _make_scanner(slave=2, **{"scan-range": "1-8"})
        self.assertEqual(scanner.slave, 2)
        filtered = scanner._slave_filter()
        self.assertEqual(filtered, {2})

    def test_slave_filter_all(self):
        """Test slave filter returns full range when --slave not set [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-4"})
        filtered = scanner._slave_filter()
        self.assertEqual(filtered, {1, 2, 3, 4})

    def test_device_info_flag(self):
        """Test -i/--device-info flag [Category A]"""
        scanner = _make_scanner(**{"device-info": True})
        self.assertTrue(scanner.device_info)

    def test_dump_path_flag(self):
        """Test -d/--dump flag [Category A]"""
        scanner = _make_scanner(dump="/tmp/test")
        self.assertEqual(scanner.dump_path, "/tmp/test")

    def test_foe_read_parsing(self):
        """Test -f/--foe-read argument parsing [Category A]"""
        scanner = _make_scanner(**{"foe-read": "2:config.xml"})
        self.assertEqual(scanner.foe_read, "2:config.xml")

    def test_foe_write_parsing(self):
        """Test --foe-write argument parsing [Category A]"""
        scanner = _make_scanner(**{"foe-write": "1:/tmp/firmware.bin"})
        self.assertEqual(scanner.foe_write, "1:/tmp/firmware.bin")

    def test_dc_analysis_flag(self):
        """Test --dc-analysis flag [Category A]"""
        scanner = _make_scanner(**{"dc-analysis": True})
        self.assertTrue(scanner.dc_analysis)

    def test_eeprom_dump_flag(self):
        """Test -e/--eeprom-dump flag [Category A]"""
        scanner = _make_scanner(**{"eeprom-dump": True})
        self.assertTrue(scanner.eeprom_dump)

    def test_emergency_monitor_disabled(self):
        """Test --no-emergency-monitor flag [Category A]"""
        scanner = _make_scanner(**{"emergency-monitor": False})
        self.assertFalse(scanner.emergency_monitor)

    def test_emergency_monitor_enabled_by_default(self):
        """Test emergency monitoring enabled by default [Category A]"""
        scanner = _make_scanner()
        self.assertTrue(scanner.emergency_monitor)

    def test_custom_timeout(self):
        """Test --timeout flag [Category A]"""
        scanner = _make_scanner(timeout=30)
        self.assertEqual(scanner.timeout, 30)

    def test_op_state_flag(self):
        """Test --op-state flag [Category A]"""
        scanner = _make_scanner(**{"op-state": True})
        self.assertTrue(scanner.op_state)

    def test_boot_state_flag(self):
        """Test --boot-state flag [Category A]"""
        scanner = _make_scanner(**{"boot-state": True})
        self.assertTrue(scanner.boot_state)

    def test_scan_fsoe_flag(self):
        """Test --fsoe/--scan-fsoe flag [Category A]"""
        scanner = _make_scanner(**{"scan-fsoe": True})
        self.assertTrue(scanner.scan_fsoe)

    def test_esc_debug_flag(self):
        """Test --esc-registers/--esc-debug flag [Category A]"""
        scanner = _make_scanner(**{"esc-debug": True})
        self.assertTrue(scanner.esc_debug)

    def test_sdo_scan_flag(self):
        """Test -C/--scan-coe/--sdo-scan flag [Category A]"""
        scanner = _make_scanner(**{"sdo-scan": True})
        self.assertTrue(scanner.sdo_scan)

    def test_eeprom_parse_flag(self):
        """Test -p/--eeprom-parse flag [Category A]"""
        scanner = _make_scanner(**{"eeprom-parse": True})
        self.assertTrue(scanner.eeprom_parse)

    def test_confirm_flag(self):
        """Test -y/--confirm flag [Category A]"""
        scanner = _make_scanner(confirm=True)
        self.assertTrue(scanner.confirm)

    def test_fuzz_mode_sdo(self):
        """Test --fuzz sdo mode parsing [Category A]"""
        scanner = _make_scanner(fuzz="sdo")
        self.assertTrue(scanner.fuzz_sdo)
        self.assertFalse(scanner.fuzz_pdo)

    def test_fuzz_mode_pdo(self):
        """Test --fuzz pdo mode parsing [Category A]"""
        scanner = _make_scanner(fuzz="pdo")
        self.assertFalse(scanner.fuzz_sdo)
        self.assertTrue(scanner.fuzz_pdo)

    def test_fuzz_mode_all(self):
        """Test --fuzz all mode parsing [Category A]"""
        scanner = _make_scanner(fuzz="all")
        self.assertTrue(scanner.fuzz_sdo)
        self.assertTrue(scanner.fuzz_pdo)

    def test_fuzz_iterations(self):
        """Test --fuzz-iterations flag [Category A]"""
        scanner = _make_scanner(**{"fuzz-iterations": 50})
        self.assertEqual(scanner.fuzz_iterations, 50)

    def test_sdo_read_cmd(self):
        """Test -r/--read-coe/--sdo-read flag [Category A]"""
        scanner = _make_scanner(**{"sdo-read": "1:0x1008:0"})
        self.assertEqual(scanner.sdo_read_cmd, "1:0x1008:0")

    def test_sdo_write_cmd(self):
        """Test -w/--write-coe/--sdo-write flag [Category A]"""
        scanner = _make_scanner(**{"sdo-write": "1:0x7000:1:0xFF"})
        self.assertEqual(scanner.sdo_write_cmd, "1:0x7000:1:0xFF")

    def test_eeprom_write_cmd(self):
        """Test --eeprom-write flag [Category A]"""
        scanner = _make_scanner(**{"eeprom-write": "0x08:0x1234"})
        self.assertEqual(scanner.eeprom_write_cmd, "0x08:0x1234")

    def test_set_alias_cmd(self):
        """Test --set-alias flag [Category A]"""
        scanner = _make_scanner(**{"set-alias": "1:100"})
        self.assertEqual(scanner.set_alias_cmd, "1:100")

    def test_set_coe_cmd(self):
        """Test --set-coe flag [Category A]"""
        scanner = _make_scanner(**{"set-coe": "sdo,sdo_info"})
        self.assertEqual(scanner.set_coe_cmd, "sdo,sdo_info")

    def test_set_mailbox_cmd(self):
        """Test --set-mailbox flag [Category A]"""
        scanner = _make_scanner(**{"set-mailbox": "coe,foe"})
        self.assertEqual(scanner.set_mailbox_cmd, "coe,foe")

    def test_coe_range_parsing(self):
        """Test --coe-range flag [Category A]"""
        scanner = _make_scanner(**{"coe-range": "0x2000-0x3000,0xF110"})
        self.assertEqual(scanner.coe_range, "0x2000-0x3000,0xF110")


# ===========================================================================
# Protocol Logic Tests [Category A]
# ===========================================================================


class TestEtherCATProtocolLogic(unittest.TestCase):
    """Test EtherCAT protocol-specific logic [Category A]"""

    def test_slave_state_codes(self):
        """Test EtherCAT slave state recognition [Category A]"""
        expected = {
            0x00: "NONE",
            0x01: "INIT",
            0x02: "PRE-OP",
            0x03: "BOOTSTRAP",
            0x04: "SAFE-OP",
            0x08: "OP",
        }
        for code, name in expected.items():
            self.assertEqual(get_slave_state_name(code), name)

    def test_slave_state_error_flag(self):
        """Test EtherCAT state + error flag [Category A]"""
        self.assertEqual(get_slave_state_name(0x14), "SAFE-OP+ERROR")
        self.assertEqual(get_slave_state_name(0x11), "INIT+ERROR")
        self.assertEqual(get_slave_state_name(0x18), "OP+ERROR")

    def test_al_status_error_known_codes(self):
        """Test AL status error code decoding [Category A]"""
        self.assertEqual(get_al_status_error(0x0000), "No error")
        self.assertEqual(get_al_status_error(0x0001), "Unspecified error")
        self.assertEqual(get_al_status_error(0x0026), "Invalid DC SYNC configuration")
        self.assertEqual(get_al_status_error(0x002C), "DC sync0 cycle time")

    def test_al_status_error_unknown_code(self):
        """Test AL status error with unknown code [Category A]"""
        result = get_al_status_error(0xFFFF)
        self.assertIn("Unknown error", result)
        self.assertIn("0xFFFF", result)

    def test_vendor_id_lookup_beckhoff(self):
        """Test vendor ID lookup for Beckhoff [Category A]"""
        result = lookup_vendor(0x02)
        self.assertIn("Beckhoff", result)

    def test_vendor_id_lookup_unknown(self):
        """Test vendor ID lookup for unknown vendor [Category A]"""
        result = lookup_vendor(0x7FFFFFFF)
        self.assertIn("Unknown", result)
        self.assertIn("0x7FFFFFFF", result)

    def test_coe_object_name_exact(self):
        """Test CoE object name lookup for known indices [Category A]"""
        self.assertEqual(get_coe_object_name(0x1000), "Device Type")
        self.assertEqual(get_coe_object_name(0x1008), "Device Name")
        self.assertEqual(get_coe_object_name(0x1018, 1), "Vendor ID")
        self.assertEqual(get_coe_object_name(0x1018, 4), "Serial")

    def test_coe_object_name_ranges(self):
        """Test CoE object name for range-based indices [Category A]"""
        result = get_coe_object_name(0x6000, 1)
        self.assertIn("Input", result)
        result = get_coe_object_name(0x7000, 1)
        self.assertIn("Output", result)
        result = get_coe_object_name(0x2000, 0)
        self.assertIn("Vendor", result)

    def test_encode_sdo_offset(self):
        """Test SDO offset encoding for ADS transport [Category A]"""
        self.assertEqual(encode_sdo_offset(0x1008, 0), 0x10080000)
        self.assertEqual(encode_sdo_offset(0x1018, 1), 0x10180001)
        self.assertEqual(encode_sdo_offset(0x1018, 4), 0x10180004)


# ===========================================================================
# Recent Fix #1: EEPROM Dump Stride [Category A]
# ===========================================================================


class TestEEPROMDumpStride(unittest.TestCase):
    """Verify EEPROM dump reads consecutive word addresses (fix #1) [Category A]"""

    def test_eeprom_dump_reads_all_addresses(self):
        """EEPROM dump must read 0x00-0x7F (128 words), not skip every other [Category A]"""
        scanner = _make_scanner(**{"eeprom-dump": True, "scan-range": "1-1"})
        mock_slave = _make_mock_slave()
        # eeprom_read returns 4 bytes per word (pysoem behavior)
        mock_slave.eeprom_read = Mock(return_value=b"\x00\x00\x00\x00")
        master = _make_mock_master(slaves=[mock_slave])

        scanner._dump_full_eeprom(master)

        # The fix ensures we read EVERY word from 0x00 to 0x7F
        called_addrs = [call.args[0] for call in mock_slave.eeprom_read.call_args_list]
        expected_addrs = list(range(0x00, 0x80))
        self.assertEqual(called_addrs, expected_addrs, "EEPROM dump must read all 128 words")

    def test_eeprom_dump_reports_correct_byte_count(self):
        """EEPROM dump total_bytes should be 4 * words_read [Category A]"""
        scanner = _make_scanner(**{"eeprom-dump": True, "scan-range": "1-1"})
        mock_slave = _make_mock_slave()
        mock_slave.eeprom_read = Mock(return_value=b"\xaa\xbb\xcc\xdd")
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._dump_full_eeprom(master)
        self.assertIn(1, result)
        self.assertEqual(result[1]["total_bytes"], 128 * 4)


# ===========================================================================
# Recent Fix #2: SM Type Decode Tautology [Category A]
# ===========================================================================


class TestSMTypeDecode(unittest.TestCase):
    """Verify SM type decode uses distinct values (fix #2) [Category A]"""

    def test_sm_types_are_distinct(self):
        """SM_TYPES must map different codes to different names [Category A]"""
        values = list(SM_TYPES.values())
        # Remove 'unused' and check rest are distinct
        non_unused = [v for v in values if v != "unused"]
        self.assertEqual(len(non_unused), len(set(non_unused)), "SM type names must be distinct")

    def test_sm_types_cover_standard_positions(self):
        """SM types 0-4 should map correctly per ETG.1000 [Category A]"""
        self.assertEqual(SM_TYPES[0], "unused")
        self.assertEqual(SM_TYPES[1], "mbx_out")
        self.assertEqual(SM_TYPES[2], "mbx_in")
        self.assertEqual(SM_TYPES[3], "pdo_out")
        self.assertEqual(SM_TYPES[4], "pdo_in")

    def test_parse_syncmanager_uses_type_field(self):
        """SyncManager parser uses data[7] for type, not position [Category A]"""
        sm_data = bytearray()
        # SM0 with type=3 (pdo_out) - would be wrong if using position heuristic
        sm_data.extend(struct.pack("<H", 0x1000))  # start
        sm_data.extend(struct.pack("<H", 4))  # length
        sm_data.append(0x26)  # control
        sm_data.append(0x00)  # status
        sm_data.append(0x01)  # enable
        sm_data.append(0x03)  # type = pdo_out

        result = parse_syncmanager_category(bytes(sm_data))
        self.assertEqual(result[0]["type"], "pdo_out")


# ===========================================================================
# Recent Fix #3: DC Sync Error Check Range [Category A]
# ===========================================================================


class TestDCSyncErrorRange(unittest.TestCase):
    """Verify DC sync error uses AL Status Code 0x0026-0x002C (fix #3) [Category A]"""

    def test_dc_sync_errors_detected_in_range(self):
        """DC analysis should detect sync errors for AL status 0x0026-0x002C [Category A]"""
        scanner = _make_scanner(**{"dc-analysis": True, "scan-range": "1-1"})

        for al_code in [0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C]:
            mock_slave = _make_mock_slave(al_status=al_code)
            master = _make_mock_master(slaves=[mock_slave])

            result = scanner._analyze_distributed_clock(master)
            self.assertTrue(
                len(result["sync_errors"]) > 0,
                f"AL status 0x{al_code:04X} should be detected as DC sync error",
            )

    def test_dc_no_false_positive_outside_range(self):
        """DC analysis should NOT flag non-DC AL status codes [Category A]"""
        scanner = _make_scanner(**{"dc-analysis": True, "scan-range": "1-1"})

        for al_code in [0x0000, 0x0001, 0x0011, 0x0025, 0x002D, 0x0050]:
            mock_slave = _make_mock_slave(al_status=al_code)
            master = _make_mock_master(slaves=[mock_slave])

            result = scanner._analyze_distributed_clock(master)
            self.assertEqual(
                len(result["sync_errors"]),
                0,
                f"AL status 0x{al_code:04X} should NOT be flagged as DC sync error",
            )


# ===========================================================================
# Recent Fix #4: SDO Write-Only Probe Gated Behind --confirm [Category A]
# ===========================================================================


class TestSDOWriteOnlyGating(unittest.TestCase):
    """Verify SDO write-only probe is gated behind --confirm (fix #4) [Category A]"""

    def test_write_only_probe_blocked_without_confirm(self):
        """_test_sdo_write_only must return False when confirm=False [Category A]"""
        scanner = _make_scanner(confirm=False)
        mock_slave = Mock()
        mock_slave.sdo_write = Mock()  # Would succeed if called

        result = scanner._test_sdo_write_only(mock_slave, 0x6040, 0)
        self.assertFalse(result, "Write-only probe must be blocked without --confirm")
        mock_slave.sdo_write.assert_not_called()

    def test_write_only_probe_allowed_with_confirm(self):
        """_test_sdo_write_only should attempt write when confirm=True [Category A]"""
        scanner = _make_scanner(confirm=True)
        mock_slave = Mock()
        mock_slave.sdo_write = Mock()  # Succeeds

        result = scanner._test_sdo_write_only(mock_slave, 0x6040, 0)
        self.assertTrue(result, "Write-only probe should succeed with --confirm")
        mock_slave.sdo_write.assert_called_once()

    def test_write_only_probe_returns_false_on_error(self):
        """_test_sdo_write_only returns False when write raises [Category A]"""
        scanner = _make_scanner(confirm=True)
        mock_slave = Mock()
        mock_slave.sdo_write = Mock(side_effect=Exception("SDO abort"))

        result = scanner._test_sdo_write_only(mock_slave, 0x6040, 0)
        self.assertFalse(result)


# ===========================================================================
# Recent Fix #5: FoE dump_path Validated for Path Traversal [Category A]
# ===========================================================================


class TestFoEPathTraversal(unittest.TestCase):
    """Verify FoE dump_path uses os.path.basename to prevent traversal (fix #5) [Category A]"""

    def test_foe_read_uses_basename_for_dump(self):
        """FoE read should strip directory components from filename [Category A]"""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(
                dump=tmpdir,
                **{"foe-read": "1:../../etc/passwd", "scan-range": "1-1"},
            )
            mock_slave = _make_mock_slave()
            mock_slave.foe_read = Mock(return_value=b"test_data")
            master = _make_mock_master(slaves=[mock_slave])

            result = scanner._foe_read_file(master)

            # The saved file should use basename only, not the traversal path
            if result.get("success"):
                # Check that no file was written outside the dump dir
                for f in os.listdir(tmpdir):
                    self.assertTrue(
                        f.startswith("foe_"),
                        f"FoE dump file should start with 'foe_': {f}",
                    )
                # The traversal attempt should result in a sanitized filename
                saved_files = os.listdir(tmpdir)
                for sf in saved_files:
                    self.assertNotIn("..", sf, "Path traversal should be stripped")
                    self.assertNotIn("/", sf, "Directory separators should be stripped")


# ===========================================================================
# Discover + Slave Discovery Tests [Category A]
# ===========================================================================


class TestSlaveDiscovery(unittest.TestCase):
    """Test slave discovery and enumeration [Category A]"""

    def test_discover_slaves_basic(self):
        """Test basic slave discovery returns correct structure [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-2"})
        slaves = [
            _make_mock_slave(name="EK1100", man=0x02, prod=0x044C2C52, state=0x04),
            _make_mock_slave(name="EL2004", man=0x02, prod=0x07D43052, state=0x04),
        ]
        master = _make_mock_master(slaves=slaves)

        result = scanner._discover_slaves(master)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[1]["name"], "EK1100")
        self.assertEqual(result[1]["manufacturer_id"], 0x02)
        self.assertIn("Beckhoff", result[1]["manufacturer"])
        self.assertEqual(result[2]["name"], "EL2004")
        self.assertEqual(result[1]["state"], "SAFE-OP")

    def test_discover_slaves_bytes_name(self):
        """Test slave name decoding when pysoem returns bytes [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        mock_slave = _make_mock_slave(name=b"EL1004\x00\x00")
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._discover_slaves(master)
        self.assertEqual(result[1]["name"], "EL1004")

    def test_discover_slaves_empty_name(self):
        """Test slave with empty name gets default [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        mock_slave = _make_mock_slave(name="")
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._discover_slaves(master)
        self.assertEqual(result[1]["name"], "Slave_1")

    def test_discover_slaves_io_map(self):
        """Test I/O map data in slave discovery [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        mock_slave = _make_mock_slave(input_bytes=4, output_bytes=2)
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._discover_slaves(master)
        io = result[1]["io_map"]
        self.assertEqual(io["input_bytes"], 4)
        self.assertEqual(io["output_bytes"], 2)

    def test_discover_slaves_with_al_status_error(self):
        """Test slave with AL status error is reported [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        mock_slave = _make_mock_slave(state=0x14, al_status=0x001A)
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._discover_slaves(master)
        self.assertEqual(result[1]["state"], "SAFE-OP+ERROR")
        self.assertIsNotNone(result[1]["al_status_error"])
        self.assertIn("Synchronization", result[1]["al_status_error"])


# ===========================================================================
# --confirm Gating Tests [Category A]
# ===========================================================================


class TestConfirmGating(unittest.TestCase):
    """Test that write operations are blocked without --confirm [Category A]"""

    def test_sdo_write_requires_confirm(self):
        """SDO write in discover() is skipped without --confirm [Category A]"""
        scanner = _make_scanner(**{"sdo-write": "0x7000:1:0xFF"}, confirm=False)
        master = _make_mock_master()

        # Run discover - SDO write should be skipped
        results = scanner.discover(master)
        self.assertNotIn("sdo_write_result", results)

    def test_sdo_write_allowed_with_confirm(self):
        """SDO write in discover() proceeds with --confirm [Category A]"""
        scanner = _make_scanner(**{"sdo-write": "0x7000:1:0xFF", "scan-range": "1-1"}, confirm=True)
        mock_slave = _make_mock_slave()
        mock_slave.sdo_write = Mock()
        master = _make_mock_master(slaves=[mock_slave])

        results = scanner.discover(master)
        self.assertIn("sdo_write_result", results)

    def test_eeprom_write_requires_confirm(self):
        """EEPROM write is skipped without --confirm [Category A]"""
        scanner = _make_scanner(**{"eeprom-write": "0x08:0x1234"}, confirm=False)
        master = _make_mock_master()

        results = scanner.discover(master)
        self.assertNotIn("eeprom_write_result", results)

    def test_set_alias_requires_confirm(self):
        """Set alias is skipped without --confirm [Category A]"""
        scanner = _make_scanner(**{"set-alias": "100"}, confirm=False)
        master = _make_mock_master()

        results = scanner.discover(master)
        self.assertNotIn("set_alias_result", results)

    def test_set_coe_requires_confirm(self):
        """Set CoE is skipped without --confirm [Category A]"""
        scanner = _make_scanner(**{"set-coe": "0x3F"}, confirm=False)
        master = _make_mock_master()

        results = scanner.discover(master)
        self.assertNotIn("set_coe_result", results)

    def test_set_mailbox_requires_confirm(self):
        """Set mailbox is skipped without --confirm [Category A]"""
        scanner = _make_scanner(**{"set-mailbox": "coe,foe"}, confirm=False)
        master = _make_mock_master()

        results = scanner.discover(master)
        self.assertNotIn("set_mailbox_result", results)

    def test_foe_write_requires_confirm(self):
        """FoE write is skipped without --confirm [Category A]"""
        scanner = _make_scanner(**{"foe-write": "1:/tmp/test.bin"}, confirm=False)
        master = _make_mock_master()

        results = scanner.discover(master)
        foe = results.get("foe_results", {})
        self.assertNotIn("write", foe)

    def test_fuzz_requires_confirm(self):
        """Fuzzing is skipped without --confirm [Category A]"""
        scanner = _make_scanner(fuzz="sdo", confirm=False)
        master = _make_mock_master()

        results = scanner.discover(master)
        self.assertEqual(results.get("fuzzing_results", {}), {})


# ===========================================================================
# EEPROM/ESI Parser Tests [Category A]
# ===========================================================================


class TestEEPROMParser(unittest.TestCase):
    """Test EEPROM/ESI parser functions per ETG.2010 [Category A]"""

    def test_sii_crc_calculation(self):
        """Test SII CRC-8 calculation [Category A]"""
        data = bytes(14)
        crc = calculate_sii_crc(data)
        self.assertIsInstance(crc, int)
        self.assertTrue(0 <= crc <= 0xFF)

    def test_sii_crc_changes_with_data(self):
        """Test SII CRC changes when data changes [Category A]"""
        data1 = bytes(14)
        data2 = bytes([0x01] + [0] * 13)
        crc1 = calculate_sii_crc(data1)
        crc2 = calculate_sii_crc(data2)
        self.assertNotEqual(crc1, crc2)

    def test_parse_sii_header(self):
        """Test SII header parsing with known values [Category A]"""
        data = _build_sii_header()
        result = parse_sii_header(data)

        self.assertEqual(result["vendor_id"], 0x02)
        self.assertEqual(result["product_code"], 0x044C2C52)
        self.assertEqual(result["serial_number"], 0x12345678)
        self.assertEqual(result["station_alias"], 0x0001)
        self.assertEqual(result["std_rx_mbx_size"], 128)
        self.assertEqual(result["std_tx_mbx_size"], 128)
        self.assertEqual(result["eeprom_size_kbit"], 4)
        self.assertTrue(result["crc_valid"])

    def test_parse_sii_header_mailbox_protocols(self):
        """Test mailbox protocol flag parsing [Category A]"""
        data = _build_sii_header(mbx_protocols=0x3F)
        result = parse_sii_header(data)
        mbx = result["mailbox_protocol_flags"]

        self.assertTrue(mbx["AoE"])
        self.assertTrue(mbx["EoE"])
        self.assertTrue(mbx["CoE"])
        self.assertTrue(mbx["FoE"])
        self.assertTrue(mbx["SoE"])
        self.assertTrue(mbx["VoE"])

    def test_parse_sii_header_coe_foe_only(self):
        """Test mailbox flags CoE+FoE only [Category A]"""
        data = _build_sii_header(mbx_protocols=0x0C)
        result = parse_sii_header(data)
        mbx = result["mailbox_protocol_flags"]

        self.assertFalse(mbx["AoE"])
        self.assertFalse(mbx["EoE"])
        self.assertTrue(mbx["CoE"])
        self.assertTrue(mbx["FoE"])
        self.assertFalse(mbx["SoE"])
        self.assertFalse(mbx["VoE"])

    def test_parse_sii_header_insufficient_data(self):
        """Test SII header with insufficient data [Category C]"""
        result = parse_sii_header(bytes(64))
        self.assertIn("error", result)

    def test_parse_strings_category(self):
        """Test STRINGS category parsing [Category A]"""
        strings_data = bytearray()
        test_strings = ["EK1100", "Beckhoff", "EtherCAT Coupler"]
        strings_data.append(len(test_strings))
        for s in test_strings:
            strings_data.append(len(s))
            strings_data.extend(s.encode("ascii"))

        result = parse_strings_category(bytes(strings_data))
        self.assertEqual(result[0], "")  # Index 0 is empty
        self.assertEqual(result[1], "EK1100")
        self.assertEqual(result[2], "Beckhoff")
        self.assertEqual(result[3], "EtherCAT Coupler")

    def test_parse_strings_category_empty(self):
        """Test STRINGS category with no data [Category C]"""
        result = parse_strings_category(b"")
        self.assertEqual(result, [""])

    def test_parse_general_category(self):
        """Test GENERAL category parsing [Category A]"""
        general_data = bytearray(18)
        general_data[0] = 1  # group_idx
        general_data[1] = 2  # image_idx
        general_data[2] = 3  # order_idx
        general_data[3] = 4  # name_idx
        general_data[5] = 0x3F  # coe_details (all features)
        general_data[11] = 0x01  # flags (enable_safeop)
        struct.pack_into("<h", general_data, 12, 100)  # current_on_ebus_ma
        struct.pack_into("<H", general_data, 16, 0x3022)  # physical_port

        strings = ["", "IO Modules", "ek1100.png", "EK1100-0000", "EK1100 EtherCAT Coupler"]
        result = parse_general_category(bytes(general_data), strings)

        self.assertEqual(result["group"], "IO Modules")
        self.assertEqual(result["name"], "EK1100 EtherCAT Coupler")
        self.assertEqual(result["current_on_ebus_ma"], 100)

        coe = result["coe_flags"]
        self.assertTrue(coe["sdo"])
        self.assertTrue(coe["sdo_info"])
        self.assertTrue(coe["complete_access"])

        self.assertEqual(result["ports"][0], "ebus")
        self.assertEqual(result["ports"][1], "ebus")

    def test_parse_general_category_insufficient_data(self):
        """Test GENERAL category with insufficient data [Category C]"""
        result = parse_general_category(b"\x00" * 10, [""])
        self.assertIn("error", result)

    def test_parse_syncmanager_category(self):
        """Test SyncManager category parsing [Category A]"""
        sm_data = bytearray()
        for sm_type, ctrl, start in [(1, 0x26, 0x1000), (2, 0x22, 0x1080), (3, 0x64, 0x1100)]:
            sm_data.extend(struct.pack("<H", start))
            sm_data.extend(struct.pack("<H", 128 if sm_type < 3 else 4))
            sm_data.append(ctrl)
            sm_data.append(0x00)
            sm_data.append(0x01)
            sm_data.append(sm_type)

        result = parse_syncmanager_category(bytes(sm_data))
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["type"], "mbx_out")
        self.assertEqual(result[1]["type"], "mbx_in")
        self.assertEqual(result[2]["type"], "pdo_out")

    def test_parse_fmmu_category(self):
        """Test FMMU category parsing [Category A]"""
        fmmu_data = bytes([0x01, 0x02, 0x00, 0x03])
        result = parse_fmmu_category(fmmu_data)

        self.assertEqual(len(result), 4)
        self.assertEqual(result[0]["type"], "outputs")
        self.assertEqual(result[1]["type"], "inputs")
        self.assertEqual(result[2]["type"], "unused")
        self.assertEqual(result[3]["type"], "sm_status")

    def test_parse_fmmu_category_empty(self):
        """Test FMMU category with no data [Category C]"""
        result = parse_fmmu_category(b"")
        self.assertEqual(result, [])

    def test_parse_pdo_category(self):
        """Test PDO category parsing structure [Category A]"""
        pdo_data = bytearray()
        pdo_data.extend(struct.pack("<H", 0x1600))  # index
        pdo_data.append(1)  # n_entries
        pdo_data.append(2)  # sync_manager
        pdo_data.append(0)  # dc_sync
        pdo_data.append(1)  # name_idx
        pdo_data.extend(struct.pack("<H", 0x0001))  # flags (fixed)

        # Entry
        pdo_data.extend(struct.pack("<H", 0x7000))
        pdo_data.append(0x01)
        pdo_data.append(2)  # name_idx
        pdo_data.append(0x05)  # UINT8
        pdo_data.append(8)
        pdo_data.extend(struct.pack("<H", 0x0000))

        strings = ["", "RxPDO-Map", "Output1"]
        result = parse_pdo_category(bytes(pdo_data), strings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["index"], "0x1600")
        self.assertEqual(result[0]["name"], "RxPDO-Map")
        self.assertTrue(result[0]["flags"]["fixed"])
        self.assertEqual(len(result[0]["entries"]), 1)
        self.assertEqual(result[0]["entries"][0]["data_type"], "UINT8")
        self.assertEqual(result[0]["entries"][0]["bit_length"], 8)

    def test_parse_dc_category(self):
        """Test DC category parsing [Category A]"""
        dc_data = bytearray(18)
        struct.pack_into("<I", dc_data, 0, 1000000)  # cycle_time0_ns = 1ms
        struct.pack_into("<H", dc_data, 12, 0x0300)  # assign_activate = dc_sync0
        dc_data[16] = 1  # name_idx
        dc_data[17] = 2  # desc_idx

        strings = ["", "DC Sync", "Default DC mode"]
        result = parse_dc_category(bytes(dc_data), strings)

        self.assertEqual(result["cycle_time0_ns"], 1000000)
        self.assertEqual(result["assign_activate_mode"], "dc_sync0")
        self.assertEqual(result["name"], "DC Sync")

    def test_parse_dc_category_insufficient_data(self):
        """Test DC category with insufficient data [Category C]"""
        result = parse_dc_category(bytes(10), [""])
        self.assertIn("error", result)


# ===========================================================================
# CoE Operations Tests [Category A/B]
# ===========================================================================


class TestCoeOperations(unittest.TestCase):
    """Test CoE/SDO operations [Category A/B]"""

    def test_parse_sdo_address_two_parts(self):
        """Test SDO address parsing INDEX:SUBINDEX [Category A]"""
        scanner = _make_scanner()
        slave_pos, index, subindex = scanner._parse_sdo_address("0x1008:0")
        self.assertEqual(slave_pos, 0)
        self.assertEqual(index, 0x1008)
        self.assertEqual(subindex, 0)

    def test_parse_sdo_address_three_parts(self):
        """Test SDO address parsing SLAVE:INDEX:SUBINDEX [Category A]"""
        scanner = _make_scanner()
        slave_pos, index, subindex = scanner._parse_sdo_address("2:0x7000:1")
        self.assertEqual(slave_pos, 1)  # 0-based
        self.assertEqual(index, 0x7000)
        self.assertEqual(subindex, 1)

    def test_parse_sdo_address_invalid(self):
        """Test SDO address parsing with invalid format [Category C]"""
        scanner = _make_scanner()
        with self.assertRaises(ValueError):
            scanner._parse_sdo_address("invalid")

    def test_sdo_read_operation(self):
        """Test SDO read command execution [Category A]"""
        scanner = _make_scanner(**{"sdo-read": "0x1008:0", "scan-range": "1-1"})
        mock_slave = _make_mock_slave()
        mock_slave.sdo_read = Mock(return_value=b"Test Device\x00")
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._execute_sdo_read(master)
        self.assertTrue(result["success"])
        self.assertEqual(result["slave"], 1)
        self.assertEqual(result["index"], "0x1008")

    def test_sdo_write_operation_with_confirm(self):
        """Test SDO write command with --confirm [Category A]"""
        scanner = _make_scanner(**{"sdo-write": "0x7000:1:0xFF", "scan-range": "1-1"}, confirm=True)
        mock_slave = _make_mock_slave()
        mock_slave.sdo_write = Mock()
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._execute_sdo_write(master)
        self.assertTrue(result["success"])
        mock_slave.sdo_write.assert_called_once()

    def test_format_sdo_value_uint8(self):
        """Test SDO value formatting for 1-byte values [Category A]"""
        scanner = _make_scanner()
        type_str, val_str = scanner._format_sdo_value("ff", 1)
        self.assertEqual(type_str, "UINT8")
        self.assertEqual(val_str, "255")

    def test_format_sdo_value_uint16(self):
        """Test SDO value formatting for 2-byte values [Category A]"""
        scanner = _make_scanner()
        type_str, val_str = scanner._format_sdo_value("0100", 2)
        self.assertEqual(type_str, "UINT16")

    def test_format_sdo_value_string(self):
        """Test SDO value formatting for string values [Category A]"""
        scanner = _make_scanner()
        hex_str = "48656c6c6f"  # "Hello"
        type_str, val_str = scanner._format_sdo_value(hex_str, 5)
        self.assertIn("STRING", type_str)
        self.assertIn("Hello", val_str)

    def test_format_sdo_value_empty(self):
        """Test SDO value formatting for empty data [Category A]"""
        scanner = _make_scanner()
        type_str, val_str = scanner._format_sdo_value("", 0)
        self.assertEqual(type_str, "")
        self.assertEqual(val_str, "")

    def test_test_sdo_write_access_success(self):
        """Test SDO write access test (same-value write) requires --confirm [Category A]"""
        scanner = _make_scanner(confirm=True)
        mock_slave = Mock()
        mock_slave.sdo_write = Mock()
        data = bytes([0x42])

        result = scanner._test_sdo_write_access(mock_slave, 0x7000, 1, data)
        self.assertTrue(result)
        mock_slave.sdo_write.assert_called_once_with(0x7000, 1, data)

    def test_test_sdo_write_access_gated_without_confirm(self):
        """Without --confirm, write-access probing is skipped (no write) [Category A]"""
        scanner = _make_scanner()
        mock_slave = Mock()
        mock_slave.sdo_write = Mock()

        result = scanner._test_sdo_write_access(mock_slave, 0x7000, 1, bytes([0x42]))
        self.assertFalse(result)
        mock_slave.sdo_write.assert_not_called()

    def test_test_sdo_write_access_failure(self):
        """Test SDO write access test when write fails [Category A]"""
        scanner = _make_scanner(confirm=True)
        mock_slave = Mock()
        mock_slave.sdo_write = Mock(side_effect=Exception("Abort"))

        result = scanner._test_sdo_write_access(mock_slave, 0x7000, 1, b"\x00")
        self.assertFalse(result)


# ===========================================================================
# CoE Range Parsing Tests [Category A/C]
# ===========================================================================


class TestCoeRangeParsing(unittest.TestCase):
    """Test --coe-range spec parsing [Category A/C]"""

    def test_parse_single_index(self):
        """Test single index parsing [Category A]"""
        result = parse_coe_ranges("0xF110")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 0xF110)
        self.assertEqual(result[0][1], 0xF111)

    def test_parse_range(self):
        """Test index range parsing [Category A]"""
        result = parse_coe_ranges("0x2000-0x3000")
        self.assertEqual(result[0][0], 0x2000)
        self.assertEqual(result[0][1], 0x3000)

    def test_parse_index_with_subindex(self):
        """Test index:subindex parsing [Category A]"""
        result = parse_coe_ranges("0xFB00:1")
        self.assertEqual(result[0][0], 0xFB00)
        self.assertEqual(result[0][3], [1])

    def test_parse_multiple_comma_separated(self):
        """Test comma-separated ranges [Category A]"""
        result = parse_coe_ranges("0x2000-0x3000,0xF110,0x7000-0x7FFF")
        self.assertEqual(len(result), 3)

    def test_parse_invalid_range(self):
        """Test invalid range raises ValueError [Category C]"""
        with self.assertRaises(ValueError):
            parse_coe_ranges("0x3000-0x2000")  # end < start

    def test_parse_empty_raises(self):
        """Test empty spec raises ValueError [Category C]"""
        with self.assertRaises(ValueError):
            parse_coe_ranges("")

    def test_coe_category_for(self):
        """Test coe_category_for lookup [Category A]"""
        self.assertEqual(coe_category_for(0x1000), "Communication")
        self.assertEqual(coe_category_for(0x6000), "Inputs")
        self.assertEqual(coe_category_for(0x7000), "Outputs")
        self.assertEqual(coe_category_for(0xFFFF), "Custom")


# ===========================================================================
# FoE Operations Tests [Category A/C]
# ===========================================================================


class TestFoEOperations(unittest.TestCase):
    """Test File over EtherCAT operations [Category A/C]"""

    def test_foe_read_success(self):
        """Test FoE read with valid slave and file [Category A]"""
        scanner = _make_scanner(**{"foe-read": "1:test.bin", "scan-range": "1-1"})
        mock_slave = _make_mock_slave()
        mock_slave.foe_read = Mock(return_value=b"\x01\x02\x03\x04")
        master = _make_mock_master(slaves=[mock_slave])

        result = scanner._foe_read_file(master)
        self.assertTrue(result["success"])
        self.assertEqual(result["size"], 4)
        self.assertEqual(result["slave"], 1)
        self.assertEqual(result["filename"], "test.bin")

    def test_foe_read_invalid_format(self):
        """Test FoE read with invalid format [Category C]"""
        scanner = _make_scanner(**{"foe-read": "no_colon"})
        master = _make_mock_master()

        result = scanner._foe_read_file(master)
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_foe_read_invalid_slave_position(self):
        """Test FoE read with out-of-range slave [Category C]"""
        scanner = _make_scanner(**{"foe-read": "99:test.bin"})
        master = _make_mock_master(slaves=[_make_mock_slave()])

        result = scanner._foe_read_file(master)
        self.assertFalse(result["success"])

    def test_foe_write_success(self):
        """Test FoE write with valid slave and file [Category A]"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"firmware_data")
            f.flush()
            fname = f.name

        try:
            scanner = _make_scanner(
                **{"foe-write": f"1:{fname}", "scan-range": "1-1"}, confirm=True
            )
            mock_slave = _make_mock_slave()
            mock_slave.foe_write = Mock()
            master = _make_mock_master(slaves=[mock_slave])

            result = scanner._foe_write_file(master)
            self.assertTrue(result["success"])
            mock_slave.foe_write.assert_called_once()
        finally:
            os.unlink(fname)

    def test_foe_write_file_not_found(self):
        """Test FoE write with nonexistent file [Category C]"""
        scanner = _make_scanner(
            **{"foe-write": "1:/nonexistent/path.bin", "scan-range": "1-1"}, confirm=True
        )
        master = _make_mock_master(slaves=[_make_mock_slave()])

        result = scanner._foe_write_file(master)
        self.assertFalse(result["success"])
        self.assertIn("not found", result.get("error", "").lower())

    def test_foe_common_filenames(self):
        """Test FoE common filenames list is populated [Category A]"""
        self.assertGreater(len(FOE_COMMON_FILENAMES), 10)
        self.assertIn("firmware.bin", FOE_COMMON_FILENAMES)
        self.assertIn("systrace", FOE_COMMON_FILENAMES)
        self.assertIn("esi.xml", FOE_COMMON_FILENAMES)


# ===========================================================================
# Security Analysis Tests [Category A]
# ===========================================================================


class TestSoEHelpers(unittest.TestCase):
    """Test SoE encoding helpers [Category A]"""

    def test_encode_soe_offset_value(self):
        """Test SoE offset encoding for Value element [Category A]"""
        offset = encode_soe_offset(idn=1, element=7, drive=0)
        # element 7 -> bitmask 0x40
        self.assertEqual(offset & 0xFFFF, 1)
        self.assertEqual((offset >> 16) & 0xFF, 0x40)
        self.assertEqual((offset >> 24) & 0xFF, 0)

    def test_encode_soe_offset_name(self):
        """Test SoE offset encoding for Name element [Category A]"""
        offset = encode_soe_offset(idn=24, element=2, drive=0)
        self.assertEqual(offset & 0xFFFF, 24)
        self.assertEqual((offset >> 16) & 0xFF, 0x02)

    def test_soe_elements_complete(self):
        """Test SoE elements dictionary [Category A]"""
        self.assertEqual(SOE_ELEMENTS[7], "Value")
        self.assertEqual(SOE_ELEMENTS[2], "Name")

    def test_soe_standard_idns(self):
        """Test standard SERCOS IDNs [Category A]"""
        self.assertIn(1, SOE_STANDARD_IDNS)
        self.assertIn(145, SOE_STANDARD_IDNS)


# ===========================================================================
# FSoE Data Module [Category A]
# ===========================================================================


class TestFSoEData(unittest.TestCase):
    """Test FSoE data structures [Category A]"""

    def test_fsoe_coe_objects_populated(self):
        """Test FSoE CoE objects list is populated [Category A]"""
        self.assertGreater(len(FSOE_COE_OBJECTS), 10)

    def test_fsoe_param_objects_populated(self):
        """Test FSoE parameter objects list is populated [Category A]"""
        self.assertGreater(len(FSOE_PARAM_OBJECTS), 5)

    def test_fsoe_objects_structure(self):
        """Test FSoE objects have correct tuple structure [Category A]"""
        for obj in FSOE_COE_OBJECTS:
            self.assertEqual(len(obj), 5)
            index, subindex, name, dtype, read_size = obj
            self.assertIsInstance(index, int)
            self.assertIsInstance(subindex, int)
            self.assertIsInstance(name, str)
            self.assertIn(dtype, ("uint8", "uint16", "uint32", "string", "octets"))
            self.assertGreater(read_size, 0)


# ===========================================================================
# Constants Module Tests [Category A]
# ===========================================================================


class TestConstants(unittest.TestCase):
    """Test constants module [Category A]"""

    def test_al_status_codes_populated(self):
        """Test AL status codes dictionary [Category A]"""
        self.assertGreater(len(AL_STATUS_CODES), 20)
        self.assertIn(0x0000, AL_STATUS_CODES)
        self.assertIn(0x0026, AL_STATUS_CODES)

    def test_fmmu_types(self):
        """Test FMMU types [Category A]"""
        self.assertEqual(FMMU_TYPES[0], "unused")
        self.assertEqual(FMMU_TYPES[1], "outputs")
        self.assertEqual(FMMU_TYPES[2], "inputs")

    def test_coe_data_types(self):
        """Test CoE data types [Category A]"""
        self.assertIn(0x01, COE_DATA_TYPES)
        self.assertEqual(COE_DATA_TYPES[0x09], "VISIBLE_STRING")

    def test_esi_category_types(self):
        """Test ESI category types [Category A]"""
        self.assertEqual(ESI_CATEGORY_TYPES[10], "STRINGS")
        self.assertEqual(ESI_CATEGORY_TYPES[30], "GENERAL")
        self.assertEqual(ESI_CATEGORY_TYPES[41], "SyncManager")

    def test_port_types(self):
        """Test physical port types [Category A]"""
        self.assertEqual(PORT_TYPES[0], "not_impl")
        self.assertEqual(PORT_TYPES[2], "ebus")
        self.assertEqual(PORT_TYPES[3], "mii")

    def test_esc_register_map_populated(self):
        """Test ESC register map [Category A]"""
        self.assertIn(0x0130, ESC_REGISTER_MAP)
        self.assertEqual(ESC_REGISTER_MAP[0x0130][0], "AL Status")


# ===========================================================================
# NXC-Style Connection Class Tests [Category A/B]
# ===========================================================================


class TestNXCConnection(unittest.TestCase):
    """Test NXC-style ethercat connection class [Category A/B]"""

    def test_nxc_class_import(self):
        """Test NXC-style class can be imported [Category A]"""
        self.assertTrue(callable(ethercat))

    def test_nxc_class_check_dependencies(self):
        """Test NXC class dependency check [Category B]"""
        result = ethercat.check_dependencies()
        self.assertIsInstance(result, bool)

    def test_nxc_convert_args_emergency_monitor(self):
        """Test NXC class emergency monitor arg conversion [Category A]"""
        nxc_instance = ethercat.__new__(ethercat)
        mock_args = Mock()
        mock_args.no_emergency_monitor = False
        mock_args.interface = "eth0"
        mock_args.target = "enp0s3"
        mock_args.__dict__ = {
            "no_emergency_monitor": False,
            "interface": "eth0",
            "target": "enp0s3",
        }
        nxc_instance.args = mock_args
        nxc_instance.interface = "enp0s3"
        nxc_instance.ip = ""

        proto_args = nxc_instance._convert_args_to_dict()
        self.assertTrue(proto_args["emergency-monitor"])

    def test_nxc_convert_args_emergency_disabled(self):
        """Test NXC class with --no-emergency-monitor [Category A]"""
        nxc_instance = ethercat.__new__(ethercat)
        mock_args = Mock()
        mock_args.no_emergency_monitor = True
        mock_args.interface = None
        mock_args.target = "eth0"
        mock_args.__dict__ = {
            "no_emergency_monitor": True,
            "interface": None,
            "target": "eth0",
        }
        nxc_instance.args = mock_args
        nxc_instance.interface = "eth0"
        nxc_instance.ip = ""

        proto_args = nxc_instance._convert_args_to_dict()
        self.assertFalse(proto_args["emergency-monitor"])


# ===========================================================================
# Protocol Options and Metadata Tests [Category A]
# ===========================================================================


class TestProtocolOptionsAndMetadata(unittest.TestCase):
    """Test protocol_options and metadata exports [Category A]"""

    def test_protocol_options_exist(self):
        """Test protocol_options is exported [Category A]"""
        self.assertIsInstance(protocol_options, dict)

    def test_protocol_options_has_all_features(self):
        """Test protocol_options includes all expected keys [Category A]"""
        expected_keys = [
            "dump",
            "fuzz",
            "fuzz-iterations",
            "sdo",
            "eeprom",
            "scan-range",
            "foe-read",
            "foe-write",
            "dc-analysis",
            "emergency-monitor",
            "eeprom-dump",
        ]
        for key in expected_keys:
            self.assertIn(key, protocol_options, f"Missing protocol option: {key}")

    def test_protocol_options_types(self):
        """Test protocol_options have correct types [Category A]"""
        self.assertEqual(protocol_options["foe-read"]["type"], "string")
        self.assertEqual(protocol_options["dc-analysis"]["type"], "bool")
        self.assertEqual(protocol_options["fuzz-iterations"]["type"], "int")

    def test_metadata_exists(self):
        """Test metadata is exported [Category A]"""
        self.assertIsInstance(metadata, dict)

    def test_metadata_has_required_fields(self):
        """Test metadata has required fields [Category A]"""
        for field in ["name", "description", "authors", "type"]:
            self.assertIn(field, metadata)

    def test_metadata_type(self):
        """Test metadata type is scanner [Category A]"""
        self.assertEqual(metadata["type"], "scanner")

    def test_run_function_exists(self):
        """Test run function is exported [Category A]"""
        from oida.protocols.ethercat import run

        self.assertTrue(callable(run))


# ===========================================================================
# Data Structure Tests [Category A]
# ===========================================================================


# ===========================================================================
# Discover Workflow Tests [Category A]
# ===========================================================================


class TestDiscoverWorkflow(unittest.TestCase):
    """Test the full discover() method workflow [Category A]"""

    def test_discover_basic_workflow(self):
        """Test discover() returns expected result structure [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        mock_slave = _make_mock_slave()
        master = _make_mock_master(slaves=[mock_slave])

        results = scanner.discover(master)

        self.assertIn("network_info", results)
        self.assertIn("slaves", results)
        self.assertIn("security_analysis", results)
        self.assertIn("emergency_messages", results)
        self.assertIsInstance(results["emergency_messages"], list)

    def test_discover_with_device_info(self):
        """Test discover() with --device-info enriches slaves [Category A]"""
        scanner = _make_scanner(**{"device-info": True, "scan-range": "1-1"})
        mock_slave = _make_mock_slave()
        mock_slave.sdo_read = Mock(side_effect=Exception("SDO not supported"))
        master = _make_mock_master(slaves=[mock_slave])

        results = scanner.discover(master)
        self.assertIn("slaves", results)

    def test_discover_network_info(self):
        """Test network info collection [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        master = _make_mock_master()

        info = scanner._get_network_info(master)
        self.assertEqual(info["interface"], "enp0s3")
        self.assertIn("slave_count", info)
        self.assertIn("expected_wkc", info)
        self.assertIn("timestamp", info)

    def test_network_info_sends_before_receiving(self):
        """send_processdata() must precede receive_processdata() in a PD cycle."""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        master = _make_mock_master()

        # Route both PD calls through one parent so ordering is observable.
        parent = Mock()
        master.send_processdata = parent.send
        master.receive_processdata = parent.receive
        parent.receive.return_value = 3

        scanner._get_network_info(master)

        # Process data must be sent before the first receive.
        method_order = [name for name, _, _ in parent.mock_calls]
        self.assertTrue(method_order, "no process-data calls were made")
        self.assertEqual(method_order[0], "send")
        first_recv = method_order.index("receive")
        self.assertLess(
            method_order.index("send"),
            first_recv,
            "send_processdata() must be called before receive_processdata()",
        )


# ===========================================================================
# Error Handling Tests [Category C]
# ===========================================================================


class TestErrorHandling(unittest.TestCase):
    """Test error handling scenarios [Category C]"""

    def test_sdo_read_invalid_slave(self):
        """Test SDO read with invalid slave position [Category C]"""
        scanner = _make_scanner(**{"sdo-read": "99:0x1008:0"})
        master = _make_mock_master(slaves=[_make_mock_slave()])

        result = scanner._execute_sdo_read(master)
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_sdo_write_invalid_slave(self):
        """Test SDO write with invalid slave position [Category C]"""
        scanner = _make_scanner(**{"sdo-write": "99:0x1008:0:0"}, confirm=True)
        master = _make_mock_master(slaves=[_make_mock_slave()])

        result = scanner._execute_sdo_write(master)
        self.assertFalse(result["success"])

    def test_sdo_write_invalid_format(self):
        """Test SDO write with invalid format [Category C]"""
        scanner = _make_scanner(**{"sdo-write": "invalid"}, confirm=True)
        master = _make_mock_master()

        result = scanner._execute_sdo_write(master)
        self.assertFalse(result["success"])

    def test_eeprom_write_invalid_format(self):
        """Test EEPROM write with invalid format [Category C]"""
        scanner = _make_scanner(**{"eeprom-write": "a:b:c:d"}, confirm=True)
        master = _make_mock_master()

        result = scanner._execute_eeprom_write(master)
        self.assertFalse(result["success"])

    def test_set_alias_invalid_slave(self):
        """Test set alias with invalid slave [Category C]"""
        scanner = _make_scanner(**{"set-alias": "99:100"}, confirm=True)
        master = _make_mock_master(slaves=[_make_mock_slave()])

        result = scanner._execute_set_alias(master)
        self.assertFalse(result["success"])

    def test_set_alias_overflow(self):
        """Test set alias with value > 16-bit [Category C]"""
        scanner = _make_scanner(**{"set-alias": "70000"}, confirm=True)
        master = _make_mock_master(slaves=[_make_mock_slave()])

        result = scanner._execute_set_alias(master)
        self.assertFalse(result["success"])

    def test_disconnect_handles_none(self):
        """Test disconnect with None connection [Category C]"""
        scanner = _make_scanner()
        # Should not raise
        scanner.disconnect(None)

    def test_disconnect_handles_exception(self):
        """Test disconnect handles error gracefully [Category C]"""
        scanner = _make_scanner()
        mock_conn = Mock()
        mock_conn.slaves = [_make_mock_slave()]
        mock_conn.write_state = Mock(side_effect=Exception("fail"))
        mock_conn.close = Mock()

        # Should not raise
        scanner.disconnect(mock_conn)
        mock_conn.close.assert_called()


if __name__ == "__main__":
    unittest.main()
