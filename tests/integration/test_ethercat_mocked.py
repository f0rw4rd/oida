"""
EtherCAT Protocol Integration Tests -- Category A (Mocked pysoem)

Tests the full EtherCAT scanner logic with pysoem mocked at the Python level,
simulating a successful EtherCAT bus with realistic slave data. Because EtherCAT
uses raw Layer 2 Ethernet (EtherType 0x88A4), there is no TCP port to mock via
Docker -- we must patch pysoem calls directly.

Mock Data (matching docker/mocks/services/ethercat_slave.c):
  Vendor ID:      0x000003E7 (999 = MSF-ICS Mock)
  Product Code:   0x00001001
  Revision:       0x00010000
  Serial Number:  0x12345678
  Device Name:    "MSF-ICS Mock EtherCAT Slave"
  States:         PRE-OP (0x02), SAFE-OP (0x04)
  CoE objects:    Device Type (0x1000), Error Register (0x1001),
                  Device Name (0x1008), HW Version (0x1009),
                  FW Version (0x100A), Identity (0x1018)
  FoE files:      firmware.bin (512 bytes)
  EEPROM:         Full SII header + categories

Test Classification Summary
---------------------------------------------------------------------------
Category A (mocked pysoem -- exercises full scanner logic):           30+ tests
---------------------------------------------------------------------------
"""

import os
import struct
import tempfile
from unittest.mock import Mock, MagicMock, patch

import pytest

from oida.protocols.ethercat import EtherCATScanner
from oida.protocols.ethercat.eeprom import calculate_sii_crc


# ===========================================================================
# Mock Data Constants (from docker/mocks/services/ethercat_slave.c)
# ===========================================================================

MOCK_VENDOR_ID = 0x000003E7
MOCK_PRODUCT_CODE = 0x00001001
MOCK_REVISION = 0x00010000
MOCK_SERIAL_NUMBER = 0x12345678
MOCK_DEVICE_NAME = "MSF-ICS Mock EtherCAT Slave"
MOCK_HW_VERSION = "1.0.0"
MOCK_FW_VERSION = "2.1.0"
MOCK_FOE_FIRMWARE_SIZE = 512


# ===========================================================================
# Helpers
# ===========================================================================


def _make_scanner(**overrides):
    """Create an EtherCATScanner with sensible defaults."""
    defaults = {
        "interface": "eth0",
        "scan-range": "1-2",
    }
    defaults.update(overrides)
    return EtherCATScanner(defaults)


def _build_sii_header(
    vendor_id=MOCK_VENDOR_ID,
    product_code=MOCK_PRODUCT_CODE,
    revision=MOCK_REVISION,
    serial_number=MOCK_SERIAL_NUMBER,
    station_alias=0x0000,
    mbx_protocols=0x0C,  # CoE + FoE
    eeprom_size_kbit=4,
):
    """Build a valid 128-byte SII header for testing."""
    data = bytearray(128)
    struct.pack_into("<H", data, 0x00, 0x0080)  # PDI control
    struct.pack_into("<H", data, 0x04, 0x0001)  # SII version
    struct.pack_into("<H", data, 0x08, station_alias)
    struct.pack_into("<I", data, 0x10, vendor_id)
    struct.pack_into("<I", data, 0x14, product_code)
    struct.pack_into("<I", data, 0x18, revision)
    struct.pack_into("<I", data, 0x1C, serial_number)
    # Standard mailbox config
    struct.pack_into("<H", data, 0x30, 0x1000)  # rx offset
    struct.pack_into("<H", data, 0x32, 128)  # rx size
    struct.pack_into("<H", data, 0x34, 0x1080)  # tx offset
    struct.pack_into("<H", data, 0x36, 128)  # tx size
    struct.pack_into("<H", data, 0x38, mbx_protocols)
    # Bootstrap mailbox
    struct.pack_into("<H", data, 0x28, 0x1000)  # boot rx offset
    struct.pack_into("<H", data, 0x2A, 64)  # boot rx size
    struct.pack_into("<H", data, 0x2C, 0x1040)  # boot tx offset
    struct.pack_into("<H", data, 0x2E, 64)  # boot tx size
    struct.pack_into("<H", data, 0x7C, eeprom_size_kbit - 1)
    # Compute and set CRC
    crc = calculate_sii_crc(bytes(data))
    data[0x0E] = crc
    return bytes(data)


def _build_eeprom_image():
    """Build a complete EEPROM image with header + ESI categories.

    Returns a dict mapping word_address -> 4-byte data (pysoem returns 4 bytes
    per eeprom_read call, but only the first 2 are significant per word).
    """
    raw = bytearray(2048)  # 1024 words

    # Header (bytes 0x00-0x7F)
    header = _build_sii_header()
    raw[0x00 : 0x00 + len(header)] = header

    # Categories start at byte 0x80

    offset = 0x80

    # --- STRINGS category (type 10) ---
    strings_payload = bytearray()
    test_strings = [MOCK_DEVICE_NAME, "MSF-ICS", "EK-Mock-0001"]
    strings_payload.append(len(test_strings))
    for s in test_strings:
        encoded = s.encode("ascii")
        strings_payload.append(len(encoded))
        strings_payload.extend(encoded)
    # Pad to even length
    if len(strings_payload) % 2:
        strings_payload.append(0)

    struct.pack_into("<H", raw, offset, 10)  # cat type
    struct.pack_into("<H", raw, offset + 2, len(strings_payload) // 2)
    raw[offset + 4 : offset + 4 + len(strings_payload)] = strings_payload
    offset += 4 + len(strings_payload)

    # --- GENERAL category (type 30) ---
    general_payload = bytearray(18)
    general_payload[0] = 1  # group_idx -> strings[1]
    general_payload[1] = 0  # image_idx
    general_payload[2] = 3  # order_idx -> strings[3]
    general_payload[3] = 1  # name_idx -> strings[1] (device name)
    general_payload[5] = 0x3F  # coe_details (all features)
    general_payload[11] = 0x01  # flags (enable_safeop)
    struct.pack_into("<h", general_payload, 12, 200)  # current_on_ebus_ma
    struct.pack_into("<H", general_payload, 16, 0x3022)  # physical_port

    struct.pack_into("<H", raw, offset, 30)
    struct.pack_into("<H", raw, offset + 2, len(general_payload) // 2)
    raw[offset + 4 : offset + 4 + len(general_payload)] = general_payload
    offset += 4 + len(general_payload)

    # --- FMMU category (type 40) ---
    fmmu_payload = bytes([0x01, 0x02])  # outputs, inputs
    if len(fmmu_payload) % 2:
        fmmu_payload = fmmu_payload + b"\x00"

    struct.pack_into("<H", raw, offset, 40)
    struct.pack_into("<H", raw, offset + 2, len(fmmu_payload) // 2)
    raw[offset + 4 : offset + 4 + len(fmmu_payload)] = fmmu_payload
    offset += 4 + len(fmmu_payload)

    # --- SyncManager category (type 41) ---
    sm_payload = bytearray()
    for sm_type, ctrl, start, length in [
        (1, 0x26, 0x1000, 128),  # mbx_out
        (2, 0x22, 0x1080, 128),  # mbx_in
        (3, 0x64, 0x1100, 4),  # pdo_out
        (4, 0x20, 0x1180, 4),  # pdo_in
    ]:
        sm_payload.extend(struct.pack("<H", start))
        sm_payload.extend(struct.pack("<H", length))
        sm_payload.append(ctrl)
        sm_payload.append(0x00)  # status
        sm_payload.append(0x01)  # enable
        sm_payload.append(sm_type)

    struct.pack_into("<H", raw, offset, 41)
    struct.pack_into("<H", raw, offset + 2, len(sm_payload) // 2)
    raw[offset + 4 : offset + 4 + len(sm_payload)] = sm_payload
    offset += 4 + len(sm_payload)

    # --- End marker ---
    struct.pack_into("<H", raw, offset, 0xFFFF)
    struct.pack_into("<H", raw, offset + 2, 0x0000)

    # Convert to word-addressed dict for eeprom_read mock
    eeprom_words = {}
    for word_addr in range(1024):
        byte_offset = word_addr * 2
        if byte_offset + 2 <= len(raw):
            # pysoem eeprom_read returns 4 bytes, first 2 are the word
            eeprom_words[word_addr] = bytes(raw[byte_offset : byte_offset + 2]) + b"\x00\x00"
        else:
            eeprom_words[word_addr] = b"\x00\x00\x00\x00"

    return eeprom_words


def _make_mock_slave(
    name=MOCK_DEVICE_NAME,
    man=MOCK_VENDOR_ID,
    prod=MOCK_PRODUCT_CODE,
    rev=MOCK_REVISION,
    serial=MOCK_SERIAL_NUMBER,
    state=0x04,  # SAFE-OP
    al_status=0,
    input_bytes=4,
    output_bytes=4,
    with_sdo=True,
    with_eeprom=True,
    with_foe=True,
):
    """Create a realistic mock pysoem slave object."""
    slave = Mock()
    slave.name = name
    slave.man = man
    slave.id = prod
    slave.rev = rev
    slave.serial = serial
    slave.state = state
    slave.al_status = al_status
    slave.input = bytes(input_bytes)
    slave.output = bytearray(output_bytes)
    slave.delay = 100
    slave.port_des = 0x0302
    slave.FMMUfunc = 2
    slave.SMfunc = 4
    slave.group = ""
    slave.image = ""
    slave.dtype = ""

    # SDO data table matching the Docker mock
    sdo_data = {
        (0x1000, 0): struct.pack("<I", 0x00000191),  # Device Type: servo drive
        (0x1001, 0): struct.pack("<B", 0x00),  # Error Register: no error
        (0x1008, 0): MOCK_DEVICE_NAME.encode("utf-8") + b"\x00",
        (0x1009, 0): MOCK_HW_VERSION.encode("utf-8") + b"\x00",
        (0x100A, 0): MOCK_FW_VERSION.encode("utf-8") + b"\x00",
        (0x1018, 0): struct.pack("<B", 4),  # subindex count
        (0x1018, 1): struct.pack("<I", MOCK_VENDOR_ID),
        (0x1018, 2): struct.pack("<I", MOCK_PRODUCT_CODE),
        (0x1018, 3): struct.pack("<I", MOCK_REVISION),
        (0x1018, 4): struct.pack("<I", MOCK_SERIAL_NUMBER),
        # FSoE safety objects
        (0xF100, 0): struct.pack("<B", 16),  # subindex count
        (0xF100, 1): struct.pack("<B", 0x01),  # Safety Project State
        (0xF100, 5): struct.pack("<B", 2),  # FSoE Module Count
    }

    if with_sdo:

        def _sdo_read(index, subindex):
            key = (index, subindex)
            if key in sdo_data:
                return sdo_data[key]
            raise Exception(f"SDO abort: object 0x{index:04X}:{subindex} not found")

        slave.sdo_read = Mock(side_effect=_sdo_read)
        slave.sdo_write = Mock()  # Accept any write
    else:
        slave.sdo_read = Mock(side_effect=Exception("SDO not supported"))
        slave.sdo_write = Mock(side_effect=Exception("SDO not supported"))

    # EEPROM data
    if with_eeprom:
        eeprom_words = _build_eeprom_image()

        def _eeprom_read(word_addr):
            return eeprom_words.get(word_addr, b"\x00\x00\x00\x00")

        slave.eeprom_read = Mock(side_effect=_eeprom_read)
        slave.eeprom_write = Mock()
    else:
        slave.eeprom_read = Mock(side_effect=Exception("EEPROM not available"))
        slave.eeprom_write = Mock(side_effect=Exception("EEPROM not available"))

    # FoE data
    if with_foe:
        firmware_data = bytes(range(256)) * (MOCK_FOE_FIRMWARE_SIZE // 256)

        def _foe_read(filename, password=0, size=1048576, timeout=10000000):
            if filename == "firmware.bin":
                return firmware_data
            raise Exception(f"FoE: file '{filename}' not found")

        slave.foe_read = Mock(side_effect=_foe_read)
        slave.foe_write = Mock()
    else:
        slave.foe_read = Mock(side_effect=Exception("FoE not supported"))
        slave.foe_write = Mock(side_effect=Exception("FoE not supported"))

    # DC support
    slave.dc_sync = Mock()

    # Emergency callback
    slave.add_emergency_callback = Mock()

    return slave


def _make_mock_master(slaves=None, expected_wkc=3):
    """Create a mock pysoem master with slave list."""
    if slaves is None:
        slaves = [_make_mock_slave(), _make_mock_slave(name="MSF-ICS Mock Slave 2")]

    master = Mock()
    master.slaves = slaves
    master.expected_wkc = expected_wkc
    master.state = 0x04  # SAFE-OP
    master.dc_time = 1000000000  # 1 second in ns
    master.send_processdata = Mock()
    master.receive_processdata = Mock(return_value=expected_wkc)
    master.config_init = Mock(return_value=len(slaves))
    master.config_map = Mock()
    master.config_dc = Mock()
    master.state_check = Mock()
    master.write_state = Mock()
    master.read_state = Mock()
    master.close = Mock()
    master.open = Mock()
    return master


def _make_mock_pysoem_module():
    """Create a mock pysoem module with state constants."""
    mock_pysoem = MagicMock()
    mock_pysoem.NONE_STATE = 0x00
    mock_pysoem.INIT_STATE = 0x01
    mock_pysoem.PREOP_STATE = 0x02
    mock_pysoem.BOOT_STATE = 0x03
    mock_pysoem.SAFEOP_STATE = 0x04
    mock_pysoem.OP_STATE = 0x08
    mock_pysoem.STATE_ERROR = 0x10
    mock_pysoem.ConfigMapError = type("ConfigMapError", (Exception,), {})
    return mock_pysoem


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def mock_pysoem():
    """Provide a mock pysoem module."""
    return _make_mock_pysoem_module()


@pytest.fixture
def mock_master():
    """Provide a mock EtherCAT master with 2 realistic slaves."""
    return _make_mock_master()


@pytest.fixture
def mock_slave():
    """Provide a single mock EtherCAT slave."""
    return _make_mock_slave()


# ===========================================================================
# Test Class
# ===========================================================================


@pytest.mark.ethercat
class TestEtherCATMockedIntegration:
    """Category A integration tests exercising full scanner logic with mocked pysoem.

    These tests bypass the raw socket requirement by mocking pysoem at the
    Python level, allowing us to test every scanner feature with realistic
    slave data matching the Docker mock values.
    """

    # ====================================================================
    # Basic Discovery Tests
    # ====================================================================

    def test_discover_finds_slaves(self):
        """Test discover() finds and reports all slaves [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-2"})
        master = _make_mock_master()

        results = scanner.discover(master)

        assert "slaves" in results
        assert len(results["slaves"]) == 2
        assert results["slaves"][1]["name"] == MOCK_DEVICE_NAME
        assert results["slaves"][1]["manufacturer_id"] == MOCK_VENDOR_ID
        assert results["slaves"][1]["product_code"] == MOCK_PRODUCT_CODE
        assert results["slaves"][1]["revision"] == MOCK_REVISION

    def test_discover_result_structure(self):
        """Test discover() returns all expected result keys [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-2"})
        master = _make_mock_master()

        results = scanner.discover(master)

        expected_keys = [
            "network_info",
            "slaves",
            "sdo_data",
            "eeprom_data",
            "eeprom_raw",
            "dc_analysis",
            "foe_results",
            "emergency_messages",
            "fuzzing_results",
            "fsoe_data",
            "security_analysis",
        ]
        for key in expected_keys:
            assert key in results, f"Missing result key: {key}"

    def test_network_info_populated(self):
        """Test network info contains correct data [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-2"})
        master = _make_mock_master()

        results = scanner.discover(master)

        info = results["network_info"]
        assert info["interface"] == "eth0"
        assert info["slave_count"] == 2
        assert info["expected_wkc"] == 3
        assert "timestamp" in info

    def test_slave_state_reported(self):
        """Test slave state is correctly decoded [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        slave = _make_mock_slave(state=0x04)
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert results["slaves"][1]["state"] == "SAFE-OP"
        assert results["slaves"][1]["state_code"] == 0x04

    def test_slave_io_map(self):
        """Test slave I/O map data is reported [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        slave = _make_mock_slave(input_bytes=8, output_bytes=4)
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        io = results["slaves"][1]["io_map"]
        assert io["input_bytes"] == 8
        assert io["output_bytes"] == 4

    # ====================================================================
    # Device Info (SDO Enrichment) Tests
    # ====================================================================

    def test_device_info_enriches_slaves(self):
        """Test --device-info reads SDO objects to enrich slave data [Category A]"""
        scanner = _make_scanner(**{"device-info": True, "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        slave_info = results["slaves"][1]
        assert slave_info["device_name_sdo"] == MOCK_DEVICE_NAME
        assert slave_info["hw_version"] == MOCK_HW_VERSION
        assert slave_info["fw_version"] == MOCK_FW_VERSION

    def test_device_info_reads_identity_objects(self):
        """Test --device-info reads Identity Object (0x1018) [Category A]"""
        scanner = _make_scanner(**{"device-info": True, "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        slave_info = results["slaves"][1]
        # Serial number from SDO 0x1018:4
        assert slave_info.get("serial_number") == f"0x{MOCK_SERIAL_NUMBER:08X}"
        # Revision from SDO 0x1018:3
        assert slave_info.get("revision_sdo") == f"0x{MOCK_REVISION:08X}"

    # ====================================================================
    # EEPROM Reading Tests
    # ====================================================================

    def test_eeprom_data_read(self):
        """Test EEPROM data is read with --device-info --dump [Category A]"""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(
                **{
                    "device-info": True,
                    "scan-range": "1-1",
                },
                dump=tmpdir,
            )
            slave = _make_mock_slave()
            master = _make_mock_master(slaves=[slave])

            results = scanner.discover(master)

            assert "eeprom_data" in results
            assert 1 in results["eeprom_data"]
            eeprom = results["eeprom_data"][1]
            assert "general" in eeprom
            assert eeprom["general"]["vendor_id"] == MOCK_VENDOR_ID
            assert eeprom["general"]["product_code"] == MOCK_PRODUCT_CODE
            assert eeprom["general"]["serial_number"] == MOCK_SERIAL_NUMBER

    def test_eeprom_dump_full(self):
        """Test --eeprom-dump reads all 128 EEPROM words [Category A]"""
        scanner = _make_scanner(**{"eeprom-dump": True, "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert "eeprom_raw" in results
        assert 1 in results["eeprom_raw"]
        raw = results["eeprom_raw"][1]
        assert raw["total_bytes"] == 128 * 4
        assert len(raw["data"]) == 128

    def test_eeprom_parse_esi(self):
        """Test --eeprom-parse reads and parses ESI structure [Category A]"""
        scanner = _make_scanner(**{"eeprom-parse": True, "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert "eeprom_parsed" in results
        parsed = results["eeprom_parsed"]
        assert 1 in parsed

        slave_esi = parsed[1]
        assert "header" in slave_esi
        header = slave_esi["header"]
        assert header["vendor_id"] == MOCK_VENDOR_ID
        assert header["product_code"] == MOCK_PRODUCT_CODE
        assert header["serial_number"] == MOCK_SERIAL_NUMBER
        assert header["crc_valid"] is True

        # Should have found categories
        assert len(slave_esi["categories_found"]) >= 3
        cat_names = [c["name"] for c in slave_esi["categories_found"]]
        assert "STRINGS" in cat_names
        assert "GENERAL" in cat_names

    def test_eeprom_parse_mailbox_protocols(self):
        """Test EEPROM parse shows CoE+FoE mailbox protocols [Category A]"""
        scanner = _make_scanner(**{"eeprom-parse": True, "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        parsed = results["eeprom_parsed"][1]
        header = parsed["header"]
        mbx = header["mailbox_protocol_flags"]
        assert mbx["CoE"] is True
        assert mbx["FoE"] is True
        assert mbx["AoE"] is False

    # ====================================================================
    # SDO Read/Write Tests
    # ====================================================================

    def test_sdo_data_read(self):
        """Test SDO data reading with --device-info --dump [Category A]"""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(
                **{
                    "device-info": True,
                    "scan-range": "1-1",
                },
                dump=tmpdir,
            )
            slave = _make_mock_slave()
            master = _make_mock_master(slaves=[slave])

            results = scanner.discover(master)

            assert "sdo_data" in results
            assert 1 in results["sdo_data"]

    def test_sdo_read_command(self):
        """Test --sdo-read / -r reads specific SDO object [Category A]"""
        scanner = _make_scanner(**{"sdo-read": "1:0x1008:0", "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        result = scanner._execute_sdo_read(master)

        assert result["success"] is True
        assert result["slave"] == 1
        assert result["index"] == "0x1008"
        assert result["subindex"] == 0
        assert MOCK_DEVICE_NAME.encode("utf-8").hex() in result["data"]

    def test_sdo_read_numeric_value(self):
        """Test SDO read for numeric objects returns value [Category A]"""
        scanner = _make_scanner(**{"sdo-read": "0x1000:0", "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        result = scanner._execute_sdo_read(master)

        assert result["success"] is True
        assert result["value"] == 0x00000191

    def test_sdo_write_with_confirm(self):
        """Test SDO write succeeds with --confirm [Category A]"""
        scanner = _make_scanner(
            **{"sdo-write": "1:0x7000:1:0xFF", "scan-range": "1-1"},
            confirm=True,
        )
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert "sdo_write_result" in results
        assert results["sdo_write_result"]["success"] is True

    def test_sdo_write_blocked_without_confirm(self):
        """Test SDO write is blocked without --confirm [Category A]"""
        scanner = _make_scanner(
            **{"sdo-write": "1:0x7000:1:0xFF", "scan-range": "1-1"},
            confirm=False,
        )
        master = _make_mock_master()

        results = scanner.discover(master)

        assert "sdo_write_result" not in results

    # ====================================================================
    # CoE Dictionary Scan Tests
    # ====================================================================

    def test_coe_dictionary_scan(self):
        """Test -C / --scan-coe scans object dictionary [Category A]"""
        scanner = _make_scanner(
            **{
                "sdo-scan": True,
                "coe-range": "0x1000-0x1020",
                "scan-range": "1-1",
            }
        )
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert "coe_dictionary" in results
        coe = results["coe_dictionary"]
        assert 1 in coe
        assert "objects" in coe[1]
        assert "access_stats" in coe[1]
        # Should have found at least some readable objects
        total_ro = coe[1]["access_stats"]["RO"]
        total_rw = coe[1]["access_stats"]["RW"]
        assert total_ro + total_rw > 0

    # ====================================================================
    # FoE (File over EtherCAT) Tests
    # ====================================================================

    def test_foe_read_firmware(self):
        """Test --foe-read reads file from slave [Category A]"""
        scanner = _make_scanner(
            **{"foe-read": "1:firmware.bin", "scan-range": "1-1"},
        )
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        result = scanner._foe_read_file(master)

        assert result["success"] is True
        assert result["slave"] == 1
        assert result["filename"] == "firmware.bin"
        assert result["size"] == MOCK_FOE_FIRMWARE_SIZE

    def test_foe_read_saves_to_dump(self):
        """Test FoE read saves file when --dump is specified [Category A]"""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(
                **{"foe-read": "1:firmware.bin", "scan-range": "1-1"},
                dump=tmpdir,
            )
            slave = _make_mock_slave()
            master = _make_mock_master(slaves=[slave])

            results = scanner.discover(master)

            foe = results["foe_results"]
            assert "read" in foe
            assert foe["read"]["success"] is True
            # Check file was saved
            saved_files = os.listdir(tmpdir)
            foe_files = [f for f in saved_files if f.startswith("foe_")]
            assert len(foe_files) >= 1

    def test_foe_read_nonexistent_file(self):
        """Test FoE read fails gracefully for missing file [Category A]"""
        scanner = _make_scanner(
            **{"foe-read": "1:nonexistent.bin", "scan-range": "1-1"},
        )
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        result = scanner._foe_read_file(master)

        assert result["success"] is False
        assert "error" in result

    def test_foe_write_with_confirm(self):
        """Test FoE write succeeds with --confirm [Category A]"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 256)
            fname = f.name

        try:
            scanner = _make_scanner(
                **{"foe-write": f"1:{fname}", "scan-range": "1-1"},
                confirm=True,
            )
            slave = _make_mock_slave()
            master = _make_mock_master(slaves=[slave])

            results = scanner.discover(master)

            foe = results["foe_results"]
            assert "write" in foe
            assert foe["write"]["success"] is True
            assert foe["write"]["size"] == 256
        finally:
            os.unlink(fname)

    # ====================================================================
    # Distributed Clock Analysis Tests
    # ====================================================================

    def test_dc_analysis(self):
        """Test --dc-analysis analyzes distributed clock [Category A]"""
        scanner = _make_scanner(**{"dc-analysis": True, "scan-range": "1-2"})
        master = _make_mock_master()

        results = scanner.discover(master)

        dc = results["dc_analysis"]
        assert dc["dc_configured"] is True
        assert len(dc["slaves_with_dc"]) >= 1
        assert dc["sync_errors"] == []

    def test_dc_analysis_detects_sync_errors(self):
        """Test DC analysis detects sync errors via AL status [Category A]"""
        scanner = _make_scanner(**{"dc-analysis": True, "scan-range": "1-1"})
        slave = _make_mock_slave(al_status=0x0026)  # Invalid DC SYNC configuration
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        dc = results["dc_analysis"]
        assert len(dc["sync_errors"]) > 0
        assert dc["sync_errors"][0]["slave"] == 1

    # ====================================================================
    # FSoE (Functional Safety) Tests
    # ====================================================================

    def test_fsoe_scan(self):
        """Test --scan-fsoe reads FSoE safety objects [Category A]"""
        scanner = _make_scanner(**{"scan-fsoe": True, "scan-range": "1-1"})
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        fsoe = results["fsoe_data"]
        assert 1 in fsoe
        fsoe_objects = fsoe[1]
        assert len(fsoe_objects) >= 1
        # Check structure
        obj = fsoe_objects[0]
        assert "index" in obj
        assert "name" in obj
        assert "value" in obj

    # ====================================================================
    # Security Analysis Tests
    # ====================================================================

    def test_security_analysis_present(self):
        """Test security analysis is always present in results [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        master = _make_mock_master(slaves=[_make_mock_slave()])

        results = scanner.discover(master)

        analysis = results["security_analysis"]
        assert analysis["authentication"] is False
        assert analysis["encryption"] is False
        assert analysis["access_control"] is False
        assert "issues" in analysis
        assert len(analysis["issues"]) > 0

    def test_security_analysis_identifies_inherent_weaknesses(self):
        """Test security analysis reports EtherCAT weaknesses [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        master = _make_mock_master(slaves=[_make_mock_slave()])

        results = scanner.discover(master)

        issues = results["security_analysis"]["issues"]
        issue_text = " ".join(issues).lower()
        assert "authentication" in issue_text or "no auth" in issue_text
        assert "encryption" in issue_text or "no encrypt" in issue_text

    def test_security_analysis_has_score(self):
        """Test security analysis produces a security score [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        master = _make_mock_master(slaves=[_make_mock_slave()])

        results = scanner.discover(master)

        analysis = results["security_analysis"]
        assert "security_level" in analysis
        assert "security_score" in analysis

    # ====================================================================
    # Emergency Monitoring Tests
    # ====================================================================

    def test_emergency_monitoring_setup(self):
        """Test emergency callbacks are registered for each slave [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-2"})
        slaves = [_make_mock_slave(), _make_mock_slave()]
        master = _make_mock_master(slaves=slaves)

        scanner.discover(master)

        # Both slaves should have emergency callbacks registered
        for slave in slaves:
            slave.add_emergency_callback.assert_called_once()

    def test_emergency_monitoring_disabled(self):
        """Test --no-emergency-monitor skips callback setup [Category A]"""
        scanner = _make_scanner(
            **{"emergency-monitor": False, "scan-range": "1-2"},
        )
        slaves = [_make_mock_slave(), _make_mock_slave()]
        master = _make_mock_master(slaves=slaves)

        scanner.discover(master)

        # No emergency callbacks should be registered
        for slave in slaves:
            slave.add_emergency_callback.assert_not_called()

    # ====================================================================
    # Data Export Tests
    # ====================================================================

    def test_dump_exports_json_files(self):
        """Test --dump exports data to JSON files [Category A]"""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(
                **{
                    "device-info": True,
                    "scan-range": "1-1",
                },
                dump=tmpdir,
            )
            slave = _make_mock_slave()
            master = _make_mock_master(slaves=[slave])

            scanner.discover(master)

            # Check that JSON files were created
            files = os.listdir(tmpdir)
            json_files = [f for f in files if f.endswith(".json")]
            assert len(json_files) >= 1, f"Expected JSON export files, got: {files}"

    # ====================================================================
    # Slave Selection Tests
    # ====================================================================

    def test_slave_filter_with_scan_range(self):
        """Test --scan-range limits which slaves are scanned [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        slaves = [_make_mock_slave(), _make_mock_slave(name="Slave 2")]
        master = _make_mock_master(slaves=slaves)

        results = scanner.discover(master)

        # Only slave 1 should be in results
        assert 1 in results["slaves"]
        assert 2 not in results["slaves"]

    def test_slave_filter_with_slave_flag(self):
        """Test -S / --slave limits to single slave [Category A]"""
        scanner = _make_scanner(slave=2, **{"scan-range": "1-4"})
        slaves = [
            _make_mock_slave(name="Slave 1"),
            _make_mock_slave(name="Slave 2"),
        ]
        master = _make_mock_master(slaves=slaves)

        results = scanner.discover(master)

        assert 2 in results["slaves"]
        assert 1 not in results["slaves"]

    # ====================================================================
    # Connect / Disconnect Tests
    # ====================================================================

    @patch("oida.protocols.ethercat.check_raw_socket_capability")
    @patch("oida.protocols.ethercat._get_pysoem")
    def test_connect_success(self, mock_get_pysoem, mock_raw_socket):
        """Test connect() initializes master successfully [Category A]"""
        mock_raw_socket.return_value = (True, None)

        mock_pysoem = _make_mock_pysoem_module()
        master = _make_mock_master()
        mock_pysoem.Master.return_value = master
        mock_get_pysoem.return_value = mock_pysoem

        scanner = _make_scanner()
        result = scanner.connect()

        assert result is not None
        master.open.assert_called_once_with("eth0")
        master.config_init.assert_called_once()

    @patch("oida.protocols.ethercat.check_raw_socket_capability")
    @patch("oida.protocols.ethercat._get_pysoem")
    def test_connect_no_slaves(self, mock_get_pysoem, mock_raw_socket):
        """Test connect() handles no-slaves scenario gracefully [Category A]"""
        mock_raw_socket.return_value = (True, None)

        mock_pysoem = _make_mock_pysoem_module()
        master = _make_mock_master(slaves=[])
        master.config_init.return_value = 0
        mock_pysoem.Master.return_value = master
        mock_get_pysoem.return_value = mock_pysoem

        scanner = _make_scanner()
        result = scanner.connect()

        # Should return master even with no slaves (for manual operations)
        assert result is not None

    @patch("oida.protocols.ethercat.check_raw_socket_capability")
    def test_connect_no_raw_socket(self, mock_raw_socket):
        """Test connect() fails gracefully without raw socket [Category A]"""
        mock_raw_socket.return_value = (False, "No raw socket capability")

        scanner = _make_scanner()
        result = scanner.connect()

        assert result is None

    @patch("oida.protocols.ethercat._get_pysoem")
    def test_disconnect_clean(self, mock_get_pysoem):
        """Test disconnect() closes master cleanly [Category A]"""
        mock_pysoem = _make_mock_pysoem_module()
        mock_get_pysoem.return_value = mock_pysoem

        scanner = _make_scanner()
        master = _make_mock_master()

        scanner.disconnect(master)

        master.close.assert_called_once()

    # ====================================================================
    # EEPROM Write Operations Tests
    # ====================================================================

    def test_eeprom_write_with_confirm(self):
        """Test EEPROM write succeeds with --confirm [Category A]"""
        scanner = _make_scanner(
            **{"eeprom-write": "0x08:0x1234", "scan-range": "1-1"},
            confirm=True,
        )
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert "eeprom_write_result" in results
        assert results["eeprom_write_result"]["success"] is True

    def test_set_alias_with_confirm(self):
        """Test --set-alias writes station alias with --confirm [Category A]"""
        scanner = _make_scanner(
            **{"set-alias": "1:42", "scan-range": "1-1"},
            confirm=True,
        )
        slave = _make_mock_slave()
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert "set_alias_result" in results
        result = results["set_alias_result"]
        assert result["success"] is True
        assert result["alias"] == 42

    # ====================================================================
    # Combined Feature Tests
    # ====================================================================

    def test_full_scan_all_features(self):
        """Test full scan with multiple features enabled [Category A]"""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = _make_scanner(
                **{
                    "device-info": True,
                    "eeprom-dump": True,
                    "eeprom-parse": True,
                    "dc-analysis": True,
                    "scan-fsoe": True,
                    "scan-range": "1-2",
                    "foe-read": "1:firmware.bin",
                },
                dump=tmpdir,
            )
            master = _make_mock_master()

            results = scanner.discover(master)

            # Verify all feature results are present
            assert len(results["slaves"]) == 2
            assert results["eeprom_raw"][1]["total_bytes"] == 128 * 4
            assert "eeprom_parsed" in results
            assert results["dc_analysis"]["dc_configured"] is True
            assert "fsoe_data" in results
            assert results["foe_results"]["read"]["success"] is True
            assert len(results["security_analysis"]["issues"]) > 0

            # Verify export files were created
            files = os.listdir(tmpdir)
            assert len(files) >= 1

    def test_tree_view_display(self):
        """Test slave tree view is displayed without errors [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-2"})
        slaves = [
            _make_mock_slave(name="EK1100", input_bytes=0, output_bytes=0),
            _make_mock_slave(name="EL2004", input_bytes=1, output_bytes=0),
        ]
        master = _make_mock_master(slaves=slaves)

        # Should not raise any exceptions
        results = scanner.discover(master)
        assert len(results["slaves"]) == 2

    def test_report_findings_runs(self):
        """Test _report_findings executes without errors [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        master = _make_mock_master(slaves=[_make_mock_slave()])

        # discover() calls _report_findings() internally
        results = scanner.discover(master)
        assert results is not None

    # ====================================================================
    # Slave with Error State Tests
    # ====================================================================

    def test_slave_with_error_state(self):
        """Test slave in error state is correctly reported [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        slave = _make_mock_slave(state=0x14, al_status=0x001A)
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        slave_info = results["slaves"][1]
        assert slave_info["state"] == "SAFE-OP+ERROR"
        assert slave_info["al_status_error"] is not None

    # ====================================================================
    # Bytes Name Handling Tests
    # ====================================================================

    def test_slave_name_bytes_decoded(self):
        """Test slave name from bytes is correctly decoded [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        slave = _make_mock_slave(name=b"EL1004\x00\x00")
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert results["slaves"][1]["name"] == "EL1004"

    def test_slave_name_empty_gets_default(self):
        """Test slave with empty name gets default name [Category A]"""
        scanner = _make_scanner(**{"scan-range": "1-1"})
        slave = _make_mock_slave(name="")
        master = _make_mock_master(slaves=[slave])

        results = scanner.discover(master)

        assert results["slaves"][1]["name"] == "Slave_1"
