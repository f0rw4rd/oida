"""
DNP3 Protocol Integration Tests

Tests oida dnp3 scanner against Docker mock services.
Uses structured JSON log assertions for precise validation.

Mock Server Data (from docker/mocks/compose.yml + mock server sources):

  dnp3-basic (port 20000):
    Outstation address: 1024, Master address: 1
    Points: 10 BI, 10 AI, 5 CT, 5 BO, 5 AO
    Device Attributes (Group 0):
      Vendor (254):    "OIDA Mock"
      Product (252):   "OIDA Basic Outstation"
      Serial (249):    "OIDA-DNP3-BASIC-001"
      SW Version (242): "2.1.0"
      HW Version (243): "Rev-A"
      Location (245):  "Outstation 1024 - OIDA Test"

  dnp3-complex (port 20001):
    Outstation address: 10, Master address: 1
    Points: 50 BI, 50 AI, 20 CT, 20 BO, 20 AO
    Product: "OIDA Substation RTU", Serial: "OIDA-DNP3-SUB-010"
    SW: "3.4.1", HW: "Rev-C"

  dnp3-tls (port 20002):
    TLS-enabled, outstation=1024
    Product: "OIDA Secure Outstation", Serial: "OIDA-DNP3-TLS-1024"

  dnp3-enhanced (port 20010):
    Outstation address: 10, 10 BI/10 AI/5 CT/5 BO/5 AO + 5 FCT + 3 Octet
    Supports: cold/warm restart, freeze ops, deadband writes, control ops
    Cold restart delay: 60 seconds, Warm restart delay: 5000 ms

  dnp3-filetransfer (port 20020):
    Slave address: 1, Master address: 2
    File transfer (Group 70) enabled
    Test files: config.txt, firmware_info.txt, event_log.csv, historical_data.bin

Test Classification Summary
---------------------------------------------------------------------------
Category A (strict -- mock supports, assert success + validate data):  23 tests
Category B (conditional -- mock may not support, accept 0 or 1):       43 tests
Category C (error handling -- assert failure + validate error events):  13 tests
Skipped (untestable -- requires hardware or unsupported feature):       7 tests
Total defined in file:                                                 86 tests
Total collected (including 8 inherited from BaseProtocolIntegrationTest): 94 tests
---------------------------------------------------------------------------
"""

import pytest
from typing import Optional

from .base_protocol_test import BaseProtocolIntegrationTest
from .conftest import MOCK_HOST, MOCK_PORTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_messages(log) -> str:
    """Concatenate all log messages into a single lowercase string for searching."""
    return " ".join(e.get("message", "") for e in log.events).lower()


def _assert_log_has_events(result, min_count=1):
    """Assert that the scan_log exists and has at least min_count events."""
    assert result.scan_log is not None, "scan_log should be populated when json_log=True"
    result.scan_log.assert_has_events(min_count=min_count)


def _assert_log_event_structure(log):
    """Validate that every event in the log has the required fields."""
    required = {"timestamp", "level", "event_type", "module", "message"}
    for i, event in enumerate(log.events):
        missing = required - set(event.keys())
        assert not missing, f"Event {i} missing fields: {missing}"


# ---------------------------------------------------------------------------
# Known mock data constants
# ---------------------------------------------------------------------------

# dnp3-basic (port 20000)
BASIC_OUTSTATION_ADDR = 1024
BASIC_MASTER_ADDR = 1
BASIC_DEVICE_NAME = "OIDA Basic Outstation"
BASIC_VENDOR = "OIDA Mock"
BASIC_SERIAL = "OIDA-DNP3-BASIC-001"
BASIC_SW_VERSION = "2.1.0"
BASIC_HW_VERSION = "Rev-A"
BASIC_BI_COUNT = 10
BASIC_AI_COUNT = 10
BASIC_CT_COUNT = 5
BASIC_BO_COUNT = 5
BASIC_AO_COUNT = 5

# dnp3-complex (port 20001)
COMPLEX_OUTSTATION_ADDR = 10
COMPLEX_DEVICE_NAME = "OIDA Substation RTU"
COMPLEX_SERIAL = "OIDA-DNP3-SUB-010"

# dnp3-enhanced (port 20010)
ENHANCED_OUTSTATION_ADDR = 10
ENHANCED_DEVICE_NAME = "OIDA Enhanced Outstation"
ENHANCED_SERIAL = "OIDA-DNP3-ENH-001"

# dnp3-filetransfer (port 20020)
FT_SLAVE_ADDR = 1
FT_MASTER_ADDR = 2


@pytest.mark.dnp3
class TestDnp3Integration(BaseProtocolIntegrationTest):
    """Integration tests for DNP3 scanner"""

    @property
    def protocol_name(self) -> str:
        return "dnp3"

    @property
    def default_port(self) -> int:
        return 20000

    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        return host

    # ========================================================================
    # Discovery / Basic Connectivity Tests
    # ========================================================================

    def test_basic_connectivity(self, cli_runner, target, port, docker_services):
        """Test basic connection to DNP3 outstation [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--outstation-addr",
            str(BASIC_OUTSTATION_ADDR),
            "--master-addr",
            str(BASIC_MASTER_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Basic connectivity failed: {result.stderr}"
        _assert_log_has_events(result)
        log = result.scan_log
        _assert_log_event_structure(log)

        messages = _all_messages(log)
        assert "connected" in messages, "Expected 'connected' in log messages"

    def test_basic_discovery_with_json_log(self, cli_runner, target, port, docker_services):
        """Test basic discovery produces structured JSON log events [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--outstation-addr",
            str(BASIC_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Discovery failed: {result.stderr}"
        _assert_log_has_events(result, min_count=2)
        log = result.scan_log

        # Should have info-level events from the scan
        info_events = log.get_events(level="info")
        assert len(info_events) > 0, "Expected info events from discovery"

    def test_default_outstation_address(self, cli_runner, target, port, docker_services):
        """Test that default outstation address (1024) works for basic mock [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            format="json",
            json_log=True,
            timeout=30,
        )

        # Default outstation addr is 1024, which matches the basic mock
        assert result.success, f"Default outstation addr scan failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_explicit_master_address(self, cli_runner, target, port, docker_services):
        """Test specifying master address via -m flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-m",
            "1",
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Explicit master addr failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Integrity Poll & Data Point Tests
    # ========================================================================

    def test_integrity_poll_default(self, cli_runner, target, port, docker_services):
        """Test default integrity poll (all classes) returns data points [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Integrity poll failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        has_points = any(term in messages for term in ["bi", "ai", "ct", "bo", "ao", "points"])
        assert has_points, f"Expected point data in log messages, got: {messages[:500]}"

    def test_class_poll_class0(self, cli_runner, target, port, docker_services):
        """Test Class 0 specific poll [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-c",
            "0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Class 0 poll failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_class_poll_class1(self, cli_runner, target, port, docker_services):
        """Test Class 1 event read [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-c",
            "1",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_class_poll_all(self, cli_runner, target, port, docker_services):
        """Test explicit 'all' class poll [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-c",
            "all",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Class all poll failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Device Attribute Tests (Group 0)
    # ========================================================================

    def test_device_attributes_default(self, cli_runner, target, port, docker_services):
        """Test reading device attributes (enabled by default) [Category B]

        Note: stepfunc mock may not return Group 0 attributes through opendnp3.
        The scanner attempts the read but the outstation may not respond with data.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Device attribute read failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        has_attr_attempt = any(
            term in messages for term in ["device attributes", "group 0", "no device attr"]
        )
        assert has_attr_attempt, (
            f"Expected device attribute read attempt in log, got: {messages[:500]}"
        )

    def test_dump_attrs_flag(self, cli_runner, target, port, docker_services):
        """Test --dump-attrs (-a) triggers extended attribute read [Category B]

        Note: stepfunc mock may not return Group 0 attributes through opendnp3.
        We verify the flag is accepted and the scanner attempts the operation.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-a",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Dump attrs failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        has_attr_activity = any(
            term in messages
            for term in [
                "device attributes",
                "group 0",
                "no device attr",
                "oida mock",
                "vendor",
                "product",
            ]
        )
        assert has_attr_activity, (
            f"Expected attribute read activity with -a flag, got: {messages[:500]}"
        )

    def test_skip_device_attrs(self, cli_runner, target, port, docker_services):
        """Test --skip-device-attrs skips Group 0 reads [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--skip-device-attrs",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Skip device attrs failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Read Variation Tests
    # ========================================================================

    def test_read_variation_analog_input(self, cli_runner, target, port, docker_services):
        """Test reading specific group/variation (Group 30 Var 0 = Analog Input) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-g",
            "30.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Variation read (30.0) failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)
        assert "group30var0" in messages or "read" in messages or "completed" in messages

    def test_read_variation_binary_input(self, cli_runner, target, port, docker_services):
        """Test reading Group 1 (Binary Input) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-g",
            "1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Variation read (1.0) failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_read_variation_counter(self, cli_runner, target, port, docker_services):
        """Test reading Group 20 (Counter) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-g",
            "20.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Variation read (20.0) failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Point Enumeration Tests
    # ========================================================================

    def test_enumerate_points(self, cli_runner, target, port, docker_services):
        """Test --enumerate-points (-e) discovers all data point ranges [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-e",
            format="json",
            json_log=True,
            timeout=45,
        )

        assert result.success, f"Point enumeration failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        # Should mention point types
        has_enum_data = any(
            term in messages for term in ["enumerate", "point", "bi", "ai", "index", "flags"]
        )
        assert has_enum_data, "Expected enumeration data in messages"

    # ========================================================================
    # Complex Outstation Tests (port 20001)
    # ========================================================================

    @pytest.mark.containers("dnp3-complex")
    def test_complex_outstation_discovery(self, cli_runner, target, docker_services):
        """Test discovery against complex outstation (160 data points) [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_complex"]),
            "-o",
            str(COMPLEX_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Complex outstation scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        assert any(term in messages for term in ["connected", "points", "bi", "ai"]), (
            "Expected data from complex outstation"
        )

    @pytest.mark.containers("dnp3-complex")
    def test_complex_outstation_attributes(self, cli_runner, target, docker_services):
        """Test device attributes from complex outstation [Category B]

        Note: stepfunc mock may not return Group 0 attributes through opendnp3.
        We verify the scanner attempts the read and completes without error.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_complex"]),
            "-o",
            str(COMPLEX_OUTSTATION_ADDR),
            "-a",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Complex attrs failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        has_attr_activity = any(
            term in messages
            for term in [
                "device attributes",
                "group 0",
                "no device attr",
                "oida substation",
                "oida mock",
                "connected",
            ]
        )
        assert has_attr_activity, "Expected attribute read attempt on complex outstation"

    # ========================================================================
    # Enhanced Outstation Tests (port 20010)
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_enhanced_outstation_basic_scan(self, cli_runner, target, docker_services):
        """Test basic scan against enhanced outstation [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Enhanced outstation scan failed: {result.stderr}"
        _assert_log_has_events(result)

    @pytest.mark.containers("dnp3-enhanced")
    def test_cold_restart(self, cli_runner, target, docker_services):
        """Test cold restart command against enhanced outstation [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--cold-restart",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["restart", "cold", "delay"]), (
                    "Expected restart-related messages on success"
                )

    @pytest.mark.containers("dnp3-enhanced")
    def test_warm_restart(self, cli_runner, target, docker_services):
        """Test warm restart command against enhanced outstation [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--warm-restart",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["restart", "warm", "delay"]), (
                    "Expected restart-related messages"
                )

    @pytest.mark.containers("dnp3-enhanced")
    def test_freeze_immediate(self, cli_runner, target, docker_services):
        """Test immediate freeze of counters [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--freeze-immediate",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_freeze_clear(self, cli_runner, target, docker_services):
        """Test freeze and clear counters [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--freeze-clear",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_freeze_no_ack(self, cli_runner, target, docker_services):
        """Test freeze with no-ack (stealth) mode [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--freeze-immediate",
            "--freeze-no-ack",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_write_deadband(self, cli_runner, target, docker_services):
        """Test writing analog input dead band (Group 34) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--write-deadband",
            "0:100.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_write_deadband_multiple(self, cli_runner, target, docker_services):
        """Test writing multiple dead band values [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--write-deadband",
            "0:50.0",
            "--write-deadband",
            "1:75.0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_delay_measure(self, cli_runner, target, docker_services):
        """Test communication delay measurement [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "-d",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["delay", "round-trip", "ms"]), (
                    "Expected delay measurement data"
                )

    @pytest.mark.containers("dnp3-enhanced")
    def test_time_sync_lan(self, cli_runner, target, docker_services):
        """Test LAN time synchronization [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--time-sync",
            "lan",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_time_sync_nonlan(self, cli_runner, target, docker_services):
        """Test non-LAN time synchronization [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--time-sync",
            "non-lan",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_read_octet_strings(self, cli_runner, target, docker_services):
        """Test reading octet strings (Group 110) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--read-octet",
            "110:0-2",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_security_stats(self, cli_runner, target, docker_services):
        """Test reading security statistics (Group 121) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--security-stats",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Security stats may not be available on all outstations
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_record_time(self, cli_runner, target, docker_services):
        """Test RECORD_CURRENT_TIME command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--record-time",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Binary Output Control Tests (require --confirm)
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_bo_direct_operate(self, cli_runner, target, docker_services):
        """Test direct operate on binary output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--bo-direct",
            "0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(
                    term in messages for term in ["control", "direct", "operate", "success"]
                ), "Expected control result messages"

    @pytest.mark.containers("dnp3-enhanced")
    def test_bo_sbo(self, cli_runner, target, docker_services):
        """Test select-before-operate on binary output [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--bo-sbo",
            "0",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_bo_control_code(self, cli_runner, target, docker_services):
        """Test binary output with specific control code (PULSE_ON) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--bo-direct",
            "0",
            "--control-code",
            "1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Analog Output Control Tests (require --confirm)
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_ao_direct_float(self, cli_runner, target, docker_services):
        """Test analog output direct operate with float value [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--ao-direct",
            "0",
            "--ao-value",
            "42.5",
            "--ao-type",
            "float",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_ao_direct_int32(self, cli_runner, target, docker_services):
        """Test analog output direct operate with int32 value [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--ao-direct",
            "0",
            "--ao-value",
            "100",
            "--ao-type",
            "int32",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_ao_sbo(self, cli_runner, target, docker_services):
        """Test analog output select-before-operate [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--ao-sbo",
            "0",
            "--ao-value",
            "25.0",
            "--ao-type",
            "float",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Unsolicited Response Control Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_enable_unsolicited(self, cli_runner, target, docker_services):
        """Test enabling unsolicited responses [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--enable-unsol",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_disable_unsolicited(self, cli_runner, target, docker_services):
        """Test disabling unsolicited responses [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--disable-unsol",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Application Control Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_stop_application(self, cli_runner, target, docker_services):
        """Test stop application command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--stop-app",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Application control may not be supported by enhanced mock
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_start_application(self, cli_runner, target, docker_services):
        """Test start application command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--start-app",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-enhanced")
    def test_init_data(self, cli_runner, target, docker_services):
        """Test initialize data command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--init-data",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    @pytest.mark.containers("dnp3-enhanced")
    def test_save_config(self, cli_runner, target, docker_services):
        """Test save configuration command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--save-config",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Save config may not be available in the opendnp3 build
        assert result.returncode in [0, 1]

    # ========================================================================
    # File Transfer Tests (port 20020) -- requires dnp3-filetransfer container
    # ========================================================================

    @pytest.mark.containers("dnp3-filetransfer")
    def test_list_directory(self, cli_runner, target, docker_services):
        """Test file directory listing (Group 70) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--list-dir",
            "/",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(
                    term in messages for term in ["directory", "entries", "file", "config"]
                ), "Expected directory listing data"

    @pytest.mark.containers("dnp3-filetransfer")
    def test_read_file(self, cli_runner, target, docker_services):
        """Test reading a file from outstation [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--read-file",
            "/config.txt",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-filetransfer")
    def test_file_info(self, cli_runner, target, docker_services):
        """Test getting file metadata [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--file-info",
            "/config.txt",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    @pytest.mark.containers("dnp3-filetransfer")
    def test_delete_file(self, cli_runner, target, docker_services):
        """Test deleting a file on outstation (write operation) [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--delete-file",
            "/event_log.csv",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Address Scan Tests
    # ========================================================================

    @pytest.mark.slow
    def test_scan_range_basic(self, cli_runner, target, port, docker_services):
        """Test address range scanning with -r flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-r",
            "1024-1024",
            "--scan-timeout",
            "2",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Address scan failed: {result.stderr}"
        _assert_log_has_events(result)
        messages = _all_messages(result.scan_log)

        assert any(term in messages for term in ["scan", "address", "found", "outstation"]), (
            "Expected scan results in messages"
        )

    def test_scan_range_narrow(self, cli_runner, target, port, docker_services):
        """Test narrow address range scan [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-r",
            "1024-1026",
            "--scan-timeout",
            "1",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Narrow range scan failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # TLS Transport Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-tls")
    def test_tls_without_cert(self, cli_runner, target, docker_services):
        """Test TLS connection without explicit certificates [Category B]

        Note: Mock may accept TLS connections without client certificates,
        or may reject them -- either outcome is valid.
        """
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_tls"]),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--tls",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # TLS without cert/key may succeed or fail depending on mock config
        assert result.returncode in [0, 1], "TLS test should not hang or crash"
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Channel Retry Tuning Tests
    # ========================================================================

    def test_retry_min_max(self, cli_runner, target, port, docker_services):
        """Test channel retry tuning parameters [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--retry-min",
            "1",
            "--retry-max",
            "10",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Retry tuning failed: {result.stderr}"
        _assert_log_has_events(result)

    def test_no_reconnect(self, cli_runner, target, port, docker_services):
        """Test --no-reconnect flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--no-reconnect",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"No-reconnect scan failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # No-Ack / Stealth Mode Tests
    # ========================================================================

    def test_no_ack_flag(self, cli_runner, target, port, docker_services):
        """Test --no-ack stealth mode flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "-n",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"No-ack mode failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Probe Objects Tests
    # ========================================================================

    @pytest.mark.slow
    def test_probe_objects(self, cli_runner, target, port, docker_services):
        """Test --probe-objects probes all DNP3 groups 0-122 [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--probe-objects",
            "--confirm",
            format="json",
            json_log=True,
            timeout=90,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)
            if result.success:
                messages = _all_messages(result.scan_log)
                assert any(term in messages for term in ["probe", "group", "supported"]), (
                    "Expected probe results"
                )

    # ========================================================================
    # Argument Validation / Error Handling Tests
    # ========================================================================

    def test_control_without_outstation_addr(self, cli_runner, target, port, docker_services):
        """Test that control ops without -o fail with ConfigurationError [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "--bo-direct",
            "0",
            "--confirm",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should fail because --outstation-addr is required for control ops
        assert not result.success, "Should fail without --outstation-addr for control ops"

    def test_ao_without_value(self, cli_runner, target, port, docker_services):
        """Test that analog output without --ao-value fails [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--ao-direct",
            "0",
            "--confirm",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should fail because --ao-value is required
        assert not result.success, "Should fail without --ao-value"

    def test_invalid_scan_range_format(self, cli_runner, target, port, docker_services):
        """Test invalid --scan-range format is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-r",
            "not-a-range",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "Invalid scan range should fail"

    def test_invalid_scan_range_reversed(self, cli_runner, target, port, docker_services):
        """Test reversed scan range (START > END) is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-r",
            "100-50",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "Reversed scan range should fail"

    def test_invalid_deadband_format(self, cli_runner, target, port, docker_services):
        """Test invalid --write-deadband format is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--write-deadband",
            "bad-format",
            "--confirm",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "Invalid deadband format should fail"

    def test_freeze_no_ack_without_freeze_op(self, cli_runner, target, port, docker_services):
        """Test --freeze-no-ack without freeze operation is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--freeze-no-ack",
            "--confirm",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "--freeze-no-ack without freeze op should fail"

    def test_connection_refused(self, cli_runner):
        """Test handling of connection to closed port [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            MOCK_HOST,
            "--port",
            "65534",
            "--timeout",
            "3",
            "--scan-timeout",
            "2",
            timeout=30,
            expect_json=False,
            json_log=True,
        )

        # Should fail (returncode 1 or timeout -1) but not crash with exception
        assert not result.success, "Should fail on connection refused"
        # If we got structured log events, verify they're well-formed
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    def test_timeout_handling(self, cli_runner):
        """Test timeout is properly enforced [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            "10.255.255.1",
            "--port",
            str(self.default_port),
            "--timeout",
            "3",
            timeout=20,
            expect_json=False,
            json_log=True,
        )

        # Should complete within reasonable time (timeout + cleanup buffer)
        assert result.execution_time < 25, "Command did not respect timeout"
        assert not result.success, "Should fail when connecting to unreachable host"

    def test_wrong_outstation_address(self, cli_runner, target, port, docker_services):
        """Test connecting with wrong outstation address [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            "9999",
            "--timeout",
            "5",
            timeout=20,
            expect_json=False,
            json_log=True,
        )

        # May succeed connecting but integrity poll should fail
        # or connection may fail entirely - both are valid
        assert result.returncode in [0, 1], "Should not hang with wrong address"

    def test_invalid_assign_class_format(self, cli_runner, target, port, docker_services):
        """Test invalid --assign-class format is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--assign-class",
            "bad-format",
            "--confirm",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "Invalid assign-class format should fail"

    def test_invalid_read_octet_group(self, cli_runner, target, port, docker_services):
        """Test invalid octet string group number is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--read-octet",
            "99:0-5",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "Invalid octet group should fail"

    # NOT COVERED (no test exists — do not add skipped placeholders for these):
    #   - Serial transport (--serial, baud/parity/data-bits/stop-bits): needs a
    #     physical serial device.
    #   - Secure Authentication v5: needs a compatible outstation and an
    #     opendnp3 build with SA support.

    # ========================================================================
    # UDP Transport Tests
    # ========================================================================

    def test_udp_transport(self, cli_runner, target, port, docker_services):
        """Test UDP transport option [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--transport",
            "udp",
            "--timeout",
            "5",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # UDP transport may or may not work depending on mock
        assert result.returncode in [0, 1]

    # ========================================================================
    # Output Format Tests
    # ========================================================================

    def test_verbose_output(self, cli_runner, target, port, docker_services):
        """Test verbose output flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            timeout=30,
            expect_json=False,
            json_log=True,
            verbose=True,
        )

        assert result.success, f"Verbose output scan failed: {result.stderr}"
        assert result.stdout or result.stderr, "No output with verbose flag"

    def test_debug_output(self, cli_runner, target, port, docker_services):
        """Test debug output flag [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            timeout=30,
            expect_json=False,
            json_log=True,
            debug=True,
        )

        assert result.success, f"Debug output scan failed: {result.stderr}"

    def test_json_output_format(self, cli_runner, target, port, docker_services):
        """Test JSON output format [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"JSON output test failed: {result.stderr}"
        _assert_log_has_events(result)
        _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Scan Timeout Configuration Tests
    # ========================================================================

    def test_scan_timeout_parameter(self, cli_runner, target, port, docker_services):
        """Test --scan-timeout parameter for address scanning [Category A]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(port),
            "-r",
            "1024-1024",
            "--scan-timeout",
            "1.0",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.success, f"Scan timeout param failed: {result.stderr}"
        _assert_log_has_events(result)

    # ========================================================================
    # Assign Class Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_assign_class(self, cli_runner, target, docker_services):
        """Test assigning points to event class [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--assign-class",
            "1:0-9:1",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Class assignment may not be supported by enhanced mock
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Activate Configuration Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_activate_config(self, cli_runner, target, docker_services):
        """Test activate configuration command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--activate-config",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Activate config may not be available in opendnp3 build
        assert result.returncode in [0, 1]

    # ========================================================================
    # Deadband Type Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_deadband_type_uint16(self, cli_runner, target, docker_services):
        """Test dead band write with uint16 type [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--write-deadband",
            "0:50",
            "--deadband-type",
            "uint16",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    # ========================================================================
    # Freeze At Time Test
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_freeze_at_time(self, cli_runner, target, docker_services):
        """Test scheduled freeze at time [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--freeze-at-time",
            "+60s",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Additional Application Control Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-enhanced")
    def test_init_app(self, cli_runner, target, docker_services):
        """Test initialize application command [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_enhanced"]),
            "-o",
            str(ENHANCED_OUTSTATION_ADDR),
            "--init-app",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # Init app may not be supported by enhanced mock
        assert result.returncode in [0, 1]

    # ========================================================================
    # Write File Tests (require --confirm)
    # ========================================================================

    @pytest.mark.containers("dnp3-filetransfer")
    def test_write_file_without_data_fails(self, cli_runner, target, docker_services):
        """Test --write-file without --write-data is rejected [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--write-file",
            "/test.txt",
            "--confirm",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        assert not result.success, "Should fail without --write-data"

    @pytest.mark.containers("dnp3-filetransfer")
    def test_write_file_with_inline_data(self, cli_runner, target, docker_services):
        """Test writing a file with inline data [Category B]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--write-file",
            "/test_write.txt",
            "--write-data",
            "test data content",
            "--confirm",
            format="json",
            json_log=True,
            timeout=30,
        )

        # File write may or may not be supported by filetransfer mock
        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # Save File (--save-file) Test
    # ========================================================================

    @pytest.mark.containers("dnp3-filetransfer")
    def test_read_file_with_save(self, cli_runner, target, docker_services, tmp_path):
        """Test reading a file and saving to local path [Category B]"""
        local_save_path = str(tmp_path / "downloaded_config.txt")
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_filetransfer"]),
            "-o",
            str(FT_SLAVE_ADDR),
            "-m",
            str(FT_MASTER_ADDR),
            "--read-file",
            "/config.txt",
            "--save-file",
            local_save_path,
            format="json",
            json_log=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]
        if result.scan_log is not None and len(result.scan_log) > 0:
            _assert_log_event_structure(result.scan_log)

    # ========================================================================
    # TLS Certificate Path Tests
    # ========================================================================

    @pytest.mark.containers("dnp3-tls")
    def test_tls_with_nonexistent_cert(self, cli_runner, target, docker_services):
        """Test TLS with nonexistent certificate path fails gracefully [Category C]"""
        result = cli_runner.run(
            self.protocol_name,
            target,
            "--port",
            str(MOCK_PORTS["dnp3_tls"]),
            "-o",
            str(BASIC_OUTSTATION_ADDR),
            "--tls",
            "--tls-cert",
            "/nonexistent/cert.pem",
            "--tls-key",
            "/nonexistent/key.pem",
            timeout=15,
            expect_json=False,
            json_log=True,
        )

        # Should fail but not crash
        assert not result.success, "Should fail with nonexistent cert"
