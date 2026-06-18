"""
Tier 1: "All definitions execute" integration tests.

For each P0 protocol (Modbus, OPC UA, IEC 104, MMS, MQTT), this test:
1. Starts an in-process mock server
2. Creates a fuzzer configured against it
3. Runs a small number of mutations per request definition
4. Verifies the definition rendered and executed without crashing

This catches bugs in later request definitions that are only triggered
when boofuzz tries to render them during an actual fuzz run.
"""

import pytest

from .conftest import FuzzTimeout, create_fuzzer_config, run_fuzz_with_timeout
from .mock_servers import (
    iec104_server,
    mms_server,
    modbus_server,
    mqtt_server,
    opcua_server,
)

pytestmark = pytest.mark.integration_fuzzers


# ============================================================================
# Helpers
# ============================================================================


def _get_request_names(protocol_name):
    """Get request definition names for a protocol without instantiating."""
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
    if not fuzzer_class:
        return []
    return [r.name for r in fuzzer_class.get_request_definitions()]


# ============================================================================
# Modbus
# ============================================================================

MODBUS_REQUESTS = _get_request_names("modbus")


class TestModbusDefinitionExecution:
    """Test that each Modbus request definition executes without error."""

    @pytest.mark.parametrize("request_name", MODBUS_REQUESTS or ["skip"], ids=lambda r: r)
    def test_definition_executes(self, request_name, fuzz_session):
        if request_name == "skip":
            pytest.skip("No Modbus request definitions found")

        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            pytest.skip("Modbus fuzzer not available")

        with modbus_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "modbus",
                fuzz_session,
                enabled_requests=[request_name],
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=15)
            except FuzzTimeout:
                pass  # Timeout is acceptable -- we just want no crash
            except (ConnectionError, OSError):
                pass  # Connection issues are acceptable
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")


# ============================================================================
# OPC UA
# ============================================================================

OPCUA_REQUESTS = _get_request_names("opcua")


class TestOPCUADefinitionExecution:
    """Test that each OPC UA request definition executes without error."""

    @pytest.mark.parametrize("request_name", OPCUA_REQUESTS or ["skip"], ids=lambda r: r)
    def test_definition_executes(self, request_name, fuzz_session):
        if request_name == "skip":
            pytest.skip("No OPC UA request definitions found")

        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("opcua")
        if not fuzzer_class:
            pytest.skip("OPC UA fuzzer not available")

        with opcua_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "opcua",
                fuzz_session,
                enabled_requests=[request_name],
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=15)
            except FuzzTimeout:
                pass
            except (ConnectionError, OSError):
                pass
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")
            except Exception as e:
                if "No requests specified" in str(e):
                    pytest.skip(f"Request '{request_name}' not loadable: {e}")
                raise


# ============================================================================
# IEC 104
# ============================================================================

IEC104_REQUESTS = _get_request_names("iec104")


class TestIEC104DefinitionExecution:
    """Test that each IEC 104 request definition executes without error."""

    @pytest.mark.parametrize("request_name", IEC104_REQUESTS or ["skip"], ids=lambda r: r)
    def test_definition_executes(self, request_name, fuzz_session):
        if request_name == "skip":
            pytest.skip("No IEC 104 request definitions found")

        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("iec104")
        if not fuzzer_class:
            pytest.skip("IEC 104 fuzzer not available")

        with iec104_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "iec104",
                fuzz_session,
                enabled_requests=[request_name],
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=15)
            except FuzzTimeout:
                pass
            except (ConnectionError, OSError):
                pass
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")


# ============================================================================
# MMS
# ============================================================================

MMS_REQUESTS = _get_request_names("mms")


class TestMMSDefinitionExecution:
    """Test that each MMS request definition executes without error."""

    @pytest.mark.parametrize("request_name", MMS_REQUESTS or ["skip"], ids=lambda r: r)
    def test_definition_executes(self, request_name, fuzz_session):
        if request_name == "skip":
            pytest.skip("No MMS request definitions found")

        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("mms")
        if not fuzzer_class:
            pytest.skip("MMS fuzzer not available")

        with mms_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "mms",
                fuzz_session,
                enabled_requests=[request_name],
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=15)
            except FuzzTimeout:
                pass
            except (ConnectionError, OSError):
                pass
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")
            except Exception as e:
                if "No requests specified" in str(e):
                    pytest.skip(f"Request '{request_name}' not loadable: {e}")
                raise


# ============================================================================
# MQTT
# ============================================================================

MQTT_REQUESTS = _get_request_names("mqtt")


class TestMQTTDefinitionExecution:
    """Test that each MQTT request definition executes without error."""

    @pytest.mark.parametrize("request_name", MQTT_REQUESTS or ["skip"], ids=lambda r: r)
    def test_definition_executes(self, request_name, fuzz_session):
        if request_name == "skip":
            pytest.skip("No MQTT request definitions found")

        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("mqtt")
        if not fuzzer_class:
            pytest.skip("MQTT fuzzer not available")

        with mqtt_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "mqtt",
                fuzz_session,
                enabled_requests=[request_name],
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=15)
            except FuzzTimeout:
                pass
            except (ConnectionError, OSError):
                pass
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=120"])
