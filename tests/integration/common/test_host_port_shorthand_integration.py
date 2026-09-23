"""End-to-end CLI tests for the "<host>:<port>" target shorthand.

The unit tests (tests/unit/test_host_port_shorthand.py) prove the splitting
logic; these prove a real scan reaches the mock when the port is given only in
the target. Two protocols are covered deliberately:

  - modbus: TCP, registers --port with a concrete default (502).
  - coap:   UDP, registers --port with default=None and resolves 5683/5684 from
            that "unset" sentinel -- the case a naive implementation breaks by
            unconditionally writing args.port.

The mocks are published on non-default host ports, so a dropped ":port" suffix
would fall back to the protocol default and fail to reach them -- these tests
cannot pass by accident.
"""

import pytest

from tests.integration.conftest import MOCK_HOST, MOCK_PORTS

pytestmark = pytest.mark.integration


@pytest.mark.modbus
@pytest.mark.containers("modbus")
@pytest.mark.xdist_group("modbus")
class TestModbusHostPortShorthand:
    def test_shorthand_target_reaches_mock(self, cli_runner, docker_services):
        port = MOCK_PORTS["modbus"]
        result = cli_runner.run("modbus", f"{MOCK_HOST}:{port}", format="json", json_log=True)

        assert result.success, f"shorthand scan failed: {result.stderr}"
        assert result.scan_log is not None
        result.scan_log.assert_has_events(min_count=1)

    def test_shorthand_overrides_port_flag(self, cli_runner, docker_services):
        # --port points at a closed port; the target port is more specific and
        # must win, so the scan still reaches the mock.
        port = MOCK_PORTS["modbus"]
        result = cli_runner.run(
            "modbus",
            f"{MOCK_HOST}:{port}",
            "--port",
            "1",
            format="json",
            json_log=True,
        )

        assert result.success, f"shorthand did not override --port: {result.stderr}"
        assert result.scan_log is not None
        result.scan_log.assert_has_events(min_count=1)


@pytest.mark.coap
@pytest.mark.containers("coap")
@pytest.mark.xdist_group("coap")
class TestCoapHostPortShorthand:
    def test_shorthand_target_reaches_mock(self, cli_runner, docker_services):
        port = MOCK_PORTS["coap"]
        result = cli_runner.run("coap", f"{MOCK_HOST}:{port}", format="json", json_log=True)

        assert result.success, f"shorthand scan failed: {result.stderr}"
        assert result.scan_log is not None
        result.scan_log.assert_has_events(min_count=1)
