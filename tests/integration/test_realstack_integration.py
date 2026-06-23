"""Integration tests wiring OIDA scanners to the REAL OSS mock stacks.

Unlike the hand-written simulators (which were often shaped to match the
scanner and therefore can't catch scanner bugs), these targets are genuine
protocol implementations built from upstream source / official images:

  ASTM -> python-astm LIS (E1381/E1394, BSD)   astm-realstack-chemistry  TCP 1397
                                               astm-realstack-hematology TCP 1398
  HART -> FieldComm hipserver+hipflowapp        hart-hipflow-hart5    UDP+TCP 5100
          (Apache-2.0, HART5 / HART7)           hart-hipflow-hart7    UDP+TCP 5102
  FHIR -> HAPI FHIR (Apache-2.0, R4 / R5)        fhir-hapi-r4          HTTP 8090
                                                 fhir-hapi-r5          HTTP 8091

Each test asserts the scanner reads data that ONLY the genuine stack produces,
so the suite doubles as a conformance check that OIDA interoperates with real
devices. Tests skip cleanly when the mock is not running (bring them up with
`python services.py up`, or they are started by the marker-driven compose
lifecycle in CI).

The L2 real mocks (ethercat-kickcat, canopen, profinet-siemens/beckhoff,
goose-l2-breaker) and the profile-gated / slow-booting stacks (ocpp-steve) are
NOT wired here: they need same-netns/raw-socket access and Docker compose
profiles that the standard 127.0.0.1+port harness does not provide. They are
covered by their per-protocol L2 smoke tests; full real-stack L2 wiring is a
follow-up that requires profile support in the test harness.
"""

import socket

import pytest

from .conftest import MOCK_HOST, check_port_open

pytestmark = pytest.mark.integration


def _require(port: int, name: str) -> None:
    """Skip unless the real-stack mock is reachable on MOCK_HOST:port (TCP).

    hipflow maps both UDP and TCP on its host port, so a TCP probe is a valid
    liveness gate for every stack wired here.
    """
    if not check_port_open(MOCK_HOST, port):
        pytest.skip(
            f"{name} real-stack mock not reachable on {MOCK_HOST}:{port} (python services.py up)"
        )


def _require_udp(port: int, name: str) -> None:
    """Skip unless a UDP-mapped mock is reachable on MOCK_HOST:port.

    A docker UDP port-map keeps a proxy socket bound, so probing produces no
    ICMP port-unreachable; if the mock is down the host port is unmapped and the
    next operation raises ConnectionRefusedError. Used for the BACnet stack.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(1.0)
        s.connect((MOCK_HOST, port))
        s.send(b"\x81\x0b\x00\x04")  # minimal BVLC ping; reply (if any) is irrelevant
        try:
            s.recv(16)
        except socket.timeout:
            pass  # no reply expected — reachability is what we gate on
    except ConnectionRefusedError:
        pytest.skip(
            f"{name} real-stack mock not reachable on {MOCK_HOST}:{port}/udp (python services.py up)"
        )
    finally:
        s.close()


def _text(result) -> str:
    return f"{result.stdout}\n{result.stderr}".lower()


@pytest.mark.astm
class TestAstmRealStack:
    """oida astm against the real python-astm LIS (genuine E1381/E1394 framing)."""

    def test_chemistry_handshake_and_header_accepted(self, cli_runner):
        """ENQ/ACK + header exchange through the genuine python-astm protocol layer."""
        _require(1397, "astm-realstack-chemistry")
        result = cli_runner.run(
            "astm", MOCK_HOST, "--port", "1397", "--send-patient", "--confirm", timeout=40
        )
        text = _text(result)
        assert "enq/ack handshake successful" in text, f"no ASTM handshake: {text[:400]}"
        # The genuine python-astm framing must ACCEPT our records (the bug-class a
        # sim can't exercise — real strict checksum/framing validation).
        assert "header record accepted" in text, f"real LIS rejected header: {text[:400]}"

    def test_hematology_endpoint_connects(self, cli_runner):
        _require(1398, "astm-realstack-hematology")
        result = cli_runner.run("astm", MOCK_HOST, "--port", "1398", timeout=30)
        text = _text(result)
        assert "connected to astm endpoint" in text, f"no ASTM connect: {text[:400]}"


@pytest.mark.hart
class TestHartRealStack:
    """oida hart against FieldComm hipserver+hipflowapp (real HART-IP device)."""

    def test_hart5_protocol_revision(self, cli_runner):
        _require(5100, "hart-hipflow-hart5")
        result = cli_runner.run("hart", MOCK_HOST, "--port", "5100", "--read-id", timeout=30)
        text = _text(result)
        assert "connected to hart device" in text, f"no HART connect: {text[:400]}"
        assert "hart 5" in text or "rev 5" in text, f"expected HART rev 5: {text[:400]}"

    def test_hart7_protocol_revision(self, cli_runner):
        _require(5102, "hart-hipflow-hart7")
        result = cli_runner.run("hart", MOCK_HOST, "--port", "5102", "--read-id", timeout=30)
        text = _text(result)
        assert "hart 7" in text or "rev 7" in text, f"expected HART rev 7: {text[:400]}"

    def test_hart5_and_hart7_differ(self, cli_runner):
        """The two configs are genuinely different builds (rev 5 vs rev 7)."""
        _require(5100, "hart-hipflow-hart5")
        _require(5102, "hart-hipflow-hart7")
        r5 = _text(cli_runner.run("hart", MOCK_HOST, "--port", "5100", "--read-id", timeout=30))
        r7 = _text(cli_runner.run("hart", MOCK_HOST, "--port", "5102", "--read-id", timeout=30))
        assert ("hart 5" in r5 or "rev 5" in r5) and ("hart 7" in r7 or "rev 7" in r7)


@pytest.mark.fhir
class TestFhirRealStack:
    """oida fhir against real HAPI FHIR servers (distinct FHIR versions per config)."""

    def test_hapi_r4_capability(self, cli_runner):
        _require(8090, "fhir-hapi-r4")
        result = cli_runner.run("fhir", f"http://{MOCK_HOST}:8090/fhir", timeout=40)
        text = _text(result)
        assert "connected to fhir endpoint" in text, f"no FHIR connect: {text[:400]}"
        assert "hapi fhir" in text, f"not a HAPI server: {text[:400]}"
        assert "4.0.1" in text, f"expected FHIR R4 (4.0.1): {text[:400]}"

    def test_hapi_r5_version(self, cli_runner):
        _require(8091, "fhir-hapi-r5")
        result = cli_runner.run("fhir", f"http://{MOCK_HOST}:8091/fhir", timeout=40)
        text = _text(result)
        assert "hapi fhir" in text, f"not a HAPI server: {text[:400]}"
        # R5 advertises a 5.x fhirVersion — must differ from the R4 config.
        assert "4.0.1" not in text, f"R5 endpoint reported R4 version: {text[:400]}"


@pytest.mark.bacnet
class TestBacnetRealStack:
    """oida bacnet against the real bacnet-stack C device.

    Doubles as the regression guard for the broadcast-bind fix: bacpypes3 used
    to crash with `[Errno 99]` standing up a broadcast transport from a `/24`
    local mask on bridged/NAT nets, so a targeted unicast read of a fully
    compliant device aborted. The fix uses a `/32` mask for targeted reads. A
    self-matching bacpypes sim could not catch this; the real C stack does.
    """

    def test_building_targeted_read(self, cli_runner):
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet", MOCK_HOST, "--port", "47821", "--device-id", "22002", timeout=30
        )
        text = _text(result)
        # Regression guard: the targeted read must NOT abort.
        assert "errno 99" not in text, f"broadcast-bind bug regressed: {text[:500]}"
        assert "could not read device" not in text, f"targeted read aborted: {text[:500]}"
        # Genuine bacnet-stack identity (only the real C device reports these).
        assert "building-supervisor" in text, f"object-name not read: {text[:500]}"
        assert "bacnet stack at sourceforge" in text, f"vendor not read: {text[:500]}"

    def test_vav_distinct_device(self, cli_runner):
        """A second profile (instance 33003 / VAV-Box-12) — confirms distinct configs."""
        _require_udp(47822, "bacnet-realstack-vav")
        result = cli_runner.run(
            "bacnet", MOCK_HOST, "--port", "47822", "--device-id", "33003", timeout=30
        )
        text = _text(result)
        assert "errno 99" not in text, f"broadcast-bind bug regressed: {text[:500]}"
        assert "vav-box-12" in text, f"VAV device identity not read: {text[:500]}"
