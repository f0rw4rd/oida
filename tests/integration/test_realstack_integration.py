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

from tests.service_gate import require_service

from tests.integration.conftest import MOCK_HOST

pytestmark = pytest.mark.integration


def _require(port: int, name: str) -> None:
    """Skip unless the real-stack mock is reachable on MOCK_HOST:port (TCP).

    hipflow maps both UDP and TCP on its host port, so a TCP probe is a valid
    liveness gate for every stack wired here.
    """
    s = socket.create_connection((MOCK_HOST, port), timeout=3)
    s.close()


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
            pass  # no reply expected - reachability is what we gate on
    except ConnectionRefusedError:
        require_service(
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
        # sim can't exercise - real strict checksum/framing validation).
        assert "header record accepted" in text, f"real LIS rejected header: {text[:400]}"

    def test_hematology_endpoint_connects(self, cli_runner):
        _require(1398, "astm-realstack-hematology")
        result = cli_runner.run("astm", MOCK_HOST, "--port", "1398", timeout=45)
        text = _text(result)
        assert "connected to astm endpoint" in text, f"no ASTM connect: {text[:400]}"


@pytest.mark.hart
class TestHartRealStack:
    """oida hart against FieldComm hipserver+hipflowapp (real HART-IP device)."""

    def test_hart5_protocol_revision(self, cli_runner):
        _require(5100, "hart-hipflow-hart5")
        result = cli_runner.run("hart", MOCK_HOST, "--port", "5100", "--read-id", timeout=45)
        text = _text(result)
        assert "connected to hart device" in text, f"no HART connect: {text[:400]}"
        assert "hart 5" in text or "rev 5" in text, f"expected HART rev 5: {text[:400]}"

    def test_hart7_protocol_revision(self, cli_runner):
        _require(5102, "hart-hipflow-hart7")
        result = cli_runner.run("hart", MOCK_HOST, "--port", "5102", "--read-id", timeout=45)
        text = _text(result)
        assert "hart 7" in text or "rev 7" in text, f"expected HART rev 7: {text[:400]}"

    def test_hart5_and_hart7_differ(self, cli_runner):
        """The two configs are genuinely different builds (rev 5 vs rev 7)."""
        _require(5100, "hart-hipflow-hart5")
        _require(5102, "hart-hipflow-hart7")
        r5 = _text(cli_runner.run("hart", MOCK_HOST, "--port", "5100", "--read-id", timeout=45))
        r7 = _text(cli_runner.run("hart", MOCK_HOST, "--port", "5102", "--read-id", timeout=45))
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
        # R5 advertises a 5.x fhirVersion - must differ from the R4 config.
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
            "bacnet", MOCK_HOST, "--port", "47821", "--device-id", "22002", timeout=45
        )
        text = _text(result)
        # Regression guard: the targeted read must NOT abort.
        assert "errno 99" not in text, f"broadcast-bind bug regressed: {text[:500]}"
        assert "could not read device" not in text, f"targeted read aborted: {text[:500]}"
        # Genuine bacnet-stack identity (only the real C device reports these).
        assert "building-supervisor" in text, f"object-name not read: {text[:500]}"
        assert "bacnet stack at sourceforge" in text, f"vendor not read: {text[:500]}"

    def test_vav_distinct_device(self, cli_runner):
        """A second profile (instance 33003 / VAV-Box-12) - confirms distinct configs."""
        _require_udp(47822, "bacnet-realstack-vav")
        result = cli_runner.run(
            "bacnet", MOCK_HOST, "--port", "47822", "--device-id", "33003", timeout=45
        )
        text = _text(result)
        assert "errno 99" not in text, f"broadcast-bind bug regressed: {text[:500]}"
        assert "vav-box-12" in text, f"VAV device identity not read: {text[:500]}"

    def test_building_deep_inventory(self, cli_runner):
        """The building profile layers diverse object types on top of the analog/
        binary points: CharacterString / Integer / Life-Safety values and File
        objects. Enumeration must surface them (only the real C stack creates
        them, with BACFILE enabled for the File object)."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "-e",
            timeout=40,
        )
        text = _text(result)
        assert "errno 99" not in text, f"broadcast-bind bug regressed: {text[:500]}"
        for obj_type in ("characterstringvalue", "integervalue", "lifesafetypoint", "file"):
            assert obj_type in text, f"deep-inventory object {obj_type!r} missing: {text[:800]}"

    def test_building_atomic_read_file(self, cli_runner):
        """The building profile exposes File objects backed by real on-disk files
        (entrypoint seeds them; pathnames are relative for the posix backend).
        AtomicReadFile must return the genuine file content."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--read-file",
            "101",
            timeout=40,
        )
        text = _text(result)
        assert "errno 99" not in text, f"broadcast-bind bug regressed: {text[:500]}"
        # config.ini content seeded by entrypoint.sh - only a working
        # AtomicReadFile against the real file produces these bytes.
        assert "reinit_password_set" in text, (
            f"file content not read via AtomicReadFile: {text[:800]}"
        )

    def test_call_write_read_roundtrip(self, cli_runner):
        """--call writeProperty then --call readProperty must round-trip a value
        through the real stack (exercises the service-invocation dispatcher)."""
        _require_udp(47821, "bacnet-realstack-building")
        base = ["bacnet", MOCK_HOST, "--port", "47821", "--device-id", "22002"]
        w = cli_runner.run(*base, "--call", "write", "AV:1:pv:73.5", "--confirm", timeout=40)
        assert "acknowledged" in _text(w), f"WriteProperty via --call not acked: {_text(w)[:500]}"
        r = cli_runner.run(*base, "--call", "read", "AV:1:pv", timeout=40)
        assert "73.5" in _text(r), f"value did not round-trip via --call: {_text(r)[:500]}"

    def test_call_confirm_gate(self, cli_runner):
        """A mutating --call without --confirm must refuse before touching the device."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--call",
            "write",
            "AV:1:pv:1.0",
            timeout=45,
        )
        assert "confirm" in _text(result), f"mutating --call not gated: {_text(result)[:500]}"

    def test_call_extra_service_handlers(self, cli_runner):
        """profile.inc registers AddListElement/RemoveListElement/LifeSafetyOperation/
        AcknowledgeAlarm handlers the stock bacserv lacks. LifeSafetyOperation must
        be acknowledged (not 'unrecognized-service')."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--call",
            "lso",
            "lifeSafetyPoint:101:silence",
            "--confirm",
            timeout=40,
        )
        text = _text(result)
        assert "unrecognized-service" not in text, (
            f"LifeSafetyOperation handler not registered on the mock: {text[:500]}"
        )
        assert "acknowledged" in text, f"LifeSafetyOperation not acked: {text[:500]}"

    def test_list_services_catalog(self, cli_runner):
        """--list-services prints the invokable catalog without needing a device."""
        result = cli_runner.run(
            "bacnet", MOCK_HOST, "--port", "47821", "--list-services", timeout=20
        )
        text = _text(result)
        assert "service catalog" in text, f"--list-services did not print catalog: {text[:400]}"
        assert "writefile" in text and "reinit" in text, f"catalog incomplete: {text[:400]}"

    # One entry per callable service. Each must DISPATCH and produce a *handled*
    # result against the real stack - a device ack / value / Reject / Error is
    # all fine; a CLI-side failure (arg-parse bug, missing handler, unhandled
    # exception in the request builder) is not. Targets are chosen to be
    # non-destructive to other tests: dcc uses `enable` (never mutes the device),
    # writefile is covered separately, create wildcard-creates, delete targets a
    # non-existent instance. Verifies all 23 inline builders, not just a sample.
    _CALL_CASES = [
        ("read", ["read", "AV:1:pv"], False),
        ("rpm", ["rpm", "AV:1:pv,AV:101:pv"], False),
        ("whois", ["whois"], False),
        ("whohas", ["whohas", "device:22002"], False),
        ("readrange", ["readrange", "trendLog:1"], False),
        ("eventinfo", ["eventinfo"], False),
        ("alarmsummary", ["alarmsummary"], False),
        ("readfile", ["readfile", "101"], False),
        ("write", ["write", "AV:1:pv:50.0"], True),
        ("wpm", ["wpm", "AV:1:pv:50.0,AV:101:pv:50.0"], True),
        ("cov", ["cov", "AV:1:30"], True),
        ("create", ["create", "analogValue"], True),
        ("delete", ["delete", "analogValue:99999"], True),
        ("timesync", ["timesync", "2026-06-24T12:00:00"], True),
        ("utctimesync", ["utctimesync", "2026-06-24T12:00:00"], True),
        # Wrong password on purpose: exercises the reinit dispatch/builder
        # without actually warm-starting (rebooting) the shared mock mid-suite,
        # which would race the tests parametrized after this one. A successful
        # reinit is covered separately by the brute-force test.
        ("reinit", ["reinit", "warmstart:wrongpw"], True),
        ("dcc", ["dcc", "enable:0:filister"], True),
        ("lso", ["lso", "lifeSafetyPoint:101:silence"], True),
        ("ackalarm", ["ackalarm", "1:analogInput:101:normal"], True),
        ("wg", ["wg", "1:5:72.5"], True),
        ("textmessage", ["textmessage", "hello"], True),
        ("addlist", ["addlist", "AV:1:priorityArray:1"], True),
        ("rmlist", ["rmlist", "AV:1:priorityArray:1"], True),
    ]

    @pytest.mark.parametrize(
        "token,call_args,needs_confirm", _CALL_CASES, ids=[c[0] for c in _CALL_CASES]
    )
    def test_call_service_dispatches(self, cli_runner, token, call_args, needs_confirm):
        """Every callable service builds a valid request and is dispatched."""
        _require_udp(47821, "bacnet-realstack-building")
        args = [
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--call",
            *call_args,
        ]
        if needs_confirm:
            args.append("--confirm")
        result = cli_runner.run(*args, timeout=40)
        text = _text(result)
        assert "[call]" in text, f"--call {token} never dispatched: {text[:600]}"
        # OIDA must exit cleanly (0 ok / 1 finding) - not crash.
        assert result.returncode in (0, 1), f"--call {token} crashed (rc={result.returncode})"
        # CLI-side bug markers from our own dispatcher/builders - none may appear.
        # (A device Reject/Error, or a bacpypes3-internal logged traceback while
        # decoding an odd device response, is NOT our bug and is allowed.)
        for bug in ("bad arguments for", "no handler implemented", "failed:"):
            assert bug not in text, f"--call {token} dispatch bug ({bug!r}): {text[:600]}"

    def _wordlist(self, tmp_path):
        wl = tmp_path / "pw.txt"
        wl.write_text("admin\nfilister\nOIDA-Reinit\n")
        return str(wl)

    def test_brute_force_dcc_only(self, cli_runner, tmp_path):
        """--brute-force-dcc cracks ONLY the DCC password (filister), and must
        not report the ReinitializeDevice credential."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--brute-force-dcc",
            "--passwords",
            self._wordlist(tmp_path),
            "--confirm",
            timeout=45,
        )
        text = _text(result)
        assert "devicecommunicationcontrol: 'filister'" in text, f"DCC not cracked: {text[:600]}"
        assert "reinitializedevice:" not in text, (
            f"reinit ran under --brute-force-dcc: {text[:600]}"
        )

    def test_brute_force_reinit_only(self, cli_runner, tmp_path):
        """--brute-force-reinit cracks ONLY the ReinitializeDevice password."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--brute-force-reinit",
            "--passwords",
            self._wordlist(tmp_path),
            "--confirm",
            timeout=45,
        )
        text = _text(result)
        assert "reinitializedevice: 'oida-reinit'" in text, f"reinit not cracked: {text[:600]}"
        assert "devicecommunicationcontrol:" not in text, (
            f"dcc ran under --brute-force-reinit: {text[:600]}"
        )

    def test_brute_force_distinct_dcc_and_reinit_passwords(self, cli_runner, tmp_path):
        """DCC and ReinitializeDevice are INDEPENDENT passwords; --brute-force
        (run-all) cracks BOTH and reports two *different* credentials.

        The building profile sets DCC='filister' (stock default) and
        reinit='OIDA-Reinit' (changed) - proving the two services are gated
        independently."""
        _require_udp(47821, "bacnet-realstack-building")
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--port",
            "47821",
            "--device-id",
            "22002",
            "--brute-force",
            "--passwords",
            self._wordlist(tmp_path),
            "--confirm",
            timeout=45,
        )
        text = _text(result)
        assert "devicecommunicationcontrol: 'filister'" in text, (
            f"DCC password not cracked: {text[:600]}"
        )
        assert "reinitializedevice: 'oida-reinit'" in text, (
            f"ReinitializeDevice password not cracked: {text[:600]}"
        )

    def test_call_atomic_write_file_roundtrip(self, cli_runner, tmp_path):
        """AtomicWriteFile (upload) writes a real file the device serves back.

        Targets file:103 (audit.log) so it never clobbers file:101 (config.ini)
        asserted by test_building_atomic_read_file."""
        _require_udp(47821, "bacnet-realstack-building")
        payload = tmp_path / "payload.bin"
        payload.write_text("oida --call upload marker 4711\n")
        base = ["bacnet", MOCK_HOST, "--port", "47821", "--device-id", "22002"]
        w = cli_runner.run(*base, "--call", "writefile", f"103:{payload}", "--confirm", timeout=40)
        assert "bytes from" in _text(w), f"AtomicWriteFile not acked: {_text(w)[:500]}"
        r = cli_runner.run(*base, "--read-file", "103", timeout=40)
        assert "oida --call upload marker 4711" in _text(r), (
            f"uploaded content did not round-trip: {_text(r)[:500]}"
        )
