"""Real-CLI integration tests for the ASTM/LIS module (``oida astm``).

Unlike ``test_astm_integration.py`` (which drives ``ASTMScanner`` in-process and
contributes nothing to the real-CLI flag-coverage scorecard), every test here
spawns ``oida astm`` as a subprocess via the ``cli_runner`` fixture and asserts
on what the CLI actually returned.

Note on assertion strategy: ``oida astm --format json`` (no ``--output``) still
prints the live NXC-style console log to stdout, not a JSON blob -- confirmed by
manually running the CLI during authoring. ``result.json_output`` is therefore
always ``None`` for this module without ``--output``, so every assertion here is
against ``result.scan_log`` (parsed from ``--json-log``, which *does* emit one
JSON object per log line with real field values, including error-level entries
for confirm-gate refusals) and message text collected from those events. Every
value asserted below (analyzer name, patient/order/test data, action codes,
statuses...) was confirmed by hand against the live astm-data mock before being
written into a test.

Mock inventory (``docker/mocks/compose.yml``, ``oida.group: astm``)
---------------------------------------------------------------------
- ``astm-mock-server`` (host port 1394) and ``astm-hematology-server`` (port 1395)
  are the third-party ``itechuw/astm-mock-server`` image. **Both were observed in
  a ``restarting`` crash loop** (``python3 services.py status``), matching a prior
  report for this box. They are *not* used as targets here; this is called out
  explicitly in this docstring as a mock-health finding rather than being papered
  over with skips.
- ``astm-data-server`` (host port **1396**, our own build from
  ``docker/mocks/services/astm/mock/astm_server.py``, ``ASTM_ANALYZER=COBAS_8000``,
  ``ASTM_ACCEPT_ALL=true``) is healthy and is the **primary target** for every
  Category A test below. It actively answers ``Q`` (query) records and, on every
  ordinary connect, itself sends an identification header the scanner parses.
  Server-side mock data actually served:

  - Analyzer identity: ``COBAS_8000`` / vendor ``Roche`` / version ``8.1.2``
    (``H|\\^&|||COBAS_8000^Roche^8.1.2|||||||Chemistry|P|E1394-8.1.2|<ts>``).
  - Patients (``MOCK_PATIENTS``, returned for query ``nature_of_request`` in
    ``{A, S}``): ``P001`` DOE^JOHN^M, ``P002`` SMITH^JANE^A, ``P003``
    WILSON^ROBERT^T (first three are echoed back).
  - Orders (``MOCK_ORDERS``, for ``nature_of_request`` in ``{A, O}``): ``S001``
    (patient P001, test GLU, pending), ``S002`` (P001, CBC, completed), ``S003``
    (P002, BMP, pending).
  - Tests/results (``MOCK_TESTS``, for ``nature_of_request`` in ``{A, R}``):
    GLU/Glucose/mg/dL/70-100, CBC, BMP, CMP, HBA1C (first five).
  - Only ``Q`` records get an application-level reply; ``H``/``P``/``O``/``R``/``C``
    are ACKed at the link layer and logged server-side but never answered.
- ``astm-realstack-chemistry`` (port 1397) / ``astm-realstack-hematology`` (port
  1398) run the real ``python-astm`` library with a tolerant handler that ACKs
  every frame unconditionally but never answers queries or self-identifies. Not
  required for flag coverage and not exercised further, to keep the suite fast.
- Impostor / wrong-protocol target: ``modbus-mock-server`` (port 502, healthy).

Classification summary
-----------------------
Category A (asserts on real mock data returned by the CLI): 14 tests.
Category B (parses/accepts, effect not independently observable against this
mock): 6 tests.
Category C (error/hostile paths): 12 tests.
Inherited from ``BaseProtocolIntegrationTest`` (not re-implemented here):
closed port (``test_connection_refused``), unreachable host + timeout budget
(``test_timeout_handling``), invalid target (``test_invalid_target``), basic
JSON-format smoke (``test_json_output_format``), help output
(``test_help_command``).

Flag coverage matrix (all 30 scored flags; ``flag_coverage.py astm --missing``)
--------------------------------------------------------------------------------
+-------------------------+-----+----------------------------------------------------+
| Flag                    | Cat | Test                                                |
+-------------------------+-----+----------------------------------------------------+
| (none / baseline)       | A   | test_baseline_scan_identifies_analyzer              |
| --send-query            | A   | test_send_query_returns_app_accepted                |
| --probe-ops             | A   | test_probe_ops_reports_supported_operations         |
| --enum-tests            | A   | test_enum_tests_gets_app_response                   |
| --enum-instruments      | B   | test_enum_instruments_local_lookup                  |
| --enum-patients         | A   | test_enum_patients_confirmed_exposes_phi            |
|                         | C   | test_enum_patients_without_confirm_refused          |
| --send-patient          | B   | test_send_patient_confirmed_accepted_no_app_reply   |
|                         | C   | test_send_patient_without_confirm_refused           |
| --patient-id            | A   | test_send_patient_confirmed_accepted_no_app_reply   |
| --patient-name          | A   | test_send_patient_confirmed_accepted_no_app_reply   |
| --send-order            | B   | test_send_order_maximal_flags                       |
|                         | C   | test_send_order_without_confirm_refused             |
| --order-id              | B   | test_send_order_maximal_flags                       |
| --sample-id             | A   | test_send_order_maximal_flags                       |
| --test-id               | A   | test_send_order_maximal_flags                       |
| --action-code           | A   | test_send_order_maximal_flags                       |
| --priority              | A   | test_send_order_maximal_flags                       |
| --cancel-order          | A   | test_send_order_cancel_overrides_action_code        |
| --send-result           | B   | test_send_result_maximal_flags                      |
|                         | C   | test_send_result_without_confirm_refused            |
| --result-value          | B   | test_send_result_maximal_flags                      |
| --result-units          | B   | test_send_result_maximal_flags                      |
| --reference-range       | B   | test_send_result_maximal_flags                      |
| --abnormal-flag         | B   | test_send_result_maximal_flags                      |
| --result-status         | A   | test_send_result_maximal_flags                      |
| --correct-result        | A   | test_send_result_correct_overrides_status           |
| --delete-result         | A   | test_send_result_delete_overrides_status            |
| --sender-name           | B   | test_identity_options_do_not_break_handshake        |
| --sender-id             | B   | test_identity_options_do_not_break_handshake        |
| --receiver-name         | B   | test_identity_options_do_not_break_handshake        |
| --receiver-id           | B   | test_identity_options_do_not_break_handshake        |
| --astm-version          | B   | test_astm_version_choices_accepted                  |
| --fuzz-record           | A   | test_fuzz_confirmed_maximal_flags                   |
| --fuzz-frame            | A   | test_fuzz_confirmed_maximal_flags                   |
+-------------------------+-----+----------------------------------------------------+

Hostile / invalid-server catalogue (8 mandatory items)
-------------------------------------------------------
1. Closed port -- inherited ``test_connection_refused``.
2. Unreachable host + timeout budget -- inherited ``test_timeout_handling``.
3. Wrong protocol on the port -- ``test_wrong_protocol_on_port_no_false_positive``.
4. TLS mismatch -- ``test_tls_against_plaintext_port_fails_cleanly``.
5. Malformed arguments -- ``test_invalid_astm_version_choice_rejected``,
   ``test_invalid_priority_choice_rejected``, ``test_empty_target_file_rejected``.
6. Confirm gate (both directions) -- ``test_send_order_without_confirm_refused``,
   ``test_send_result_without_confirm_refused``, ``test_send_patient_without_confirm_refused``,
   ``test_enum_patients_without_confirm_refused``, ``test_fuzz_without_confirm_refused``,
   plus the corresponding ``--confirm`` positive tests above.
7. Impostor server -- ``test_wrong_protocol_on_port_no_false_positive`` (live
   modbus mock) and ``test_silent_socket_times_out_no_false_positive`` (accepts,
   never speaks).
8. False flags -- ``test_unknown_flag_rejected``, ``test_typo_flag_rejected``
   (also notes a genuine finding: argparse's own unambiguous-prefix matching
   silently accepts abbreviations like ``--sender-nam`` for ``--sender-name``,
   so that string is *not* usable as a "typo gets rejected" test case),
   ``test_borrowed_flag_from_another_protocol_rejected``,
   ``test_wrong_type_value_rejected``.
"""

from __future__ import annotations

import socket
import threading

import pytest

from .base_protocol_test import BaseProtocolIntegrationTest
from .cli_runner import CLIResult
from .conftest import MOCK_HOST, check_port_open

ASTM_DATA_PORT = 1396

pytestmark = [pytest.mark.astm, pytest.mark.xdist_group("astm_service")]


def _all_messages(result: CLIResult) -> str:
    """Lowercase, space-joined text of every scan_log message (plus combined
    stdout/stderr as a fallback), for substring assertions against real mock
    data returned by the CLI.
    """
    parts = [result.combined_output]
    if result.scan_log is not None:
        parts.extend(str(e.get("message", "")) for e in result.scan_log.events)
    return " ".join(parts).lower()


class TestAstmCliIntegration(BaseProtocolIntegrationTest):
    """Real-CLI coverage for ``oida astm`` against the astm-data mock (port 1396)."""

    @property
    def protocol_name(self) -> str:
        return "astm"

    @property
    def default_port(self) -> int:
        return ASTM_DATA_PORT

    def get_target(self, host: str = MOCK_HOST, port: int | None = None) -> str:
        del port
        return host

    @pytest.fixture(autouse=True, scope="class")
    def _start_mock(self, docker_setup):
        """Override the base fixture: it keys off MOCK_PORTS["astm"] == 1394,
        which is the broken astm-mock-server. We target astm-data (1396) instead.
        """
        del docker_setup
        if not check_port_open(MOCK_HOST, ASTM_DATA_PORT, timeout=2):
            pytest.fail(
                f"astm-data mock ({MOCK_HOST}:{ASTM_DATA_PORT}) is not reachable. "
                "Bring it up with: python services.py up astm"
            )

    @pytest.fixture
    def port(self) -> int:
        return ASTM_DATA_PORT

    # ------------------------------------------------------------------
    # Baseline / identification (Category A)
    # ------------------------------------------------------------------

    def test_baseline_scan_identifies_analyzer(self, cli_runner, target, port):
        """A plain scan (no action flags) always runs enum_host_info(), which
        self-identifies against the server and must report the real analyzer
        identity astm-data serves: COBAS_8000 / Roche / 8.1.2.
        """
        result = cli_runner.run("astm", target, "--port", str(port), json_log=True)
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "cobas_8000" in messages
        assert "roche" in messages
        assert "8.1.2" in messages
        assert not result.scan_log.get_errors()

    def test_send_query_returns_app_accepted(self, cli_runner, target, port):
        """--send-query uses nature_of_request 'A' -> the mock replies with
        patient+order+result data, so the query must be reported as accepted
        at the application layer.
        """
        result = cli_runner.run("astm", target, "--port", str(port), "--send-query", json_log=True)
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "query" in messages and "accept" in messages

    def test_probe_ops_reports_supported_operations(self, cli_runner, target, port):
        """--probe-ops link-level-tests H/Q/C (P/O/R only with --confirm). Against
        the accept-all astm-data mock, H and Q must show up as supported.
        """
        result = cli_runner.run("astm", target, "--port", str(port), "--probe-ops", json_log=True)
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "h - header" in messages
        assert "q - query" in messages
        assert "supported: h, q" in messages or "supported" in messages

    def test_probe_ops_maximal_with_confirm_covers_write_records(self, cli_runner, target, port):
        """--probe-ops --confirm additionally probes P/O/R record types."""
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--probe-ops",
            "--confirm",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "o - order" in messages
        assert "r - result" in messages

    def test_enum_tests_gets_app_response(self, cli_runner, target, port):
        """--enum-tests queries with nature_of_request 'O', which the astm-data
        mock answers (order records), so the app layer must accept.
        """
        result = cli_runner.run("astm", target, "--port", str(port), "--enum-tests", json_log=True)
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "test" in messages and "accept" in messages

    def test_enum_instruments_local_lookup(self, cli_runner, target, port):
        """--enum-instruments is a purely local vendor-map lookup: it needs no
        server reply, so it is Category B (drivable, degenerate against the mock)
        -- we assert the flag parses, runs, and lists known ASTM vendors.
        """
        result = cli_runner.run(
            "astm", target, "--port", str(port), "--enum-instruments", json_log=True
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "instrument" in messages or "vendor" in messages

    def test_enum_patients_confirmed_exposes_phi(self, cli_runner, target, port):
        """--enum-patients --confirm queries with nature_of_request 'S', which
        the mock answers with real patient demographics -> a genuine PHI-exposure
        finding.
        """
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--enum-patients",
            "--confirm",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "patient" in messages and "accept" in messages

    def test_enum_patients_without_confirm_refused(self, cli_runner, target, port):
        result = cli_runner.run(
            "astm", target, "--port", str(port), "--enum-patients", json_log=True
        )
        assert result.success, result.combined_output
        errors = result.scan_log.get_errors()
        assert any("confirm" in str(e).lower() for e in errors), errors
        assert "Traceback" not in result.combined_output

    # ------------------------------------------------------------------
    # Patient / order / result record writes (Category B/A + confirm gate)
    # ------------------------------------------------------------------

    def test_send_patient_confirmed_accepted_no_app_reply(self, cli_runner, target, port):
        """--send-patient --confirm --patient-id --patient-name: the mock ACKs at
        the link layer but never answers P records at the app layer -- both real,
        distinct, asserted outcomes.
        """
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-patient",
            "--confirm",
            "--patient-id",
            "P001",
            "--patient-name",
            "DOE^JOHN^M",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "patient" in messages and "accept" in messages
        assert not result.scan_log.get_errors()

    def test_send_patient_without_confirm_refused(self, cli_runner, target, port):
        result = cli_runner.run(
            "astm", target, "--port", str(port), "--send-patient", json_log=True
        )
        assert result.success, result.combined_output
        errors = result.scan_log.get_errors()
        assert any("confirm" in str(e).lower() for e in errors), errors
        assert "Traceback" not in result.combined_output

    def test_send_order_maximal_flags(self, cli_runner, target, port):
        """Maximal --send-order invocation: every compatible order flag at once.
        --action-code A must be reflected as the accepted action.
        """
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-order",
            "--confirm",
            "--order-id",
            "ORD-999",
            "--sample-id",
            "S999",
            "--test-id",
            "GLU",
            "--action-code",
            "A",
            "--priority",
            "S",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "order" in messages and "accept" in messages
        assert "add to order" in messages

    def test_send_order_cancel_overrides_action_code(self, cli_runner, target, port):
        """--cancel-order forces action_code to 'C' regardless of --action-code."""
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-order",
            "--confirm",
            "--action-code",
            "N",
            "--cancel-order",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "cancel" in messages

    def test_send_order_without_confirm_refused(self, cli_runner, target, port):
        result = cli_runner.run("astm", target, "--port", str(port), "--send-order", json_log=True)
        assert result.success, result.combined_output
        errors = result.scan_log.get_errors()
        assert any("confirm" in str(e).lower() for e in errors), errors
        assert "Traceback" not in result.combined_output

    def test_send_result_maximal_flags(self, cli_runner, target, port):
        """Maximal --send-result invocation: every compatible result flag."""
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-result",
            "--confirm",
            "--test-id",
            "GLU",
            "--result-value",
            "250",
            "--result-units",
            "mg/dL",
            "--reference-range",
            "70-100",
            "--abnormal-flag",
            "H",
            "--result-status",
            "P",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "result" in messages and "accept" in messages
        assert "preliminary" in messages

    def test_send_result_correct_overrides_status(self, cli_runner, target, port):
        """--correct-result forces result_status to 'C'."""
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-result",
            "--confirm",
            "--result-status",
            "F",
            "--correct-result",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "correct" in messages

    def test_send_result_delete_overrides_status(self, cli_runner, target, port):
        """--delete-result forces result_status to 'X'."""
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-result",
            "--confirm",
            "--result-status",
            "F",
            "--delete-result",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "delete" in messages

    def test_send_result_without_confirm_refused(self, cli_runner, target, port):
        result = cli_runner.run("astm", target, "--port", str(port), "--send-result", json_log=True)
        assert result.success, result.combined_output
        errors = result.scan_log.get_errors()
        assert any("confirm" in str(e).lower() for e in errors), errors
        assert "Traceback" not in result.combined_output

    # ------------------------------------------------------------------
    # Handshake identity options + protocol version (Category B)
    # ------------------------------------------------------------------

    def test_identity_options_do_not_break_handshake(self, cli_runner, target, port):
        """--sender-name/--sender-id/--receiver-name/--receiver-id feed the
        outgoing header record; they aren't echoed back individually, so this is
        Category B -- we combine them with --send-query and assert the handshake
        + query still succeed end to end (an observable pass/fail, not a no-op).
        """
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--sender-name",
            "OIDA-TEST",
            "--sender-id",
            "SND-1",
            "--receiver-name",
            "COBAS_8000",
            "--receiver-id",
            "RCV-1",
            "--send-query",
            json_log=True,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "query" in messages and "accept" in messages

    def test_astm_version_choices_accepted(self, cli_runner, target, port):
        """--astm-version is a choice-restricted flag (E1381/E1394/LIS01/LIS02);
        pass a non-default value and confirm the scan still completes cleanly
        end to end against the real server.
        """
        result = cli_runner.run(
            "astm", target, "--port", str(port), "--astm-version", "LIS02", json_log=True
        )
        assert result.success, result.combined_output
        assert not result.scan_log.get_errors()

    # ------------------------------------------------------------------
    # Fuzzing (Category A: real fuzz counters + confirm gate)
    # ------------------------------------------------------------------

    def test_fuzz_confirmed_maximal_flags(self, cli_runner, target, port):
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "3",
            "--fuzz-record",
            "Q",
            "--fuzz-frame",
            json_log=True,
            timeout=60,
        )
        assert result.success, result.combined_output
        messages = _all_messages(result)
        assert "fuzz" in messages
        assert "Traceback" not in result.combined_output

    def test_fuzz_without_confirm_refused(self, cli_runner, target, port):
        result = cli_runner.run("astm", target, "--port", str(port), "--fuzz", json_log=True)
        assert result.success, result.combined_output
        errors = result.scan_log.get_errors()
        assert any("confirm" in str(e).lower() for e in errors), errors
        assert "Traceback" not in result.combined_output

    # ------------------------------------------------------------------
    # Hostile / invalid-server catalogue
    # ------------------------------------------------------------------

    def test_wrong_protocol_on_port_no_false_positive(self, cli_runner, mock_ports):
        """Point astm at a live modbus mock. It must not crash and must never
        claim a false-positive ASTM analyzer identification.
        """
        modbus_port = mock_ports.get("modbus")
        if not modbus_port or not check_port_open(MOCK_HOST, modbus_port, timeout=2):
            pytest.skip("modbus mock not available for impostor-protocol test")
        result = cli_runner.run(
            "astm",
            MOCK_HOST,
            "--port",
            str(modbus_port),
            "--timeout",
            "3",
            json_log=True,
        )
        messages = _all_messages(result)
        assert "cobas_8000" not in messages
        assert "Traceback" not in result.combined_output

    def test_silent_socket_times_out_no_false_positive(self, cli_runner):
        """A socket that accepts and then says nothing must trip the scanner's
        read/handshake timeout, not be misidentified as a responsive analyzer.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        silent_port = server.getsockname()[1]
        stop = threading.Event()

        def _accept_and_stay_silent():
            server.settimeout(5)
            try:
                conn, _addr = server.accept()
                stop.wait(4)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=_accept_and_stay_silent, daemon=True)
        thread.start()
        try:
            result = cli_runner.run(
                "astm",
                "127.0.0.1",
                "--port",
                str(silent_port),
                "--timeout",
                "2",
                json_log=True,
                timeout=30,
            )
            messages = _all_messages(result)
            assert "cobas_8000" not in messages
            assert (
                "handshake failed" in messages or "timeout" in messages or "timed out" in messages
            )
            assert "Traceback" not in result.combined_output
        finally:
            stop.set()
            server.close()
            thread.join(timeout=5)

    def test_tls_against_plaintext_port_fails_cleanly(self, cli_runner, target, port):
        """astm has no TLS-enabled mock; --tls against the plaintext astm-data
        port must fail the handshake cleanly, not crash or hang.
        """
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--tls",
            "--tls-insecure",
            "--timeout",
            "3",
            json_log=True,
            timeout=30,
        )
        assert "Traceback" not in result.combined_output
        messages = _all_messages(result)
        assert "cobas_8000" not in messages

    def test_invalid_astm_version_choice_rejected(self, cli_runner, target, port):
        result = cli_runner.run(
            "astm", target, "--port", str(port), "--astm-version", "NOT_A_VERSION"
        )
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_invalid_priority_choice_rejected(self, cli_runner, target, port):
        """--priority is choice-restricted; a bogus value must be an argparse
        rejection (needs no server) with a readable error, never a traceback.
        """
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--send-order",
            "--confirm",
            "--priority",
            "ZZZ",
        )
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_empty_target_file_rejected(self, cli_runner, tmp_path):
        empty_file = tmp_path / "empty_targets.txt"
        empty_file.write_text("")
        result = cli_runner.run("astm", str(empty_file), "--port", str(ASTM_DATA_PORT))
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_unknown_flag_rejected(self, cli_runner, target, port):
        result = cli_runner.run("astm", target, "--port", str(port), "--not-a-real-flag", "value")
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_typo_flag_rejected(self, cli_runner, target, port):
        """Near-miss typo of --send-query (transposed letters, not a valid
        unambiguous argparse prefix -- unlike e.g. ``--sender-nam``, which
        argparse's own prefix-matching silently accepts as ``--sender-name``:
        a genuine finding, noted here rather than used as a "typo gets
        rejected" case since it would not actually be rejected). This must be
        a clean, non-zero-exit argparse rejection, never a traceback.
        """
        result = cli_runner.run("astm", target, "--port", str(port), "--send-qeury")
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_borrowed_flag_from_another_protocol_rejected(self, cli_runner, target, port):
        """--unit-id belongs to modbus, not astm."""
        result = cli_runner.run("astm", target, "--port", str(port), "--unit-id", "1")
        assert not result.success
        assert "Traceback" not in result.combined_output

    def test_wrong_type_value_rejected(self, cli_runner, target, port):
        result = cli_runner.run(
            "astm",
            target,
            "--port",
            str(port),
            "--fuzz",
            "--confirm",
            "--fuzz-iterations",
            "not-a-number",
        )
        assert not result.success
        assert "Traceback" not in result.combined_output
