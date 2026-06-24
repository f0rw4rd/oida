"""Unit tests for services.py — OIDA service manager.

Tests cover:
- Argparse subcommand parsing
- check_port / check_port_udp with mocked sockets
- wait_healthy with mocked subprocess
- list and ports commands with mocked compose config
- up with different stack values
- up-proto label resolution
- clean command (including filesystem cleanup)
- Color output formatting and NO_COLOR support
- Error handling (timeouts, unreachable ports)
- Docker pre-flight check
- _wait_service_healthy direct tests
- cmd_build unknown stack error
- JSON parse error in _get_compose_config
- groups command + data-driven `up <group>` (core + CVE span)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure services.py is importable from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import services as dev


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_run():
    """Patch subprocess.run globally for dev module."""
    with patch.object(dev, "_run") as m:
        m.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        yield m


@pytest.fixture()
def mock_subprocess_run():
    """Patch subprocess.run at the subprocess level (for check_port etc)."""
    with patch("subprocess.run") as m:
        m.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        yield m


@pytest.fixture()
def sample_compose_config():
    """Return a realistic compose config dict for testing."""
    return {
        "services": {
            "modbus-mock": {
                "labels": {
                    "oida.group": "modbus",
                    "oida.ports": "502",
                    "oida.description": "Modbus TCP simulator",
                },
                "profiles": [],
            },
            "opcua-mock": {
                "labels": {
                    "oida.group": "opcua",
                    "oida.ports": "4840",
                    "oida.description": "OPC UA server",
                },
                "profiles": ["opcua-extra"],
            },
            "hart-mock": {
                "labels": {
                    "oida.group": "hart",
                    "oida.ports": "5094-5095",
                    "oida.description": "HART-IP gateway",
                },
                "profiles": [],
            },
            "no-label-svc": {
                "labels": {},
                "profiles": [],
            },
        }
    }


@pytest.fixture()
def sample_cve_config():
    """Compose config with CVE services."""
    return {
        "services": {
            "modbus-cve-2024-10918": {
                "labels": {
                    "oida.group": "modbus",
                    "oida.ports": "5030",
                    "oida.description": "Modbus CVE demo",
                    "oida.cve": "CVE-2024-10918",
                },
            },
            "mqtt-cve-2023-1234": {
                "labels": {
                    "oida.group": "mqtt",
                    "oida.ports": "1885",
                    "oida.description": "MQTT CVE demo",
                    "oida.cve": "CVE-2023-1234",
                },
            },
        }
    }


# ---------------------------------------------------------------------------
# Argparse Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestArgparse:
    """Test that all subcommands parse correctly."""

    def test_no_args_shows_help(self):
        parser = dev.build_parser()
        args = parser.parse_args([])
        assert args.command is None

    def test_up_default(self):
        parser = dev.build_parser()
        args = parser.parse_args(["up"])
        assert args.command == "up"
        assert args.stack == "core"

    def test_up_with_stack(self):
        parser = dev.build_parser()
        for stack in ("core", "cve", "all", "hart"):
            args = parser.parse_args(["up", stack])
            assert args.stack == stack

    def test_down(self):
        parser = dev.build_parser()
        args = parser.parse_args(["down"])
        assert args.command == "down"

    def test_restart(self):
        parser = dev.build_parser()
        args = parser.parse_args(["restart"])
        assert args.command == "restart"

    def test_status(self):
        parser = dev.build_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"

    def test_logs_no_service(self):
        parser = dev.build_parser()
        args = parser.parse_args(["logs"])
        assert args.command == "logs"
        assert args.service == []

    def test_logs_with_services(self):
        parser = dev.build_parser()
        args = parser.parse_args(["logs", "modbus-mock", "opcua-mock"])
        assert args.service == ["modbus-mock", "opcua-mock"]

    def test_build_default(self):
        parser = dev.build_parser()
        args = parser.parse_args(["build"])
        assert args.stack == "core"

    def test_build_with_stack(self):
        parser = dev.build_parser()
        args = parser.parse_args(["build", "cve"])
        assert args.stack == "cve"

    def test_push_default(self):
        parser = dev.build_parser()
        args = parser.parse_args(["push"])
        assert args.command == "push"
        assert args.batch == 10

    def test_push_batch(self):
        parser = dev.build_parser()
        args = parser.parse_args(["push", "--batch", "4"])
        assert args.batch == 4

    def test_clean(self):
        parser = dev.build_parser()
        args = parser.parse_args(["clean"])
        assert args.command == "clean"

    def test_list_command(self):
        parser = dev.build_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"

    def test_ports_command(self):
        parser = dev.build_parser()
        args = parser.parse_args(["ports"])
        assert args.command == "ports"

    def test_up_cve(self):
        parser = dev.build_parser()
        args = parser.parse_args(["up-cve", "smtp"])
        assert args.command == "up-cve"
        assert args.proto == "smtp"

    def test_up_proto(self):
        parser = dev.build_parser()
        args = parser.parse_args(["up-proto", "hart"])
        assert args.command == "up-proto"
        assert args.group == "hart"

    def test_groups_command_parses(self):
        parser = dev.build_parser()
        args = parser.parse_args(["groups"])
        assert args.command == "groups"

    def test_removed_per_protocol_commands_rejected(self):
        """The old PROTO_SPECS up-<x> commands are gone; argparse must reject them."""
        parser = dev.build_parser()
        for old in ("up-goose", "up-mqtt", "up-modbus-vuln", "up-opener"):
            with pytest.raises(SystemExit):
                parser.parse_args([old])

    def test_all_commands_have_dispatch(self):
        """Every parser subcommand should have a dispatch handler."""
        parser = dev.build_parser()
        # Get all registered subcommand names
        subparsers_action = None
        for action in parser._subparsers._actions:
            if hasattr(action, "_parser_class"):
                subparsers_action = action
                break
        assert subparsers_action is not None
        registered = set(subparsers_action.choices.keys())
        dispatched = set(dev.COMMAND_DISPATCH.keys())
        assert registered == dispatched, f"Missing dispatch: {registered - dispatched}"


class TestPushCommand:
    """Test cmd_push registry guard."""

    def test_push_fails_hard_without_registry(self, monkeypatch):
        """Unset OIDA_REGISTRY must abort before touching docker."""
        monkeypatch.setattr(dev, "_load_dotenv", lambda: None)
        monkeypatch.delenv("OIDA_REGISTRY", raising=False)
        args = SimpleNamespace(batch=10)
        with patch("subprocess.run") as m:
            rc = dev.cmd_push(args)
        assert rc == 1
        m.assert_not_called()


# ---------------------------------------------------------------------------
# check_port / check_port_udp Tests
# ---------------------------------------------------------------------------


class TestCheckPort:
    """Test TCP/UDP port checking with mocked sockets."""

    def test_tcp_port_reachable(self, capsys):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        with patch("services.socket.create_connection", return_value=mock_conn):
            result = dev.check_port(502, "Modbus")
        assert result is True
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        assert "Modbus" in captured.out
        assert ":502" in captured.out

    def test_tcp_port_unreachable(self, capsys):
        with patch("services.socket.create_connection", side_effect=OSError("refused")):
            result = dev.check_port(502, "Modbus")
        assert result is False
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "not reachable" in captured.out

    def test_tcp_port_timeout(self, capsys):
        with patch("services.socket.create_connection", side_effect=TimeoutError("timed out")):
            result = dev.check_port(4840, "OPC UA")
        assert result is False
        captured = capsys.readouterr()
        assert "[!!]" in captured.out

    def test_udp_port_reachable(self, capsys):
        """UDP port open: sendto succeeds, recvfrom times out (no ICMP rejection)."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.side_effect = TimeoutError("timed out")
        with patch("services.socket.socket", return_value=mock_sock):
            result = dev.check_port(5094, "HART-IP", udp=True)
        assert result is True
        mock_sock.settimeout.assert_called_once_with(dev.PORT_CHECK_TIMEOUT)
        mock_sock.sendto.assert_called_once()
        captured = capsys.readouterr()
        assert "UDP:5094" in captured.out

    def test_udp_port_connection_refused(self, capsys):
        """UDP port closed: ICMP port unreachable raises ConnectionRefusedError."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.side_effect = ConnectionRefusedError("port unreachable")
        # ConnectionRefusedError is raised during the recv, but our code catches it
        # at the outer level since it's a subclass of OSError. However, the code
        # specifically catches ConnectionRefusedError first.
        # Actually, looking at the code: the recvfrom raises ConnectionRefusedError
        # which is NOT caught by the inner try (only TimeoutError is). So it propagates
        # to the outer except ConnectionRefusedError.
        with patch("services.socket.socket", return_value=mock_sock):
            result = dev.check_port(5094, "HART-IP", udp=True)
        assert result is False
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "UDP:5094" in captured.out

    def test_udp_port_os_error(self, capsys):
        """UDP port OSError (e.g. network unreachable) returns False."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto.side_effect = OSError("network unreachable")
        with patch("services.socket.socket", return_value=mock_sock):
            result = dev.check_port(5094, "HART-IP", udp=True)
        assert result is False
        captured = capsys.readouterr()
        assert "[!!]" in captured.out

    def test_udp_socket_creation_fails(self, capsys):
        """If socket creation fails, return False."""
        with patch("services.socket.socket", side_effect=OSError("cannot create")):
            result = dev.check_port(5094, "HART-IP", udp=True)
        assert result is False
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "UDP:5094" in captured.out

    def test_check_port_udp_wrapper(self, capsys):
        """check_port_udp is a convenience wrapper."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.side_effect = TimeoutError("timed out")
        with patch("services.socket.socket", return_value=mock_sock):
            result = dev.check_port_udp(10161, "SNMP")
        assert result is True

    def test_custom_host(self, capsys):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        with patch("services.socket.create_connection", return_value=mock_conn) as mock_create:
            dev.check_port(502, "Modbus", host="192.168.1.100")
        mock_create.assert_called_once_with(("192.168.1.100", 502), timeout=dev.PORT_CHECK_TIMEOUT)

    def test_udp_custom_host(self, capsys):
        """UDP check_port with custom host passes the right target."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.side_effect = TimeoutError("timed out")
        with patch("services.socket.socket", return_value=mock_sock):
            result = dev.check_port(5094, "HART-IP", udp=True, host="10.0.0.1")
        assert result is True
        mock_sock.sendto.assert_called_once_with(b"\x00", ("10.0.0.1", 5094))

    def test_default_host_from_constant(self, capsys):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        with patch("services.socket.create_connection", return_value=mock_conn) as mock_create:
            dev.check_port(502, "Modbus")
        mock_create.assert_called_once_with((dev.MOCK_HOST, 502), timeout=dev.PORT_CHECK_TIMEOUT)


# ---------------------------------------------------------------------------
# wait_healthy Tests
# ---------------------------------------------------------------------------


class TestWaitHealthy:
    """Test wait_healthy with mocked subprocess calls."""

    def test_all_healthy_immediately(self, capsys):
        """Services that are immediately healthy should return quickly."""
        compose_args = ["-f", "compose.yml"]

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "--format" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="svc-a\nsvc-b\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="healthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            result = dev.wait_healthy(compose_args)
        assert result is True
        captured = capsys.readouterr()
        assert "All services healthy" in captured.out

    def test_no_containers(self, capsys):
        """No containers should return False."""
        compose_args = ["-f", "compose.yml"]

        def run_side_effect(cmd, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            result = dev.wait_healthy(compose_args)
        assert result is False
        captured = capsys.readouterr()
        assert "No containers found" in captured.out

    def test_unhealthy_service_reported(self, capsys):
        """Unhealthy service should be reported but loop continues."""
        compose_args = ["-f", "compose.yml"]
        call_count = {"inspect": 0}

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "--format" in cmd and "Name" in str(cmd):
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="svc-a\n", stderr=""
                )
            if "inspect" in cmd:
                call_count["inspect"] += 1
                # First call: unhealthy, second: healthy
                if call_count["inspect"] <= 1:
                    return subprocess.CompletedProcess(
                        args=cmd, returncode=0, stdout="unhealthy\n", stderr=""
                    )
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="healthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            with patch("time.sleep"):
                result = dev.wait_healthy(compose_args)
        assert result is True

    def test_timeout_returns_false(self, capsys):
        """Timeout should return False and show status."""
        compose_args = ["-f", "compose.yml"]

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "--format" in cmd and "Name" in str(cmd):
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="svc-a\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="starting\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            with patch("time.sleep"):
                result = dev.wait_healthy(compose_args, timeout=6)
        assert result is False
        captured = capsys.readouterr()
        assert "Timeout" in captured.out

    def test_services_without_healthcheck_ignored(self, capsys):
        """Services without healthcheck (status='none') should be ignored."""
        compose_args = ["-f", "compose.yml"]

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "--format" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="svc-no-health\n", stderr=""
                )
            if "inspect" in cmd:
                # Returns "none" — no healthcheck defined
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="none\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            result = dev.wait_healthy(compose_args)
        assert result is True

    def test_inspect_failure_treated_as_not_found(self, capsys):
        """#13: Non-zero returncode from inspect means container not found."""
        compose_args = ["-f", "compose.yml"]
        call_count = {"inspect": 0}

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "--format" in cmd and "Name" in str(cmd):
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="svc-a\n", stderr=""
                )
            if "inspect" in cmd:
                call_count["inspect"] += 1
                if call_count["inspect"] <= 1:
                    # First call: inspect fails (container not found)
                    return subprocess.CompletedProcess(
                        args=cmd, returncode=1, stdout="", stderr="not found"
                    )
                # Second call: healthy
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="healthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            with patch("time.sleep"):
                result = dev.wait_healthy(compose_args)
        assert result is True


# ---------------------------------------------------------------------------
# _wait_service_healthy Tests
# ---------------------------------------------------------------------------


class TestWaitServiceHealthy:
    """Test _wait_service_healthy directly."""

    def test_healthy_returns_true(self):
        """Service that becomes healthy returns True."""

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "-q" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="healthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            result = dev._wait_service_healthy("test-svc", ["-f", "compose.yml"], timeout=10)
        assert result is True

    def test_unhealthy_returns_false(self, capsys):
        """Service that is unhealthy returns False."""

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "-q" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="unhealthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            result = dev._wait_service_healthy("test-svc", ["-f", "compose.yml"], timeout=10)
        assert result is False
        captured = capsys.readouterr()
        assert "unhealthy" in captured.out

    def test_no_healthcheck_returns_true(self):
        """Service with no healthcheck (status='none') returns True."""

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "-q" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="none\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            result = dev._wait_service_healthy("test-svc", ["-f", "compose.yml"], timeout=10)
        assert result is True

    def test_timeout_returns_false(self):
        """Service that never becomes healthy times out and returns False."""

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "-q" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="starting\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            with patch("time.sleep"):
                # Use time.time mock to simulate timeout
                times = iter([0, 1, 2, 100])
                with patch("time.time", side_effect=times):
                    result = dev._wait_service_healthy(
                        "test-svc", ["-f", "compose.yml"], timeout=10
                    )
        assert result is False

    def test_no_container_id_retries(self):
        """If container ID is not found initially, retries until timeout."""
        call_count = {"ps": 0}

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "-q" in cmd:
                call_count["ps"] += 1
                if call_count["ps"] <= 1:
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="healthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            with patch("time.sleep"):
                times = iter([0, 1, 2, 3])
                with patch("time.time", side_effect=times):
                    result = dev._wait_service_healthy(
                        "test-svc", ["-f", "compose.yml"], timeout=60
                    )
        assert result is True

    def test_inspect_failure_retries(self):
        """Inspect failure (container not found) should retry."""
        call_count = {"inspect": 0}

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd and "-q" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr=""
                )
            if "inspect" in cmd:
                call_count["inspect"] += 1
                if call_count["inspect"] <= 1:
                    return subprocess.CompletedProcess(
                        args=cmd, returncode=1, stdout="", stderr="not found"
                    )
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="healthy\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=run_side_effect):
            with patch("time.sleep"):
                times = iter([0, 1, 2, 3])
                with patch("time.time", side_effect=times):
                    result = dev._wait_service_healthy(
                        "test-svc", ["-f", "compose.yml"], timeout=60
                    )
        assert result is True


# ---------------------------------------------------------------------------
# list command Tests
# ---------------------------------------------------------------------------


class TestListCommand:
    """Test the list command with mocked compose config."""

    def test_list_shows_core_services(self, mock_run, sample_compose_config, capsys):
        """list command should show services with oida.group labels."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(sample_compose_config), stderr=""
        )

        with patch.object(dev, "_get_compose_config") as mock_config:
            # First call = core config, second call = CVE config
            mock_config.side_effect = [sample_compose_config, {"services": {}}]
            args = SimpleNamespace(command="list")
            dev.cmd_list(args)

        captured = capsys.readouterr()
        assert "Core Services" in captured.out
        assert "CVE Services" in captured.out

    def test_list_shows_groups_and_descriptions(self, capsys):
        """Service group names and descriptions should appear in output."""
        config = {
            "services": {
                "hart-mock": {
                    "labels": {
                        "oida.group": "hart",
                        "oida.ports": "5094",
                        "oida.description": "HART-IP gateway",
                    }
                }
            }
        }
        with patch.object(dev, "_get_compose_config") as mock_config:
            mock_config.side_effect = [config, {"services": {}}]
            dev.cmd_list(SimpleNamespace(command="list"))

        captured = capsys.readouterr()
        assert "hart" in captured.out
        assert "5094" in captured.out
        assert "HART-IP gateway" in captured.out

    def test_list_shows_cve_info(self, capsys, sample_cve_config):
        """CVE services should show CVE identifiers."""
        with patch.object(dev, "_get_compose_config") as mock_config:
            mock_config.side_effect = [{"services": {}}, sample_cve_config]
            dev.cmd_list(SimpleNamespace(command="list"))

        captured = capsys.readouterr()
        assert "CVE-2024-10918" in captured.out
        assert "CVE-2023-1234" in captured.out

    def test_list_skips_services_without_group(self, capsys):
        """Services without oida.group label should be excluded."""
        config = {
            "services": {
                "no-label": {"labels": {}},
                "labeled": {
                    "labels": {
                        "oida.group": "modbus",
                        "oida.ports": "502",
                        "oida.description": "Modbus",
                    }
                },
            }
        }
        with patch.object(dev, "_get_compose_config") as mock_config:
            mock_config.side_effect = [config, {"services": {}}]
            dev.cmd_list(SimpleNamespace(command="list"))

        captured = capsys.readouterr()
        assert "no-label" not in captured.out
        assert "modbus" in captured.out


# ---------------------------------------------------------------------------
# ports command Tests
# ---------------------------------------------------------------------------


class TestPortsCommand:
    """Test the ports command with mocked docker output."""

    def _make_ps_json(self, containers: list[dict]) -> str:
        """Build JSON output like docker compose ps --format json."""
        return "\n".join(json.dumps(c) for c in containers)

    def test_ports_no_running_services(self, mock_run, capsys):
        """No running services should show helpful message."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        dev.cmd_ports(SimpleNamespace(command="ports"))
        captured = capsys.readouterr()
        assert "No running services" in captured.out

    def test_ports_shows_running_containers(self, capsys):
        """Running containers should show port/protocol/status."""
        ps_json = self._make_ps_json(
            [
                {
                    "Name": "modbus-mock",
                    "State": "running",
                    "Health": "healthy",
                    "Publishers": [{"PublishedPort": 502, "TargetPort": 502, "Protocol": "tcp"}],
                }
            ]
        )
        inspect_output = "modbus"

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=ps_json, stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=inspect_output, stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch.object(dev, "_run", side_effect=run_side_effect):
            dev.cmd_ports(SimpleNamespace(command="ports"))

        captured = capsys.readouterr()
        assert "502" in captured.out
        assert "modbus" in captured.out

    def test_ports_detects_healthy_state(self, capsys):
        """healthy containers should show green status."""
        ps_json = self._make_ps_json(
            [
                {
                    "Name": "svc-a",
                    "State": "running",
                    "Health": "healthy",
                    "Publishers": [{"PublishedPort": 1234, "TargetPort": 1234, "Protocol": "tcp"}],
                }
            ]
        )

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=ps_json, stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="test-proto", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch.object(dev, "_run", side_effect=run_side_effect):
            dev.cmd_ports(SimpleNamespace(command="ports"))

        captured = capsys.readouterr()
        assert "healthy" in captured.out

    def test_ports_deduplicates(self, capsys):
        """Same port:name should not appear twice."""
        ps_json = self._make_ps_json(
            [
                {
                    "Name": "svc",
                    "State": "running",
                    "Health": "",
                    "Publishers": [
                        {"PublishedPort": 502, "TargetPort": 502, "Protocol": "tcp"},
                        {"PublishedPort": 502, "TargetPort": 502, "Protocol": "tcp"},
                    ],
                }
            ]
        )

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=ps_json, stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="modbus", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch.object(dev, "_run", side_effect=run_side_effect):
            dev.cmd_ports(SimpleNamespace(command="ports"))

        captured = capsys.readouterr()
        # Port 502 should appear exactly once in the table (not counting header)
        lines_with_502 = [
            line for line in captured.out.split("\n") if "502" in line and "modbus" in line
        ]
        assert len(lines_with_502) == 1

    def test_ports_fallback_to_ports_string(self, capsys):
        """Falls back to parsing Ports string if Publishers is empty."""
        ps_json = self._make_ps_json(
            [
                {
                    "Name": "old-svc",
                    "State": "running",
                    "Health": "",
                    "Publishers": [],
                    "Ports": "0.0.0.0:9999->9999/tcp",
                }
            ]
        )

        def run_side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=ps_json, stderr=""
                )
            if "inspect" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="test", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch.object(dev, "_run", side_effect=run_side_effect):
            dev.cmd_ports(SimpleNamespace(command="ports"))

        captured = capsys.readouterr()
        assert "9999" in captured.out


# ---------------------------------------------------------------------------
# up command Tests
# ---------------------------------------------------------------------------


class TestUpCommand:
    """Test the up command with different stack values."""

    @staticmethod
    def _up_args(stack, *, build=False, no_pull=False, quiet_pull=False):
        return SimpleNamespace(stack=stack, build=build, no_pull=no_pull, quiet_pull=quiet_pull)

    def test_up_core(self, mock_run):
        with patch.object(dev, "wait_healthy", return_value=True):
            result = dev.cmd_up(self._up_args("core", build=True))
        assert result == 0
        # Should call docker compose up with core file + --build (build path skips pull)
        mock_run.assert_called()
        first_call_args = mock_run.call_args_list[0][0][0]
        assert dev.COMPOSE_CORE in first_call_args
        assert "up" in first_call_args
        assert "--build" in first_call_args

    def test_up_cve(self, mock_run):
        with patch.object(dev, "wait_healthy", return_value=True):
            result = dev.cmd_up(self._up_args("cve", no_pull=True))
        assert result == 0
        first_call_args = mock_run.call_args_list[0][0][0]
        assert dev.COMPOSE_CVE in first_call_args
        assert "--profile" in first_call_args
        assert "vuln-services" in first_call_args

    def test_up_all(self, mock_run):
        with patch.object(dev, "wait_healthy", return_value=True):
            result = dev.cmd_up(self._up_args("all", no_pull=True))
        assert result == 0

    def test_up_quiet_pull_threads_through(self, mock_run):
        """--quiet-pull should suppress pull stderr (default shows docker progress)."""
        with patch.object(dev, "wait_healthy", return_value=True):
            with patch.object(dev, "_pull") as mock_pull:
                dev.cmd_up(self._up_args("core", quiet_pull=True))
        assert mock_pull.call_args.kwargs["quiet"] is True
        with patch.object(dev, "wait_healthy", return_value=True):
            with patch.object(dev, "_pull") as mock_pull:
                dev.cmd_up(self._up_args("core"))
        assert mock_pull.call_args.kwargs["quiet"] is False  # loud by default

    def test_up_unknown_stack_delegates_to_group_path(self, mock_run):
        """Unknown stack names should delegate to the data-driven group path."""
        with patch.object(dev, "_up_proto_impl", return_value=0) as mock_proto:
            result = dev.cmd_up(self._up_args("hart"))
        assert result == 0
        mock_proto.assert_called_once_with("hart", quiet_pull=False)

    def test_up_returns_1_on_unhealthy(self, mock_run):
        with patch.object(dev, "wait_healthy", return_value=False):
            with patch.object(dev, "_pull"):
                result = dev.cmd_up(self._up_args("core"))
        assert result == 1


# ---------------------------------------------------------------------------
# up-proto Tests
# ---------------------------------------------------------------------------


class TestUpProto:
    """Test up-proto label resolution with mocked compose config."""

    def test_resolves_services_by_group(self, sample_compose_config):
        """Should find services matching oida.group label."""
        with patch.object(dev, "_get_compose_config", return_value=sample_compose_config):
            services = dev._resolve_services_by_group("hart", ["-f", "compose.yml"])
        assert services == ["hart-mock"]

    def test_resolves_services_with_config_param(self, sample_compose_config):
        """Should use provided config instead of calling _get_compose_config."""
        # Should NOT call _get_compose_config when config is provided
        with patch.object(dev, "_get_compose_config") as mock_config:
            services = dev._resolve_services_by_group(
                "hart", ["-f", "compose.yml"], config=sample_compose_config
            )
        mock_config.assert_not_called()
        assert services == ["hart-mock"]

    def test_resolves_multiple_services(self, sample_compose_config):
        """Multiple services with same group should all be returned."""
        config = {
            "services": {
                "mqtt-a": {"labels": {"oida.group": "mqtt"}, "profiles": []},
                "mqtt-b": {"labels": {"oida.group": "mqtt"}, "profiles": []},
            }
        }
        with patch.object(dev, "_get_compose_config", return_value=config):
            services = dev._resolve_services_by_group("mqtt", ["-f", "compose.yml"])
        assert services == ["mqtt-a", "mqtt-b"]

    def test_no_matching_group_returns_empty(self, sample_compose_config):
        with patch.object(dev, "_get_compose_config", return_value=sample_compose_config):
            services = dev._resolve_services_by_group("nonexistent", ["-f", "compose.yml"])
        assert services == []

    def test_up_proto_no_match_shows_available(self, mock_run, sample_compose_config, capsys):
        """No match should list available groups and return 1."""
        with patch.object(dev, "_get_compose_config", return_value=sample_compose_config):
            result = dev._up_proto_impl("nonexistent")
        assert result == 1
        captured = capsys.readouterr()
        assert "No services found" in captured.out
        assert "Available groups" in captured.out
        # Should list actual groups
        assert "modbus" in captured.out
        assert "hart" in captured.out

    def test_up_proto_activates_profiles(self, mock_run, capsys):
        """Services with profiles should have --profile args."""
        config = {
            "services": {
                "goose-pub": {
                    "labels": {
                        "oida.group": "goose",
                        "oida.ports": "L2",
                        "oida.description": "GOOSE publisher",
                    },
                    "profiles": ["goose-l2"],
                }
            }
        }
        with patch.object(dev, "_get_compose_config", return_value=config):
            with patch.object(dev, "_wait_service_healthy", return_value=True):
                result = dev._up_proto_impl("goose")

        assert result == 0
        # Check that --profile goose-l2 was passed
        up_call = None
        for c in mock_run.call_args_list:
            args = c[0][0]
            if "up" in args:
                up_call = args
                break
        assert up_call is not None
        assert "--profile" in up_call
        assert "goose-l2" in up_call

    def test_up_proto_deduplicates_profiles(self, mock_run, capsys):
        """#1: Duplicate profiles should only appear once."""
        config = {
            "services": {
                "svc-a": {
                    "labels": {"oida.group": "test"},
                    "profiles": ["shared-profile"],
                },
                "svc-b": {
                    "labels": {"oida.group": "test"},
                    "profiles": ["shared-profile"],
                },
            }
        }
        with patch.object(dev, "_get_compose_config", return_value=config):
            with patch.object(dev, "_wait_service_healthy", return_value=True):
                result = dev._up_proto_impl("test")

        assert result == 0
        up_call = None
        for c in mock_run.call_args_list:
            args = c[0][0]
            if "up" in args:
                up_call = args
                break
        assert up_call is not None
        # Count occurrences of --profile
        profile_count = up_call.count("--profile")
        assert profile_count == 1, f"Expected 1 --profile but got {profile_count}: {up_call}"


# ---------------------------------------------------------------------------
# clean command Tests
# ---------------------------------------------------------------------------


class TestCleanCommand:
    """Test clean command constructs correct docker compose args."""

    def test_clean_calls_down_with_volumes_and_rmi(self, mock_run):
        dev.cmd_clean(SimpleNamespace(command="clean"))
        call_args = mock_run.call_args_list[0][0][0]
        assert "--profile" in call_args
        assert "vuln-services" in call_args
        assert "down" in call_args
        assert "-v" in call_args
        assert "--rmi" in call_args
        assert "local" in call_args

    def test_clean_does_not_raise_on_failure(self, mock_run):
        """Clean should not raise even if docker compose fails."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        # Should not raise
        result = dev.cmd_clean(SimpleNamespace(command="clean"))
        assert result == 0

    def test_clean_removes_logs_directory(self, mock_run):
        """Clean should call shutil.rmtree on logs directory if it exists."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(dev, "PROJECT_ROOT", MagicMock()):
            dev.PROJECT_ROOT.__truediv__ = MagicMock()
            logs_path = MagicMock(spec=Path)
            logs_path.exists.return_value = True

            # Chain: PROJECT_ROOT / "docker" / "logs"
            docker_path = MagicMock(spec=Path)
            dev.PROJECT_ROOT.__truediv__.return_value = docker_path
            docker_path.__truediv__ = MagicMock(return_value=logs_path)

            with patch("services.shutil.rmtree") as mock_rmtree:
                dev.cmd_clean(SimpleNamespace(command="clean"))

            mock_rmtree.assert_called_once_with(logs_path, ignore_errors=True)
            logs_path.mkdir.assert_called_once_with(exist_ok=True)


# ---------------------------------------------------------------------------
# down command Tests
# ---------------------------------------------------------------------------


class TestDownCommand:
    def test_down_uses_all_compose_files(self, mock_run, capsys):
        dev.cmd_down(SimpleNamespace(command="down"))
        call_args = mock_run.call_args_list[0][0][0]
        assert dev.COMPOSE_CORE in call_args
        assert dev.COMPOSE_CVE in call_args
        assert "--profile" in call_args
        assert "vuln-services" in call_args
        assert "down" in call_args
        captured = capsys.readouterr()
        assert "Services stopped" in captured.out


# ---------------------------------------------------------------------------
# restart command Tests
# ---------------------------------------------------------------------------


class TestRestartCommand:
    def test_restart_calls_compose_restart(self, mock_run):
        with patch.object(dev, "wait_healthy", return_value=True):
            result = dev.cmd_restart(SimpleNamespace(command="restart"))
        assert result == 0
        first_call = mock_run.call_args_list[0][0][0]
        assert "restart" in first_call


# ---------------------------------------------------------------------------
# up-cve command Tests
# ---------------------------------------------------------------------------


class TestUpCveCommand:
    def test_up_cve_uses_profile(self, mock_run, capsys):
        dev.cmd_up_cve(SimpleNamespace(proto="smtp"))
        call_args = mock_run.call_args_list[0][0][0]
        assert "--profile" in call_args
        assert "vuln-smtp" in call_args
        captured = capsys.readouterr()
        assert "vuln-smtp" in captured.out


# ---------------------------------------------------------------------------
# groups command + data-driven `up <group>` Tests
# ---------------------------------------------------------------------------


class TestGroupsCommand:
    """`groups` lists oida.group values; `up <group>` spans core + CVE members."""

    def test_all_groups_helper_ignores_unlabeled(self):
        config = {
            "services": {
                "a": {"labels": {"oida.group": "x"}},
                "b": {"labels": {"oida.group": "y"}},
                "c": {"labels": {}},  # no oida.group -> ignored
            }
        }
        assert dev._all_groups(config) == {"x", "y"}

    def test_groups_lists_distinct_groups(self, capsys):
        core = {
            "services": {
                "modbus-mock": {"labels": {"oida.group": "modbus"}},
                "hart-mock": {"labels": {"oida.group": "hart"}},
            }
        }
        full = {
            "services": {
                "modbus-mock": {"labels": {"oida.group": "modbus"}},
                "modbus-cve-x": {"labels": {"oida.group": "modbus"}},
                "hart-mock": {"labels": {"oida.group": "hart"}},
                "dns-cve-x": {"labels": {"oida.group": "dns"}},  # CVE-only group
            }
        }
        # cmd_groups reads core then full
        with patch.object(dev, "_get_compose_config", side_effect=[core, full]):
            rc = dev.cmd_groups(SimpleNamespace())
        assert rc == 0
        out = capsys.readouterr().out
        assert "modbus" in out and "hart" in out
        assert "dns" in out  # CVE-only group is surfaced
        assert "core + 1 cve" in out  # modbus shows the union split

    def test_groups_empty_returns_1(self, capsys):
        with patch.object(dev, "_get_compose_config", side_effect=[{}, {}]):
            rc = dev.cmd_groups(SimpleNamespace())
        assert rc == 1

    def test_up_group_spans_both_compose_files(self, mock_run):
        """_up_proto_impl must read config with BOTH -f files + vuln-services profile."""
        seen = {}

        def fake_config(compose_args):
            seen["args"] = compose_args
            return {
                "services": {
                    "modbus-mock": {
                        "labels": {
                            "oida.group": "modbus",
                            "oida.ports": "502",
                            "oida.description": "core",
                        },
                        "profiles": [],
                    },
                    "modbus-cve-x": {
                        "labels": {
                            "oida.group": "modbus",
                            "oida.ports": "5022",
                            "oida.description": "cve",
                        },
                        "profiles": ["vuln-services", "vuln-modbus"],
                    },
                }
            }

        with patch.object(dev, "_get_compose_config", side_effect=fake_config):
            with patch.object(dev, "_wait_service_healthy", return_value=True):
                rc = dev._up_proto_impl("modbus")
        assert rc == 0
        # config read spans both compose files with the CVE umbrella profile
        assert dev.COMPOSE_CORE in seen["args"]
        assert dev.COMPOSE_CVE in seen["args"]
        assert "--profile" in seen["args"] and "vuln-services" in seen["args"]
        # the CVE member's vuln-modbus profile was auto-collected for `up`
        up_call = next(c[0][0] for c in mock_run.call_args_list if "up" in c[0][0])
        assert "vuln-modbus" in up_call
        assert "modbus-mock" in up_call and "modbus-cve-x" in up_call


# ---------------------------------------------------------------------------
# Color Output Tests
# ---------------------------------------------------------------------------


class TestColorOutput:
    """Test ANSI color constants and formatted output."""

    @pytest.mark.smoke
    def test_color_constants_defined(self):
        # These might be empty strings if NO_COLOR is set in the test environment
        # Just verify they exist
        assert hasattr(dev, "BOLD")
        assert hasattr(dev, "DIM")
        assert hasattr(dev, "CYAN")
        assert hasattr(dev, "BLUE")
        assert hasattr(dev, "GREEN")
        assert hasattr(dev, "RED")
        assert hasattr(dev, "YELLOW")
        assert hasattr(dev, "RST")

    def test_no_color_env_disables_colors(self):
        """#8: NO_COLOR env var should disable all color codes."""
        import importlib

        old_env = os.environ.get("NO_COLOR")
        try:
            os.environ["NO_COLOR"] = "1"
            # Reload the module to re-evaluate the color constants
            importlib.reload(dev)
            assert dev.BOLD == ""
            assert dev.DIM == ""
            assert dev.RED == ""
            assert dev.GREEN == ""
            assert dev.YELLOW == ""
            assert dev.CYAN == ""
            assert dev.BLUE == ""
            assert dev.MAGENTA == ""
            assert dev.RST == ""
        finally:
            if old_env is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = old_env
            # Reload to restore original state
            importlib.reload(dev)


# ---------------------------------------------------------------------------
# main() / Dispatch Tests
# ---------------------------------------------------------------------------


class TestMain:
    """Test main() entry point and dispatch."""

    def test_no_args_returns_0(self, capsys):
        result = dev.main([])
        assert result == 0

    def test_unknown_command_returns_1(self, capsys):
        """Argparse should error on unknown subcommand."""
        with pytest.raises(SystemExit):
            dev.main(["nonexistent-command"])

    def test_dispatches_to_handler(self, mock_run):
        with patch.object(dev, "wait_healthy", return_value=True):
            with patch.object(dev, "_check_docker", return_value=True):
                with patch.object(dev, "_check_compose_file", return_value=True):
                    result = dev.main(["up", "core"])
        assert result == 0
        mock_run.assert_called()

    def test_status_dispatch(self, mock_run, capsys):
        with patch.object(dev, "_check_docker", return_value=True):
            with patch.object(dev, "_check_compose_file", return_value=True):
                result = dev.main(["status"])
        assert result == 0

    def test_build_dispatch(self, mock_run):
        with patch.object(dev, "_check_docker", return_value=True):
            with patch.object(dev, "_check_compose_file", return_value=True):
                result = dev.main(["build"])
        assert result == 0
        call_args = mock_run.call_args_list[0][0][0]
        assert "build" in call_args

    def test_handler_nonzero_return_propagates(self, mock_run):
        """#3 (test gap): Non-zero return from handler propagates through main()."""
        with patch.object(dev, "wait_healthy", return_value=False):
            with patch.object(dev, "_check_docker", return_value=True):
                with patch.object(dev, "_check_compose_file", return_value=True):
                    result = dev.main(["up", "core"])
        assert result == 1

    def test_docker_not_available(self, capsys):
        """#9: If Docker is not available, main() returns 1."""
        with patch.object(dev, "_check_docker", return_value=False):
            result = dev.main(["status"])
        assert result == 1

    def test_compose_file_missing(self, capsys):
        """#10: If compose file is missing, main() returns 1."""
        with patch.object(dev, "_check_docker", return_value=True):
            with patch.object(dev, "_check_compose_file", return_value=False):
                result = dev.main(["status"])
        assert result == 1


# ---------------------------------------------------------------------------
# Docker pre-flight check Tests
# ---------------------------------------------------------------------------


class TestCheckDocker:
    """Test _check_docker pre-flight function."""

    def test_docker_available(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result = dev._check_docker()
        assert result is True

    def test_docker_not_running(self, capsys):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
            result = dev._check_docker()
        assert result is False
        captured = capsys.readouterr()
        assert "Docker is not available" in captured.out

    def test_docker_not_installed(self, capsys):
        with patch("subprocess.run", side_effect=FileNotFoundError("docker")):
            result = dev._check_docker()
        assert result is False
        captured = capsys.readouterr()
        assert "Docker is not installed" in captured.out


# ---------------------------------------------------------------------------
# _check_compose_file Tests
# ---------------------------------------------------------------------------


class TestCheckComposeFile:
    """Test _check_compose_file."""

    def test_compose_file_exists(self):
        with patch("services.Path.exists", return_value=True):
            result = dev._check_compose_file()
        assert result is True

    def test_compose_file_missing(self, capsys):
        with patch("services.Path.exists", return_value=False):
            result = dev._check_compose_file()
        assert result is False
        captured = capsys.readouterr()
        assert "Compose file not found" in captured.out


# ---------------------------------------------------------------------------
# cmd_build Tests
# ---------------------------------------------------------------------------


class TestBuildCommand:
    """Test cmd_build including unknown stack."""

    def test_build_core_uses_core_file(self, mock_run):
        dev.cmd_build(SimpleNamespace(stack="core"))
        call_args = mock_run.call_args_list[0][0][0]
        assert dev.COMPOSE_CORE in call_args
        assert dev.COMPOSE_CVE not in call_args

    def test_build_cve_uses_both_files(self, mock_run):
        dev.cmd_build(SimpleNamespace(stack="cve"))
        call_args = mock_run.call_args_list[0][0][0]
        assert dev.COMPOSE_CORE in call_args
        assert dev.COMPOSE_CVE in call_args

    def test_build_unknown_stack_returns_error(self, mock_run, capsys):
        """#15: Unknown stack should print error and return 1."""
        result = dev.cmd_build(SimpleNamespace(stack="foobar"))
        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown stack" in captured.out
        assert "foobar" in captured.out
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# _get_compose_config Tests
# ---------------------------------------------------------------------------


class TestGetComposeConfig:
    """Test _get_compose_config including JSON parse errors."""

    def test_returns_dict(self):
        config_json = json.dumps({"services": {"test": {}}})

        def run_side_effect(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=config_json, stderr=""
            )

        with patch("subprocess.run", side_effect=run_side_effect):
            config = dev._get_compose_config(["-f", "compose.yml"])
        assert config == {"services": {"test": {}}}

    def test_returns_empty_on_failure(self):
        def run_side_effect(cmd, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="error")

        with patch("subprocess.run", side_effect=run_side_effect):
            config = dev._get_compose_config(["-f", "compose.yml"])
        assert config == {}

    def test_returns_empty_on_json_parse_error(self):
        """#5 (test gap): Invalid JSON should return empty dict, not raise."""

        def run_side_effect(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="not valid json {{{", stderr=""
            )

        with patch("subprocess.run", side_effect=run_side_effect):
            config = dev._get_compose_config(["-f", "compose.yml"])
        assert config == {}


# ---------------------------------------------------------------------------
# Constants / Configuration Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestConstants:
    """Test that project constants are correct."""

    def test_compose_dir_exists(self):
        assert dev.COMPOSE_DIR.exists()

    def test_compose_core_path(self):
        assert dev.COMPOSE_CORE.endswith("docker/mocks/compose.yml")

    def test_compose_cve_path(self):
        assert dev.COMPOSE_CVE.endswith("docker/mocks/compose.cve.yml")

    def test_project_root(self):
        assert (dev.PROJECT_ROOT / "services.py").exists()

    def test_mock_host_default(self):
        # Unless MOCK_HOST is set in env, should default to 127.0.0.1
        assert dev.MOCK_HOST in ("127.0.0.1", os.environ.get("MOCK_HOST", "127.0.0.1"))

    def test_timeouts_are_positive(self):
        assert dev.WAIT_HEALTHY_TIMEOUT > 0
        assert dev.WAIT_HEALTHY_INTERVAL > 0
        assert dev.PORT_CHECK_TIMEOUT > 0
        assert dev.STARTUP_DELAY > 0


# ---------------------------------------------------------------------------
# Helper function Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestHelpers:
    """Test internal helper functions."""

    def test_compose_cmd_builds_list(self):
        result = dev._compose_cmd("-f", "file.yml", "up", "-d")
        assert result == ["docker", "compose", "-f", "file.yml", "up", "-d"]

    def test_core_args(self):
        args = dev._core_args()
        assert args == ["-f", dev.COMPOSE_CORE]

    def test_all_args(self):
        args = dev._all_args()
        assert args == ["-f", dev.COMPOSE_CORE, "-f", dev.COMPOSE_CVE]


# ---------------------------------------------------------------------------
# Edge case / Error handling Tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Test error scenarios and edge cases."""

    def test_logs_with_service_appends_to_cmd(self, mock_run):
        dev.cmd_logs(SimpleNamespace(service=["modbus-mock"]))
        call_args = mock_run.call_args_list[0][0][0]
        assert "modbus-mock" in call_args

    def test_logs_without_service(self, mock_run):
        dev.cmd_logs(SimpleNamespace(service=[]))
        call_args = mock_run.call_args_list[0][0][0]
        assert "logs" in call_args
        # Should not have any service names at the end
        assert call_args[-1] == "--tail=100"

    def test_status_handles_no_containers(self, mock_run, capsys):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        result = dev.cmd_status(SimpleNamespace(command="status"))
        assert result == 0
        captured = capsys.readouterr()
        assert "No containers found" in captured.out


# ---------------------------------------------------------------------------
# COMMAND_DISPATCH type annotation test
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestCommandDispatch:
    """Test COMMAND_DISPATCH type annotation and completeness."""

    def test_dispatch_values_are_callable(self):
        """#11: All dispatch values should be callable."""
        for name, handler in dev.COMMAND_DISPATCH.items():
            assert callable(handler), f"Handler for '{name}' is not callable"

    def test_dispatch_matches_parser_subcommands(self):
        """Dispatch keys must exactly match the parser's registered subcommands."""
        parser = dev.build_parser()
        subparsers_action = next(
            a for a in parser._subparsers._actions if hasattr(a, "_parser_class")
        )
        registered = set(subparsers_action.choices.keys())
        assert registered == set(dev.COMMAND_DISPATCH.keys())

    def test_groups_command_dispatched(self):
        assert dev.COMMAND_DISPATCH.get("groups") is dev.cmd_groups
