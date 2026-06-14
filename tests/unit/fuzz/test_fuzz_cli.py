"""
CLI integration tests for OIDA fuzz command.
Tests the complete CLI workflow.
"""

import pytest
from unittest.mock import Mock


class TestFuzzCLIArgumentParsing:
    """Test CLI argument parsing for fuzz commands."""

    def test_fuzz_list_parsing(self):
        """Test parsing of 'oida fuzz list' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "list"])

        assert getattr(args, "fuzz_protocol", None) == "list"

    def test_fuzz_list_category_parsing(self):
        """Test parsing of 'oida fuzz list --category ics' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "list", "--category", "ics"])

        assert getattr(args, "fuzz_protocol", None) == "list"
        assert getattr(args, "category", None) == "ics"

    def test_fuzz_protocol_target_parsing(self):
        """Test parsing of 'oida fuzz modbus 192.168.1.100' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "192.168.1.100"])

        assert getattr(args, "fuzz_protocol", None) == "modbus"
        assert getattr(args, "target", None) == "192.168.1.100"

    def test_fuzz_with_port_parsing(self):
        """Test parsing of 'oida fuzz modbus 192.168.1.100 --port 502' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "192.168.1.100", "--port", "502"])

        assert getattr(args, "fuzz_protocol", None) == "modbus"
        assert getattr(args, "target", None) == "192.168.1.100"
        assert getattr(args, "port", None) == 502

    def test_fuzz_show_options_parsing(self):
        """Test parsing of 'oida fuzz modbus --show-options' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "--show-options"])

        assert getattr(args, "fuzz_protocol", None) == "modbus"
        assert getattr(args, "show_options", False) is True

    def test_fuzz_list_requests_parsing(self):
        """Test parsing of 'oida fuzz modbus --list-requests' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "--list-requests"])

        assert getattr(args, "fuzz_protocol", None) == "modbus"
        assert getattr(args, "list_requests", False) is True

    def test_fuzz_replay_parsing(self):
        """Test parsing of 'oida fuzz replay mysession' command."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "replay", "mysession"])

        assert getattr(args, "fuzz_protocol", None) == "replay"
        assert getattr(args, "target", None) == "mysession"

    def test_fuzz_with_session_parsing(self):
        """Test parsing with session name."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "192.168.1.100", "--session", "my_test"])

        assert getattr(args, "session", None) == "my_test"

    def test_fuzz_with_seed_parsing(self):
        """Test parsing with seed."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(["fuzz", "modbus", "192.168.1.100", "--seed", "12345"])

        assert getattr(args, "seed", None) == 12345

    def test_fuzz_with_options_parsing(self):
        """Test parsing with protocol options."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args()
        args = parser.parse_args(
            ["fuzz", "modbus", "192.168.1.100", "--option", "unit_id=5", "--option", "timeout=2.0"]
        )

        assert getattr(args, "protocol_options", None) == ["unit_id=5", "timeout=2.0"]


class TestFuzzCommandHandler:
    """Test fuzz command handler functions."""

    def test_handle_list_command(self):
        """Test handle_list_command returns 0 on success."""
        from oida.fuzz_cli import handle_list_command

        args = Mock()
        args.category = None
        args.with_options = False

        result = handle_list_command(args)
        assert result == 0

    def test_handle_list_command_with_category(self):
        """Test handle_list_command with category filter."""
        from oida.fuzz_cli import handle_list_command

        args = Mock()
        args.category = "ics"
        args.with_options = False

        result = handle_list_command(args)
        assert result == 0

    def test_handle_list_command_unknown_category(self):
        """Test handle_list_command with unknown category."""
        from oida.fuzz_cli import handle_list_command

        args = Mock()
        args.category = "nonexistent"
        args.with_options = False

        result = handle_list_command(args)
        assert result == 1

    def test_show_protocol_options(self):
        """Test show_protocol_options for known protocol."""
        from oida.fuzz_cli import show_protocol_options

        result = show_protocol_options("modbus")
        assert result == 0

    def test_show_protocol_options_unknown(self):
        """Test show_protocol_options for unknown protocol."""
        from oida.fuzz_cli import show_protocol_options

        result = show_protocol_options("nonexistent_protocol")
        assert result == 1

    def test_show_protocol_requests(self):
        """Test show_protocol_requests for known protocol."""
        from oida.fuzz_cli import show_protocol_requests

        result = show_protocol_requests("modbus")
        assert result == 0

    def test_show_protocol_requests_unknown(self):
        """Test show_protocol_requests for unknown protocol."""
        from oida.fuzz_cli import show_protocol_requests

        result = show_protocol_requests("nonexistent_protocol")
        assert result == 1


class TestFuzzHandleCommand:
    """Test the main handle_fuzz_command function."""

    def test_handle_fuzz_command_list(self):
        """Test handle_fuzz_command routes to list."""
        from oida.fuzz_cli import handle_fuzz_command

        args = Mock()
        args.fuzz_protocol = "list"
        args.category = None
        args.with_options = False

        result = handle_fuzz_command(args)
        assert result == 0

    def test_handle_fuzz_command_show_options(self):
        """Test handle_fuzz_command routes to show_options."""
        from oida.fuzz_cli import handle_fuzz_command

        args = Mock()
        args.fuzz_protocol = "modbus"
        args.target = None
        args.show_options = True
        args.list_requests = False

        result = handle_fuzz_command(args)
        assert result == 0

    def test_handle_fuzz_command_no_protocol(self):
        """Test handle_fuzz_command with no protocol."""
        from oida.fuzz_cli import handle_fuzz_command

        args = Mock()
        args.fuzz_protocol = None
        args.target = None
        args.show_options = False
        args.list_requests = False

        result = handle_fuzz_command(args)
        assert result == 1

    def test_handle_fuzz_command_no_target(self):
        """Test handle_fuzz_command with protocol but no target."""
        from oida.fuzz_cli import handle_fuzz_command

        args = Mock()
        args.fuzz_protocol = "modbus"
        args.target = None
        args.show_options = False
        args.list_requests = False

        result = handle_fuzz_command(args)
        assert result == 1


class TestSplitTargetPort:
    """Test embedded host:port parsing for fuzzer targets."""

    @pytest.mark.parametrize(
        "target,expected",
        [
            ("127.0.0.1:8080", ("127.0.0.1", 8080)),
            ("127.0.0.1", ("127.0.0.1", None)),
            ("example.com:1883", ("example.com", 1883)),
            ("[::1]:8080", ("::1", 8080)),
            ("[::1]", ("::1", None)),
            ("::1", ("::1", None)),
            ("2001:db8::1", ("2001:db8::1", None)),
            ("[2001:db8::1]:502", ("2001:db8::1", 502)),
            # Invalid ports -> treated as host, no port
            ("127.0.0.1:99999", ("127.0.0.1:99999", None)),
            ("127.0.0.1:abc", ("127.0.0.1:abc", None)),
            ("127.0.0.1:0", ("127.0.0.1:0", None)),
            ("", ("", None)),
        ],
    )
    def test_split(self, target, expected):
        from oida.fuzz_cli import _split_target_port

        assert _split_target_port(target) == expected

    def test_explicit_flag_wins_over_embedded(self):
        """-p/--port flag takes precedence over an embedded port."""
        from oida.fuzz_cli import _split_target_port

        host, embedded_port = _split_target_port("127.0.0.1:8080")
        user_port = 9090
        port = user_port or embedded_port or 502
        assert host == "127.0.0.1"
        assert port == 9090

    def test_embedded_wins_over_default(self):
        """Embedded port is used when no --port flag is given."""
        from oida.fuzz_cli import _split_target_port

        host, embedded_port = _split_target_port("127.0.0.1:8080")
        user_port = None
        port = user_port or embedded_port or 502
        assert host == "127.0.0.1"
        assert port == 8080


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
