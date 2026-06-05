"""
Tests for discovery CLI and callable class
"""

import pytest
from unittest.mock import patch, MagicMock
from argparse import Namespace


@pytest.fixture
def discovery_callable():
    """Get discovery callable class"""
    from oida.protocols.discovery import discovery

    return discovery


class TestDiscoveryCallable:
    """Test discovery NXC-style callable class"""

    def test_convert_args_to_dict(self, discovery_callable):
        """Test conversion of args to scanner dict"""
        mock_args = Namespace(
            target="eth0",
            timeout=30,
            no_passive=False,
            active=True,
            arp=False,
            arp_scan=True,
            no_arp=False,
            subnet="192.168.1.0/24",
            arp_timeout=3.0,
            no_lldp=False,
            no_dcp=True,
            no_mdns=False,
            no_ssdp=True,
            ics_only=True,
            resolve_mac=False,
            format="json",
            read_only=True,
            interface=None,
        )

        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.args = mock_args
            instance.interface = "eth0"
            instance.ip = ""  # Required by base class _convert_args_to_dict

            args_dict = instance._convert_args_to_dict()

            assert args_dict["target"] == "eth0"
            assert args_dict["timeout"] == 30
            assert args_dict["active"] is True
            assert args_dict["arp-scan"] is True
            assert args_dict["subnet"] == "192.168.1.0/24"
            assert args_dict["no-lldp"] is False
            assert args_dict["no-dcp"] is True
            # Verify discovery-specific interface fallback
            assert args_dict["interface"] == "eth0"

    def test_create_conn_obj(self, discovery_callable):
        """Test create_conn_obj method"""
        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.scanner = MagicMock()
            instance.scanner.connect.return_value = "eth0"
            instance.logger = MagicMock()
            instance.interface = "eth0"

            result = instance.create_conn_obj()

            assert result is True
            instance.scanner.connect.assert_called_once()

    def test_execute_scan(self, discovery_callable):
        """Test _execute_scan method"""
        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.scanner = MagicMock()
            instance.logger = MagicMock()
            instance._scan_results = None
            instance._connection = "eth0"  # Required by _execute_scan

            mock_results = {"devices": [], "statistics": {}}
            instance.scanner.discover.return_value = mock_results

            instance._execute_scan()

            assert instance._scan_results == mock_results
            instance.scanner.discover.assert_called_once_with("eth0")

    def test_execute_scan_exception(self, discovery_callable):
        """Test _execute_scan handles exceptions"""
        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.scanner = MagicMock()
            instance.logger = MagicMock()
            instance._scan_results = None

            instance.scanner.discover.side_effect = Exception("Scan error")

            instance._execute_scan()

            # Should log error and not crash
            instance.logger.fail.assert_called()

    def test_cleanup_called(self, discovery_callable):
        """Test cleanup method"""
        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.scanner = MagicMock()

            instance.cleanup()

            instance.scanner.disconnect.assert_called_once()

    def test_get_results_success(self, discovery_callable):
        """Test get_results with successful scan"""
        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.interface = "eth0"
            instance._scan_results = {"devices": [{"name": "test"}]}

            results = instance.get_results()

            assert results["success"] is True
            assert results["protocol"] == "discovery"
            assert results["host"] == "eth0"
            assert results["data"] == {"devices": [{"name": "test"}]}

    def test_get_results_failure(self, discovery_callable):
        """Test get_results with no results"""
        with patch.object(discovery_callable, "__init__", return_value=None):
            instance = discovery_callable.__new__(discovery_callable)
            instance.interface = "eth0"
            instance._scan_results = None

            results = instance.get_results()

            assert results["success"] is False
            assert results["protocol"] == "discovery"
            assert results["host"] == "eth0"


class TestDiscoveryCLI:
    """Test discovery CLI integration"""

    def test_help_output(self):
        """Test discovery --help output"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        result = proto_args(subparsers, [std_parser])

        assert result is not None

    def test_passive_mode_default(self):
        """Test that passive mode is default"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(["discovery", "eth0"])

        assert args.no_passive is False  # passive mode enabled by default
        assert args.active is False

    def test_active_flag(self):
        """Test --active flag"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(["discovery", "eth0", "--active"])

        assert args.active is True

    def test_protocol_toggles(self):
        """Test protocol toggle flags"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(
            [
                "discovery",
                "eth0",
                "--no-lldp",
                "--no-dcp",
            ]
        )

        assert args.no_lldp is True
        assert args.no_dcp is True

    def test_timeout_option(self):
        """Test --timeout option"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(["discovery", "eth0", "--timeout", "60"])

        assert args.timeout == 60

    def test_ics_only_option(self):
        """Test --ics-only option"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(["discovery", "eth0", "--ics-only"])

        assert args.ics_only is True

    def test_default_target(self):
        """Test target default is None"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(["discovery"])

        # Target is optional (None) - interface is specified at runtime or from pcap file
        assert args.target is None

    def test_subnet_option(self):
        """Test --subnet option"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(["discovery", "eth0", "--subnet", "10.0.0.0/24"])

        assert args.subnet == "10.0.0.0/24"

    def test_all_protocol_flags(self):
        """Test all protocol flags are available"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        # Test passive protocols can be toggled
        args = parser.parse_args(
            [
                "discovery",
                "eth0",
                "--no-lldp",
                "--no-dcp",
                "--no-mdns",
                "--no-ssdp",
                "--no-cdp",
            ]
        )

        assert args.no_lldp is True
        assert args.no_dcp is True
        assert args.no_mdns is True
        assert args.no_ssdp is True
        assert args.no_cdp is True

    def test_active_protocol_flags(self):
        """Test active protocol flags"""
        from oida.protocols.discovery.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        std_parser = argparse.ArgumentParser(add_help=False)

        proto_args(subparsers, [std_parser])

        args = parser.parse_args(
            [
                "discovery",
                "eth0",
                "--active",
                "--no-dns-sd",
                "--no-ws-discovery",
                "--no-llmnr",
            ]
        )

        assert args.no_dns_sd is True
        assert args.no_ws_discovery is True
        assert args.no_llmnr is True
