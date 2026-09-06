"""
Tests for DHCP discovery scanners.

Tests:
- compute_network_cidr() helper function
- Network mismatch warning in DHCPServerScanner
- Network mismatch warning in DHCPPassiveListener
"""

import pytest
from unittest.mock import patch, MagicMock


class TestComputeNetworkCidr:
    """Test compute_network_cidr helper function."""

    def test_valid_inputs(self):
        """Test with valid IP and netmask."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr("10.0.0.50", "255.255.255.0") == "10.0.0.0/24"
        assert compute_network_cidr("192.168.1.100", "255.255.255.0") == "192.168.1.0/24"
        assert compute_network_cidr("172.16.0.1", "255.255.0.0") == "172.16.0.0/16"
        assert compute_network_cidr("10.10.10.10", "255.0.0.0") == "10.0.0.0/8"

    def test_edge_case_host_mask(self):
        """Test with /32 host mask."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr("192.168.1.1", "255.255.255.255") == "192.168.1.1/32"

    def test_empty_ip(self):
        """Test with empty IP address."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr("", "255.255.255.0") is None

    def test_empty_netmask(self):
        """Test with empty netmask."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr("10.0.0.1", "") is None

    def test_none_inputs(self):
        """Test with None inputs."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr(None, "255.255.255.0") is None
        assert compute_network_cidr("10.0.0.1", None) is None
        assert compute_network_cidr(None, None) is None

    def test_invalid_ip(self):
        """Test with invalid IP address."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr("not.an.ip.address", "255.255.255.0") is None
        assert compute_network_cidr("256.256.256.256", "255.255.255.0") is None

    def test_invalid_netmask(self):
        """Test with invalid netmask."""
        from oida.protocols.discovery.core import compute_network_cidr

        assert compute_network_cidr("10.0.0.1", "not.a.mask") is None
        assert compute_network_cidr("10.0.0.1", "256.256.256.0") is None


class TestDHCPServerScannerNetworkMismatch:
    """Test DHCPServerScanner network mismatch detection."""

    @pytest.fixture
    def scanner_class(self):
        """Get DHCPServerScanner class."""
        from oida.protocols.discovery import DHCPServerScanner

        return DHCPServerScanner

    def test_mismatch_warning_fires(self, scanner_class):
        """Test that warning fires when networks don't match."""
        mock_logger = MagicMock()
        scanner = scanner_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            scanner._check_network_mismatch(
                offered_ip="10.0.0.50",
                subnet_mask="255.255.255.0",
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0][0]
            assert "10.0.0.0/24" in call_args
            assert "192.168.1.0/24" in call_args

    def test_no_warning_when_networks_match(self, scanner_class):
        """Test that no warning fires when networks match."""
        mock_logger = MagicMock()
        scanner = scanner_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            scanner._check_network_mismatch(
                offered_ip="192.168.1.50",
                subnet_mask="255.255.255.0",
                server_ip="192.168.1.1",
            )

            mock_logger.warning.assert_not_called()

    def test_multi_homed_matches_any(self, scanner_class):
        """Test that multi-homed interface matches any network."""
        mock_logger = MagicMock()
        scanner = scanner_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            # Multi-homed: two networks on same interface
            mock_networks.return_value = [
                ("192.168.1.5", "192.168.1.0/24"),
                ("10.0.0.5", "10.0.0.0/24"),
            ]

            # Should match second network
            scanner._check_network_mismatch(
                offered_ip="10.0.0.50",
                subnet_mask="255.255.255.0",
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_not_called()

    def test_no_subnet_mask_skips_check(self, scanner_class):
        """Test that check is skipped when no subnet mask."""
        mock_logger = MagicMock()
        scanner = scanner_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            scanner._check_network_mismatch(
                offered_ip="10.0.0.50",
                subnet_mask="",  # Empty subnet mask
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_not_called()

    def test_no_local_networks_skips_check(self, scanner_class):
        """Test that check is skipped when no local networks."""
        mock_logger = MagicMock()
        scanner = scanner_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = []  # No local networks

            scanner._check_network_mismatch(
                offered_ip="10.0.0.50",
                subnet_mask="255.255.255.0",
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_not_called()

    def test_warning_uses_standard_logger_when_no_nxc(self, scanner_class):
        """Test that standard logger is used when nxc_logger is None."""
        scanner = scanner_class("eth0", nxc_logger=None)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            with patch("oida.protocols.discovery.dhcp.logger") as mock_std_logger:
                scanner._check_network_mismatch(
                    offered_ip="10.0.0.50",
                    subnet_mask="255.255.255.0",
                    server_ip="10.0.0.1",
                )

                mock_std_logger.warning.assert_called_once()


class TestDHCPPassiveListenerNetworkMismatch:
    """Test DHCPPassiveListener network mismatch detection."""

    @pytest.fixture
    def listener_class(self):
        """Get DHCPPassiveListener class."""
        from oida.protocols.discovery import DHCPPassiveListener

        return DHCPPassiveListener

    def test_mismatch_warning_fires(self, listener_class):
        """Test that warning fires when networks don't match."""
        mock_logger = MagicMock()
        listener = listener_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            listener._check_network_mismatch(
                offered_ip="10.0.0.50",
                subnet_mask="255.255.255.0",
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0][0]
            assert "10.0.0.0/24" in call_args
            assert "192.168.1.0/24" in call_args

    def test_no_warning_when_networks_match(self, listener_class):
        """Test that no warning fires when networks match."""
        mock_logger = MagicMock()
        listener = listener_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            listener._check_network_mismatch(
                offered_ip="192.168.1.50",
                subnet_mask="255.255.255.0",
                server_ip="192.168.1.1",
            )

            mock_logger.warning.assert_not_called()

    def test_multi_homed_matches_any(self, listener_class):
        """Test that multi-homed interface matches any network."""
        mock_logger = MagicMock()
        listener = listener_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            # Multi-homed: two networks on same interface
            mock_networks.return_value = [
                ("192.168.1.5", "192.168.1.0/24"),
                ("10.0.0.5", "10.0.0.0/24"),
            ]

            # Should match second network
            listener._check_network_mismatch(
                offered_ip="10.0.0.50",
                subnet_mask="255.255.255.0",
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_not_called()

    def test_invalid_ip_skips_gracefully(self, listener_class):
        """Test that invalid IP is handled gracefully."""
        mock_logger = MagicMock()
        listener = listener_class("eth0", nxc_logger=mock_logger)

        with patch("oida.protocols.discovery.dhcp.get_interface_networks") as mock_networks:
            mock_networks.return_value = [("192.168.1.5", "192.168.1.0/24")]

            # compute_network_cidr returns None for invalid IP
            listener._check_network_mismatch(
                offered_ip="not.valid.ip",
                subnet_mask="255.255.255.0",
                server_ip="10.0.0.1",
            )

            mock_logger.warning.assert_not_called()


class TestDHCPServerScannerInit:
    """Test DHCPServerScanner initialization."""

    def test_default_parameters(self):
        """Test scanner with default parameters."""
        from oida.protocols.discovery import DHCPServerScanner

        scanner = DHCPServerScanner("eth0")

        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.servers == {}
        assert scanner.nxc_logger is None

    def test_custom_timeout(self):
        """Test scanner with custom timeout."""
        from oida.protocols.discovery import DHCPServerScanner

        scanner = DHCPServerScanner("eth0", timeout=10.0)

        assert scanner.timeout == 10.0

    def test_with_nxc_logger(self):
        """Test scanner with NXC logger."""
        from oida.protocols.discovery import DHCPServerScanner

        mock_logger = MagicMock()
        scanner = DHCPServerScanner("eth0", nxc_logger=mock_logger)

        assert scanner.nxc_logger is mock_logger


class TestDHCPPassiveListenerInit:
    """Test DHCPPassiveListener initialization."""

    def test_default_parameters(self):
        """Test listener with default parameters."""
        from oida.protocols.discovery import DHCPPassiveListener

        listener = DHCPPassiveListener("eth0")

        assert listener.interface == "eth0"
        assert listener.timeout == 30
        assert listener.discovered_devices == {}
        assert listener.dhcp_servers == set()
        assert listener.nxc_logger is None

    def test_with_nxc_logger(self):
        """Test listener with NXC logger."""
        from oida.protocols.discovery import DHCPPassiveListener

        mock_logger = MagicMock()
        listener = DHCPPassiveListener("eth0", nxc_logger=mock_logger)

        assert listener.nxc_logger is mock_logger
