"""
Tests for the NXC-style ``pcap`` class (scanner.py).

The NXC ``pcap`` class inherits from SerialConnection and triggers
proto_flow() on construction. We mock out the heavy init machinery
and test the class methods in isolation.
"""

import argparse
from unittest.mock import patch


from oida.protocols.pcap.scanner import pcap as PcapNXC


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**overrides):
    """Build a minimal argparse Namespace that PcapNXC expects."""
    defaults = {
        "port": None,
        "verbose": 0,
        "debug": False,
        "extract_all": False,
        "extract_files": False,
        "extract_dir": None,
        "extract_protocols": "http,smb,ftp-data,tftp,dicom,imf",
        "target": "/tmp/test.pcap",
        "interface": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _build_nxc(host="/tmp/test.pcap", **arg_overrides):
    """Construct a PcapNXC instance with proto_flow mocked out."""
    args = _make_args(**arg_overrides)
    with patch.object(PcapNXC, "proto_flow"):
        obj = PcapNXC(args, None, host)
    return obj


# ---------------------------------------------------------------------------
# _convert_args_to_dict
# ---------------------------------------------------------------------------


class TestConvertArgsToDict:
    """Verify pcap-specific keys are forwarded."""

    PCAP_KEYS = [
        "extract_files",
        "extract_dir",
        "extract_protocols",
    ]

    def test_all_pcap_keys_present_when_set(self):
        nxc = _build_nxc(
            extract_files=True,
            extract_dir="/tmp/out",
            extract_protocols="http",
        )
        result = nxc._convert_args_to_dict()
        for key in self.PCAP_KEYS:
            assert key in result, f"Missing key: {key}"

    def test_extract_files_true_propagated(self):
        nxc = _build_nxc(extract_files=True)
        result = nxc._convert_args_to_dict()
        assert result["extract_files"] is True

    def test_extract_all_propagated(self):
        nxc = _build_nxc(extract_all=True)
        result = nxc._convert_args_to_dict()
        assert result["extract_all"] is True

    def test_none_values_excluded(self):
        """Keys whose value is None should not appear (parent logic)."""
        nxc = _build_nxc(extract_dir=None)
        result = nxc._convert_args_to_dict()
        assert "extract_dir" not in result

    def test_extract_protocols_default_value(self):
        nxc = _build_nxc()
        result = nxc._convert_args_to_dict()
        assert result["extract_protocols"] == "http,smb,ftp-data,tftp,dicom,imf"


# ---------------------------------------------------------------------------
# create_conn_obj
# ---------------------------------------------------------------------------


class TestCreateConnObj:
    """create_conn_obj always returns True (offline analysis)."""

    def test_returns_true(self):
        nxc = _build_nxc()
        assert nxc.create_conn_obj() is True


# ---------------------------------------------------------------------------
# get_results
# ---------------------------------------------------------------------------


class TestGetResults:
    """Verify result structure before and after scanning."""

    def test_no_scan_returns_failure(self):
        nxc = _build_nxc()
        result = nxc.get_results()
        assert result["success"] is False
        assert result["protocol"] == "pcap"
        assert "host" in result

    def test_with_scan_results(self):
        nxc = _build_nxc()
        nxc._scan_results = {"pcap_file": "test.pcap", "devices": []}
        result = nxc.get_results()
        assert result["success"] is True
        assert result["data"]["pcap_file"] == "test.pcap"
        assert result["protocol"] == "pcap"

    def test_host_in_result(self):
        nxc = _build_nxc(host="/tmp/my.pcap")
        result = nxc.get_results()
        assert result["host"] == "/tmp/my.pcap"


# ---------------------------------------------------------------------------
# enum_host_info
# ---------------------------------------------------------------------------


class TestEnumHostInfo:
    """Verify device_info is populated."""

    def test_sets_device_info(self):
        nxc = _build_nxc(host="/tmp/test.pcap")
        nxc.enum_host_info()
        assert nxc.device_info["pcap_file"] == "/tmp/test.pcap"
        assert nxc.device_info["protocol"] == "pcap"


# ---------------------------------------------------------------------------
# Protocol metadata
# ---------------------------------------------------------------------------


class TestProtocolMetadata:
    """Basic attributes set by __init__."""

    def test_protocol_name(self):
        nxc = _build_nxc()
        assert nxc.protocol_name == "PCAP"

    def test_default_port_is_none(self):
        nxc = _build_nxc()
        assert nxc.default_port is None

    def test_scan_results_initially_none(self):
        nxc = _build_nxc()
        assert nxc._scan_results is None


# ---------------------------------------------------------------------------
# Listener filtering args forwarding
# ---------------------------------------------------------------------------


class TestListenerFilteringArgsForwarding:
    """Verify listener filtering args are forwarded through _convert_args_to_dict."""

    def test_protocols_forwarded(self):
        nxc = _build_nxc(protocols="ics")
        result = nxc._convert_args_to_dict()
        assert result["protocols"] == "ics"

    def test_category_forwarded(self):
        nxc = _build_nxc(category="credential")
        result = nxc._convert_args_to_dict()
        assert result["category"] == "credential"

    def test_exclude_forwarded(self):
        nxc = _build_nxc(exclude="routing,fhrp")
        result = nxc._convert_args_to_dict()
        assert result["exclude"] == "routing,fhrp"

    def test_quick_forwarded(self):
        nxc = _build_nxc(quick=True)
        result = nxc._convert_args_to_dict()
        assert result["quick"] is True

    def test_list_listeners_forwarded(self):
        nxc = _build_nxc(list_listeners=True)
        result = nxc._convert_args_to_dict()
        assert result["list_listeners"] is True

    def test_stats_forwarded(self):
        nxc = _build_nxc(stats=True)
        result = nxc._convert_args_to_dict()
        assert result["stats"] is True

    def test_decode_as_forwarded(self):
        nxc = _build_nxc(decode_as="tcp.port==13600,mqtt")
        result = nxc._convert_args_to_dict()
        assert result["decode_as"] == "tcp.port==13600,mqtt"

    def test_none_filtering_args_excluded(self):
        """None-valued filtering args should not appear in result."""
        nxc = _build_nxc(protocols=None, category=None, exclude=None)
        result = nxc._convert_args_to_dict()
        assert "protocols" not in result
        assert "category" not in result
        assert "exclude" not in result

    def test_false_boolean_args_excluded(self):
        """False/None boolean args should not appear (None is excluded by parent)."""
        nxc = _build_nxc(quick=None, list_listeners=None, stats=None)
        result = nxc._convert_args_to_dict()
        assert "quick" not in result
        assert "list_listeners" not in result
        assert "stats" not in result

    def test_x509_forwarded(self):
        nxc = _build_nxc(x509=True)
        result = nxc._convert_args_to_dict()
        assert result["x509"] is True

    def test_x509_none_excluded(self):
        nxc = _build_nxc(x509=None)
        result = nxc._convert_args_to_dict()
        assert "x509" not in result

    def test_assets_forwarded(self):
        nxc = _build_nxc(assets=True)
        result = nxc._convert_args_to_dict()
        assert result["assets"] is True

    def test_hashcat_forwarded(self):
        nxc = _build_nxc(hashcat=True)
        result = nxc._convert_args_to_dict()
        assert result["hashcat"] is True
