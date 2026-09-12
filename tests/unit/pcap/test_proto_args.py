"""
Tests for pcap CLI argument parser (proto_args.py).
"""

import argparse

import pytest

from oida.protocols.pcap.proto_args import proto_args


def _build_parser():
    """Build an argparse parser with pcap sub-command registered."""
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    sub = main.add_subparsers(dest="protocol")
    pcap_parser = proto_args(sub, [parent])
    return main, pcap_parser


class TestParserRegistration:
    """Verify parser is wired up correctly."""

    def test_parser_name_is_pcap(self):
        _, pcap_parser = _build_parser()
        assert pcap_parser.prog.endswith("pcap")

    def test_target_positional_is_required(self):
        main, _ = _build_parser()
        with pytest.raises(SystemExit):
            main.parse_args(["pcap"])  # missing target

    def test_target_positional_accepted(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "/tmp/test.pcap"])
        assert ns.target == "/tmp/test.pcap"


class TestExtractFlags:
    """Test -E, -e boolean flags."""

    def test_extract_files_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.extract_files is False

    def test_extract_files_short_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "-E"])
        assert ns.extract_files is True

    def test_extract_files_long_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--extract-files"])
        assert ns.extract_files is True

    def test_extract_all_flag(self):
        # -e/--extract-all is an alias of -E/--extract-files (shared dest)
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "-e"])
        assert ns.extract_files is True

    def test_extract_all_long_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--extract-all"])
        assert ns.extract_files is True


class TestOptionalArguments:
    """Test optional string/path arguments."""

    def test_extract_dir_default_none(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.extract_dir is None

    def test_extract_dir_set(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--extract-dir", "/tmp/out"])
        assert ns.extract_dir == "/tmp/out"

    def test_extract_protocols_default(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.extract_protocols == "http,smb,ftp-data,tftp,dicom,imf"

    def test_extract_protocols_custom(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--extract-protocols", "http,ftp-data"])
        assert ns.extract_protocols == "http,ftp-data"


# ---------------------------------------------------------------------------
# Listener filtering flags
# ---------------------------------------------------------------------------


class TestListenerFilteringFlags:
    """Test -p/--protocols, --category, --exclude, --quick, --list-listeners."""

    def test_protocols_no_short_flag(self):
        """Verify -p is NOT a valid short flag: reserved for --port framework-wide."""
        main, _ = _build_parser()
        with pytest.raises(SystemExit):
            main.parse_args(["pcap", "f.pcap", "-p", "ics"])

    def test_protocols_long_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--protocols", "modbus,ftp"])
        assert ns.protocols == "modbus,ftp"

    def test_protocols_default_none(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.protocols is None

    def test_category_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--category", "credential"])
        assert ns.category == "credential"

    def test_category_default_none(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.category is None

    def test_exclude_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--exclude", "routing,fhrp"])
        assert ns.exclude == "routing,fhrp"

    def test_exclude_default_none(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.exclude is None

    def test_quick_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--quick"])
        assert ns.quick is True

    def test_quick_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.quick is False

    def test_list_listeners_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--list-listeners"])
        assert ns.list_listeners is True

    def test_list_listeners_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.list_listeners is False


# ---------------------------------------------------------------------------
# Stats and decode-as flags
# ---------------------------------------------------------------------------


class TestStatsAndDecodeFlags:
    """Test -S/--stats and --decode-as."""

    def test_stats_short_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "-S"])
        assert ns.stats is True

    def test_stats_long_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--stats"])
        assert ns.stats is True

    def test_stats_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.stats is False

    def test_decode_as_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--decode-as", "tcp.port==13600,mqtt"])
        assert ns.decode_as == "tcp.port==13600,mqtt"

    def test_decode_as_default_none(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.decode_as is None


# ---------------------------------------------------------------------------
# x509 flag
# ---------------------------------------------------------------------------


class TestX509Flag:
    """Test -X/--x509 flag."""

    def test_x509_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.x509 is False

    def test_x509_short_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "-X"])
        assert ns.x509 is True

    def test_x509_long_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--x509"])
        assert ns.x509 is True


# ---------------------------------------------------------------------------
# Assets flag
# ---------------------------------------------------------------------------


class TestAssetsFlag:
    """Test -A/--assets flag."""

    def test_assets_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.assets is False

    def test_assets_short_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "-A"])
        assert ns.assets is True

    def test_assets_long_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--assets"])
        assert ns.assets is True


# ---------------------------------------------------------------------------
# Hashcat flag
# ---------------------------------------------------------------------------


class TestHashcatFlag:
    """Test --hashcat flag."""

    def test_hashcat_default_false(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap"])
        assert ns.hashcat is False

    def test_hashcat_flag(self):
        main, _ = _build_parser()
        ns = main.parse_args(["pcap", "f.pcap", "--hashcat"])
        assert ns.hashcat is True
