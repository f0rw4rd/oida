"""Tests for the tshark error helpers in PcapScanner.

Regression for the v1.0.0 release CI failure (run 36301342031): tshark 4.2
words the unknown-protocol diagnostic differently than 4.4, so
``_filter_supported_by_tshark`` kept an uncompilable filter and every pipeline
attempt was retried as a "crash" with empty results.
"""

import shutil

import pytest

from oida.protocols.pcap.scanner import PcapScanner, _extract_tshark_error

from tests.unit.pcap.conftest import FIXTURES_ROOT


class TestExtractTsharkError:
    """The caret pointer line must never be the reported error."""

    def test_skips_caret_pointer_line(self):
        # tshark prints the caret ("^~~~~") under the message; pyshark keeps
        # the stderr tail, so the caret is often the last line.
        exc = Exception(
            'tshark: "wsdiscovery" is neither a field nor a protocol name.\n'
            "                    ^~~~~~~~~~~"
        )
        assert "wsdiscovery" in _extract_tshark_error(exc)
        assert "^" not in _extract_tshark_error(exc)

    def test_prefers_last_error_line_marker(self):
        exc = Exception("Last error line: tshark: Something Else")
        assert _extract_tshark_error(exc) == "tshark: Something Else"

    def test_prefers_tshark_diagnostic_over_wrapper_text(self):
        exc = Exception("tshark crashed (retcode 2)\nstderr:\ntshark: bad display filter\n  ^~~~")
        assert _extract_tshark_error(exc) == "tshark: bad display filter"

    def test_empty_message(self):
        assert _extract_tshark_error(Exception("")) == "Unknown error"


class TestFilterSupportedByTshark:
    """Validation must handle every tshark release's unknown-protocol wording."""

    @pytest.fixture
    def pcap(self):
        return str(FIXTURES_ROOT / "dns" / "zeek_long-connection.pcap")

    @pytest.fixture(autouse=True)
    def _require_tshark(self):
        if not shutil.which("tshark"):
            pytest.skip("tshark not on PATH")

    def test_compilable_filter_kept(self, pcap):
        scanner = PcapScanner(pcap)
        assert scanner._filter_supported_by_tshark("tcp or udp") == "tcp or udp"

    def test_unknown_protocol_dropped_current_wording(self, pcap, monkeypatch):
        # 4.4+ wording (what stock Ubuntu 25.x / this repo's devcontainer ship).
        scanner = PcapScanner(pcap)
        result = scanner._filter_supported_by_tshark("nosuchproto_xyz123 or tcp")
        assert result is None

    def test_unknown_protocol_dropped_42_wording(self, pcap, monkeypatch):
        # 4.2 wording: mock a subprocess result carrying the old diagnostic,
        # which the validator must also recognise (this is what made the
        # release CI's dissector job fail 4/4 while local runs passed).

        class FakeCompleted:
            returncode = 2
            stderr = '"wsdiscovery" is neither a field nor a protocol name.'
            stdout = ""

        def fake_run(*args, **kwargs):
            return FakeCompleted()

        monkeypatch.setattr("oida.protocols.pcap.scanner.subprocess.run", fake_run)
        scanner = PcapScanner(pcap)
        assert scanner._filter_supported_by_tshark("wsdiscovery or tcp") is None
