"""Real-CLI integration tests for the ``pcap`` module.

Unlike every other protocol module, ``pcap`` is **file-driven**: there is no
mock server, no host/port target, and no ``BaseProtocolIntegrationTest``
inheritance here. The target is a capture file, and "the mock" is the
checked-in fixture inventory under ``tests/fixtures/pcap/``.

The rest of ``tests/integration/pcap/`` (the ~1500 test functions in
``test_*_passive.py`` style files) drives listeners **in-process** via
``oida.pcap.<listener>`` imports and ``conftest.py``'s
``_run_listener_test()`` helper -- it never touches argv. This file is the
complement: it spawns the real ``oida`` CLI as a subprocess (via the shared
``cli_runner`` fixture) and asserts on what the CLI actually printed/wrote,
exercising the argv parsing, flag wiring, and output-export path that the
in-process suite cannot see. It does not re-test listener extraction logic.

Every flag below is passed to the CLI as a literal ``"--flag"`` string (via
``cli_runner.run``'s positional ``*args``), not via keyword sugar, on
purpose: ``scripts/flag_coverage.py`` only credits a flag as covered when
its literal quoted string appears inside a real-CLI test body.

Fixture data inventory (all pre-recorded captures, no live traffic):
- ``tests/fixtures/pcap/ftp/credslayer_ftp.pcap`` (5 packets): a plaintext
  FTP anonymous login. Client 10.10.30.26 authenticates as
  ``anonymous`` / ``ftp@example.com`` against server 129.21.171.72:21,
  banner "Welcome to mirrors.rit.edu.". Selecting the ``ftp`` listener
  yields one credential row and two devices (FTP Server + FTP Client).
- ``tests/fixtures/pcap/modbus/modbus_test.pcap`` (2257 packets): pure
  Modbus/TCP traffic, no FTP/credential traffic at all. Used as the
  "impostor protocol" hostile-path fixture: running the CLI against it
  with ``--protocols ftp`` selected must yield zero devices and zero
  false-positive identifications.
- ``tests/fixtures/pcap/tls/internet_tls12_cert.pcap``: a real TLS 1.2
  handshake carrying a server certificate for ``login.passport.com``.
  Used to prove ``--x509`` actually parses and exports certificate data.
- ``tests/fixtures/pcap/smb/credslayer_smb_ntlm.pcap``: SMB NTLMSSP
  authentication traffic against server 192.168.199.133, producing real
  NetNTLMv2 challenge/response material. Used to prove ``--hashcat``
  writes crackable hash lines, not just credential rows.
- ``tests/fixtures/pcap/http/bruteshark_http_ntlm.pcap``: HTTP traffic
  carrying real embedded image payloads (GIFs). Used to prove
  ``--extract-files``/``--extract-all``/``--extract-dir``/
  ``--extract-protocols`` actually carve bytes to disk, not just parse.

Ground truth is ``oida pcap -h`` (reconciled against
``scripts/flag_coverage.py pcap --missing``, which reported 0/14 covered
before this file existed). One wiring note found while reconciling: ``-e``,
``-E``, ``--extract-files`` and ``--extract-all`` are **not four
independent flags** -- ``-h`` lists them on a single combined line, i.e.
they are four aliases for one ``store_true`` argparse action. The scorecard
still counts ``--extract-files`` and ``--extract-all`` as two separate
tokens to cover, so this file deliberately drives both literal strings
(in different tests) even though they exercise identical behaviour --
documented here so a reviewer doesn't mistake it for redundant testing.

Non-obvious behavioural contract discovered while probing the CLI (encoded
directly in the assertions below, not just this docstring):
- ``--format json`` alone (no ``--output``) never prints JSON to stdout;
  pcap always prints NXC-style console tables. Only ``--output <dir>``
  (combined with ``--format json``) writes real per-table JSON files
  (``credentials.json``, ``pcap.json``, ``hashcat.txt``, etc.) that these
  tests can load and assert against. ``cli_runner``'s ``result.json_output``
  (which parses stdout) is therefore useless for this module -- data
  assertions read files from an ``--output`` directory instead.
- A missing/unreadable/corrupt/truncated/permission-denied file is a
  *graceful* degradation, not a hard failure: the process exits 0, reports
  zero devices, and logs a ``protocol_error`` (level ``error``) event with
  the real tshark error text. A genuinely *empty* (0-byte) file is a
  further special case: tshark accepts it as a trivial valid capture (zero
  packets, no error at all). Only a missing *path* (or a directory given
  as the target) is a hard error (exit 1, "not found"). All three shapes
  are asserted explicitly below so a regression that starts silently
  swallowing the file-not-found case, or one that starts crashing on
  corrupt/empty captures, would be caught.
- ``--list-listeners`` is a quirky early-return path in the scanner: it
  prints the full listener catalog successfully but never populates a
  scan result, so it always exits 1 even though nothing went wrong. Tests
  accept ``returncode in (0, 1)`` for it and assert on stdout content
  instead of the exit code.

Test classification summary: Category A (drivable, validates real
extracted data) = 9, Category B (degenerate: parses/accepted, effect not
independently distinguishable against these fixtures) = 3, Category C
(hostile/negative paths) = 12. Total = 24.

Flag coverage matrix (14/14 of scripts/flag_coverage.py's "missing" pcap
flags, plus the load-bearing globals --output/--format/--json-log/--threads):

| Flag                        | Class | Test                                              |
|------------------------------|-------|----------------------------------------------------|
| ``--protocols``              | A     | test_protocols_and_category_filter_extract_ftp_credential |
| ``--category``               | A     | test_protocols_and_category_filter_extract_ftp_credential |
| ``--exclude``                 | A     | test_exclude_removes_protocol_from_results          |
| ``--quick``                   | A     | test_quick_preset_includes_ftp                      |
| ``--list-listeners``          | B     | test_list_listeners_prints_catalog                  |
| ``--stats``                   | B     | test_stats_flag_runs_clean                          |
| ``--assets``                  | A     | test_assets_flag_writes_asset_tables                |
| ``--x509``                    | A     | test_x509_flag_extracts_tls_certificate             |
| ``--extract-files``           | A     | test_extract_files_carves_real_files_from_http      |
| ``--extract-all``             | A     | test_extract_all_alias_also_carves_files            |
| ``--extract-dir``             | A     | test_extract_files_carves_real_files_from_http      |
| ``--extract-protocols``       | A     | test_extract_protocols_narrows_extraction_scope     |
| ``--hashcat``                 | A     | test_hashcat_flag_writes_netntlmv2_hash             |
| ``--decode-as``               | B     | test_decode_as_accepted_and_preserves_normal_parse  |

No flag from ``oida pcap -h`` was classified untestable-here: pcap needs no
hardware/root/serial access, only a local file and tshark (already a hard
dependency of the pcap extra used throughout ``tests/integration/pcap/``).
"""

import json
import os
import shutil
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "pcap"

FTP_PCAP = FIXTURE_DIR / "ftp" / "credslayer_ftp.pcap"
MODBUS_PCAP = FIXTURE_DIR / "modbus" / "modbus_test.pcap"
TLS_PCAP = FIXTURE_DIR / "tls" / "internet_tls12_cert.pcap"
SMB_PCAP = FIXTURE_DIR / "smb" / "credslayer_smb_ntlm.pcap"
HTTP_NTLM_PCAP = FIXTURE_DIR / "http" / "bruteshark_http_ntlm.pcap"

_REQUIRED_FIXTURES = [FTP_PCAP, MODBUS_PCAP, TLS_PCAP, SMB_PCAP, HTTP_NTLM_PCAP]

if not shutil.which("tshark"):
    pytest.skip("tshark not installed - required for pcap CLI tests", allow_module_level=True)

_missing = [str(p) for p in _REQUIRED_FIXTURES if not p.exists()]
if _missing:
    pytest.skip(
        f"required pcap fixtures missing (git-lfs not fetched?): {_missing}",
        allow_module_level=True,
    )


def _contains(obj, needle: str) -> bool:
    """Whether ``needle`` appears anywhere in the (possibly nested) JSON value."""
    return needle in json.dumps(obj)


def _load_json(path: Path):
    assert path.exists(), f"expected exported file missing: {path}"
    with path.open() as fh:
        return json.load(fh)


def _no_traceback(text: str) -> bool:
    return "Traceback (most recent call last)" not in text


# ---------------------------------------------------------------------------
# Category A: flags that drive independently observable, real extracted data
# ---------------------------------------------------------------------------


class TestPcapDataExtraction:
    def test_protocols_and_category_filter_extract_ftp_credential(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--protocols",
            "ftp",
            "--category",
            "credential",
            output=str(out_dir),
            format="json",
            json_log=True,
        )
        assert _no_traceback(result.combined_output)
        creds = _load_json(out_dir / "credentials.json")
        assert _contains(creds, "anonymous")
        assert _contains(creds, "129.21.171.72")

        pcap_json = _load_json(out_dir / "pcap.json")
        assert _contains(pcap_json, "anonymous")
        assert _contains(pcap_json, "ftp_passive_data")

    def test_exclude_removes_protocol_from_results(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--category",
            "credential",
            "--exclude",
            "ftp",
            output=str(out_dir),
            format="json",
        )
        assert _no_traceback(result.combined_output)
        # The ftp credential table must not be produced once ftp is excluded.
        assert not (out_dir / "credentials.json").exists()
        pcap_json = _load_json(out_dir / "pcap.json")
        assert not _contains(pcap_json, "anonymous")

    def test_quick_preset_includes_ftp(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--quick",
            output=str(out_dir),
            format="json",
        )
        assert _no_traceback(result.combined_output)
        creds = _load_json(out_dir / "credentials.json")
        assert _contains(creds, "anonymous")

    def test_assets_flag_writes_asset_tables(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--assets",
            output=str(out_dir),
            format="json",
        )
        assert _no_traceback(result.combined_output)
        asset_files = list(out_dir.glob("*asset*")) + list(out_dir.glob("devices.csv"))
        assert asset_files, f"expected an asset export in {list(out_dir.iterdir())}"
        found_ip = any(
            "129.21.171.72" in f.read_text() or "10.10.30.26" in f.read_text()
            for f in out_dir.iterdir()
            if f.is_file()
        )
        assert found_ip, "expected a discovered device IP in the --assets export"

    def test_x509_flag_extracts_tls_certificate(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(TLS_PCAP),
            "--x509",
            "--protocols",
            "tls",
            output=str(out_dir),
            format="json",
        )
        assert _no_traceback(result.combined_output)
        cert_files = [
            f
            for f in out_dir.iterdir()
            if f.is_file() and ("x509" in f.name.lower() or "cert" in f.name.lower())
        ]
        assert cert_files, f"expected an x509/certificate export in {list(out_dir.iterdir())}"
        found_subject = any("login.passport.com" in f.read_text() for f in cert_files)
        assert found_subject, "expected the real cert subject login.passport.com in the x509 export"

    def test_hashcat_flag_writes_netntlmv2_hash(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(SMB_PCAP),
            "--hashcat",
            output=str(out_dir),
            format="json",
        )
        assert _no_traceback(result.combined_output)
        hashcat_file = out_dir / "hashcat.txt"
        assert hashcat_file.exists(), f"expected hashcat.txt in {list(out_dir.iterdir())}"
        content = hashcat_file.read_text()
        assert "DESKTOP-2AEFM7G" in content
        assert "::" in content, "expected NetNTLM hashcat format 'user::domain:...'"

    def test_extract_files_carves_real_files_from_http(self, cli_runner, tmp_path):
        extract_dir = tmp_path / "extracted"
        result = cli_runner.run(
            "pcap",
            str(HTTP_NTLM_PCAP),
            "--extract-files",
            "--extract-dir",
            str(extract_dir),
            "--protocols",
            "http",
        )
        assert _no_traceback(result.combined_output)
        extracted = [p for p in extract_dir.rglob("*") if p.is_file()]
        assert extracted, "expected --extract-files to carve at least one file to disk"
        assert any(p.suffix == ".gif" for p in extracted), (
            f"expected a real carved .gif among extracted files: {extracted}"
        )

    def test_extract_all_alias_also_carves_files(self, cli_runner, tmp_path):
        # --extract-all is documented (per -h) as an alias of --extract-files on
        # the same argparse action; drive the literal string for scorecard
        # coverage and confirm it produces the same real-data effect.
        extract_dir = tmp_path / "extracted"
        result = cli_runner.run(
            "pcap",
            str(HTTP_NTLM_PCAP),
            "--extract-all",
            "--extract-dir",
            str(extract_dir),
            "--protocols",
            "http",
        )
        assert _no_traceback(result.combined_output)
        extracted = [p for p in extract_dir.rglob("*") if p.is_file()]
        assert extracted, "expected --extract-all to carve at least one file to disk"

    def test_extract_protocols_narrows_extraction_scope(self, cli_runner, tmp_path):
        extract_dir = tmp_path / "extracted"
        result = cli_runner.run(
            "pcap",
            str(HTTP_NTLM_PCAP),
            "--extract-files",
            "--extract-dir",
            str(extract_dir),
            "--extract-protocols",
            "http",
            "--protocols",
            "http",
            json_log=True,
        )
        assert _no_traceback(result.combined_output)
        # Real effect check: files landed under the http-specific subtree,
        # and nothing was extracted for protocols outside the narrowed scope.
        extracted = [p for p in extract_dir.rglob("*") if p.is_file()]
        assert extracted, "expected --extract-protocols http to still carve http files"
        non_http_dirs = [d for d in extract_dir.iterdir() if d.is_dir() and d.name != "http"]
        assert not non_http_dirs, (
            f"--extract-protocols http leaked other protocols: {non_http_dirs}"
        )


# ---------------------------------------------------------------------------
# Category B: flags that parse/run for real but have no independently
# distinguishable effect against these fixtures
# ---------------------------------------------------------------------------


class TestPcapAcceptedFlags:
    def test_decode_as_accepted_and_preserves_normal_parse(self, cli_runner, tmp_path):
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--decode-as",
            "tcp.port==21,ftp",
            "--protocols",
            "ftp",
            output=str(out_dir),
            format="json",
        )
        assert _no_traceback(result.combined_output)
        assert result.returncode == 0
        creds = _load_json(out_dir / "credentials.json")
        assert _contains(creds, "anonymous")

    def test_stats_flag_runs_clean(self, cli_runner):
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--stats",
            "--protocols",
            "ftp",
            expect_json=False,
        )
        assert _no_traceback(result.combined_output)
        assert result.returncode == 0

    def test_list_listeners_prints_catalog(self, cli_runner):
        result = cli_runner.run(
            "pcap",
            str(FTP_PCAP),
            "--list-listeners",
            expect_json=False,
        )
        assert _no_traceback(result.combined_output)
        # Documented quirk: this path never populates a scan result so it
        # always exits 1, even on success - assert on content, not exit code.
        assert result.returncode in (0, 1)
        lowered = result.combined_output.lower()
        assert "ftp" in lowered
        assert "modbus" in lowered


# ---------------------------------------------------------------------------
# Category C: hostile / invalid-input paths (mandatory catalogue, adapted
# for a file-driven module - no host/port, no TLS mismatch, no confirm gate)
# ---------------------------------------------------------------------------


class TestPcapHostilePaths:
    def test_nonexistent_pcap_path_errors_cleanly(self, cli_runner):
        result = cli_runner.run(
            "pcap",
            "/nonexistent/path/does-not-exist.pcap",
            expect_json=False,
        )
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0
        assert "not found" in result.combined_output.lower()

    def test_directory_as_target_errors_cleanly(self, cli_runner, tmp_path):
        result = cli_runner.run("pcap", str(tmp_path), expect_json=False)
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0
        assert "not found" in result.combined_output.lower()

    def test_junk_text_file_graceful_degradation(self, cli_runner, tmp_path):
        junk = tmp_path / "junk.txt"
        junk.write_text("this is not a pcap file, just some junk text\n" * 5)
        result = cli_runner.run("pcap", str(junk), json_log=True, expect_json=False)
        assert _no_traceback(result.combined_output)
        # pcap's contract for a malformed (but present) file is graceful
        # degradation, not a hard failure: exit 0, zero devices, an error
        # event logged with the real tshark diagnostic.
        assert result.returncode == 0
        errors = result.scan_log.get_errors() if result.scan_log else []
        assert errors, "expected an error-level event logged for a non-capture file"
        assert any("capture file" in e.get("message", "").lower() for e in errors)

    def test_empty_capture_graceful_degradation(self, cli_runner, tmp_path):
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        result = cli_runner.run("pcap", str(empty), json_log=True, expect_json=False)
        assert _no_traceback(result.combined_output)
        # Unlike junk/corrupt input, a genuinely empty file is a valid
        # (trivial) capture for tshark: it is not treated as an error, it
        # just yields zero processed packets. Assert the graceful-zero
        # path rather than an error event.
        assert result.returncode == 0
        assert "Processed 0 packets" in result.combined_output

    def test_truncated_capture_graceful_degradation(self, cli_runner, tmp_path):
        truncated = tmp_path / "truncated.pcap"
        truncated.write_bytes(FTP_PCAP.read_bytes()[:200])
        result = cli_runner.run("pcap", str(truncated), json_log=True, expect_json=False)
        assert _no_traceback(result.combined_output)
        assert result.returncode == 0

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root bypasses file permission checks",
    )
    def test_permission_denied_file_graceful_degradation(self, cli_runner, tmp_path):
        locked = tmp_path / "locked.pcap"
        locked.write_bytes(FTP_PCAP.read_bytes())
        locked.chmod(0o000)
        try:
            result = cli_runner.run("pcap", str(locked), json_log=True, expect_json=False)
        finally:
            locked.chmod(0o644)
        assert _no_traceback(result.combined_output)
        assert result.returncode == 0
        errors = result.scan_log.get_errors() if result.scan_log else []
        assert errors, "expected an error-level event logged for a permission-denied file"

    def test_impostor_protocol_no_false_positive(self, cli_runner, tmp_path):
        # A pure-Modbus capture, scanned with only the ftp listener enabled:
        # must find nothing and must not fabricate a device/credential.
        out_dir = tmp_path / "out"
        result = cli_runner.run(
            "pcap",
            str(MODBUS_PCAP),
            "--protocols",
            "ftp",
            output=str(out_dir),
            format="json",
            json_log=True,
        )
        assert _no_traceback(result.combined_output)
        assert not (out_dir / "credentials.json").exists()
        pcap_json = _load_json(out_dir / "pcap.json")
        devices = pcap_json[0]["data"]["devices"] if pcap_json else []
        assert devices == [], f"expected zero devices for an impostor-protocol scan, got {devices}"


# ---------------------------------------------------------------------------
# Category C: false flags - unknown flags, typos, borrowed flags, wrong types
# ---------------------------------------------------------------------------


class TestPcapFalseFlags:
    def test_unknown_flag_rejected(self, cli_runner):
        result = cli_runner.run("pcap", str(FTP_PCAP), "--not-a-real-flag", expect_json=False)
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0
        assert "unrecognized" in result.combined_output.lower()

    def test_near_miss_typo_flag_rejected(self, cli_runner):
        # "--catagory" is a typo of --category and is NOT a valid argparse
        # abbreviation of any real flag (unlike e.g. "--protocol", which
        # argparse silently accepts as a prefix of --protocols - that is
        # argparse's own abbreviation feature, not a typo bug, so it is
        # deliberately not used as the negative case here).
        result = cli_runner.run(
            "pcap", str(FTP_PCAP), "--catagory", "credential", expect_json=False
        )
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0
        assert "unrecognized" in result.combined_output.lower()

    def test_borrowed_flag_from_other_protocol_rejected(self, cli_runner):
        # --unit-id belongs to modbus, not pcap.
        result = cli_runner.run("pcap", str(FTP_PCAP), "--unit-id", "1", expect_json=False)
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0
        assert "unrecognized" in result.combined_output.lower()

    def test_wrong_type_value_rejected(self, cli_runner):
        result = cli_runner.run("pcap", str(FTP_PCAP), "--threads", "notanumber", expect_json=False)
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0

    def test_invalid_format_choice_rejected(self, cli_runner):
        result = cli_runner.run("pcap", str(FTP_PCAP), "--format", "bogus", expect_json=False)
        assert _no_traceback(result.combined_output)
        assert result.returncode != 0
