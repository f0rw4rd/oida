"""
PyInstaller binary smoke tests

Exercises the built binary at dist/oida to catch missing hidden imports,
broken frozen-mode discovery, and CLI regressions before release.

Run:
    pyinstaller oida.spec --clean
    pytest tests/integration/test_binary_smoke.py -v -m binary
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

# All protocol subcommands exposed by the CLI.
# NOTE: snap7 is exposed as "s7" in the CLI, so use that name here.
ALL_PROTOCOLS = [
    "ads",
    "astm",
    "bacnet",
    "can",
    "coap",
    "dicom",
    "discovery",
    "dnp3",
    "ethercat",
    "ethernetip",
    "fhir",
    "goose",
    "hart",
    "hl7",
    "iec104",
    "knx",
    "mms",
    "modbus",
    "mqtt",
    "ocpp",
    "opcua",
    "pcap",
    "profinet",
    "s7",
    "snmp",
    "tase2",
]

# Protocols whose FROZEN_DIAG failures are known/expected
KNOWN_FROZEN_FAILURES = {"codesys"}


def _run(bin_path, *args, timeout=30):
    """Run the binary and return CompletedProcess."""
    return subprocess.run(
        [str(bin_path), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _is_frozen_diag_traceback(stderr):
    """Return True if all tracebacks in stderr are FROZEN_DIAG loader tracebacks.

    The frozen protocol loader prints tracebacks for protocols it can't import
    (e.g. codesys). These are diagnostic, not crashes. This helper distinguishes
    them from real unhandled exceptions.
    """
    lines = stderr.strip().splitlines()
    if not lines:
        return False

    # Split into traceback blocks
    blocks = []
    current = []
    for line in lines:
        if line.startswith("Traceback (most recent call last)"):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))

    if not blocks:
        return False

    # Every traceback block must come from the frozen loader
    return all("_discover_frozen" in block or "FROZEN_DIAG" in block for block in blocks)


@pytest.fixture(scope="session")
def oida_bin():
    """Resolve dist/oida binary, skip all tests if it doesn't exist."""
    project_root = Path(__file__).resolve().parent.parent.parent
    dist = project_root / "dist"
    candidates = [
        # onedir (COLLECT) layout — the shipped, non-invasive build.
        dist / "oida" / "oida",
        dist / "oida" / "oida.exe",
        # onefile layout — fallback if someone builds that way.
        dist / "oida.exe",
        dist / "oida",
    ]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return p

    pytest.skip("Binary not found in dist/ (run: pyinstaller oida.spec --clean)")


@pytest.mark.binary
class TestBinarySmoke:
    """Smoke tests for the PyInstaller-built binary."""

    def test_version(self, oida_bin):
        """oida --version exits 0 and contains a version string."""
        result = _run(oida_bin, "--version")
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "." in result.stdout, f"No version string in output: {result.stdout!r}"

    def test_help(self, oida_bin):
        """oida --help exits 0 and lists all protocol names."""
        result = _run(oida_bin, "--help")
        assert result.returncode == 0, f"stderr: {result.stderr}"
        output = result.stdout.lower()
        for proto in ALL_PROTOCOLS:
            assert proto in output, f"Protocol {proto!r} missing from --help output"

    @pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
    def test_protocol_help(self, oida_bin, protocol):
        """oida <proto> --help exits 0 for each protocol."""
        result = _run(oida_bin, protocol, "--help")
        assert result.returncode == 0, (
            f"{protocol} --help failed (rc={result.returncode})\n"
            f"stdout: {result.stdout[:500]}\n"
            f"stderr: {result.stderr[:500]}"
        )

    def test_bug_report(self, oida_bin):
        """oida --bug exits 0 and contains diagnostic info."""
        result = _run(oida_bin, "--bug")
        assert result.returncode == 0, f"stderr: {result.stderr}"
        output = result.stdout.lower()
        assert "python" in output or "platform" in output or "version" in output, (
            f"Bug report output missing diagnostic info:\n{result.stdout[:500]}"
        )

    def test_invalid_target_error(self, oida_bin):
        """oida modbus <bogus> exits non-zero without an unhandled traceback."""
        result = _run(oida_bin, "modbus", "invalid-host-that-does-not-exist", "--timeout", "1")
        assert result.returncode != 0
        # FROZEN_DIAG tracebacks from the loader are expected and harmless
        if "Traceback (most recent call last)" in result.stderr:
            assert _is_frozen_diag_traceback(result.stderr), (
                f"Unhandled traceback in stderr:\n{result.stderr[:1000]}"
            )

    def test_no_frozen_diag_errors(self, oida_bin):
        """oida --help stderr shouldn't contain FROZEN_DIAG failures (except known)."""
        result = _run(oida_bin, "--help")
        for line in (result.stdout + result.stderr).splitlines():
            if "FROZEN_DIAG:" not in line:
                continue
            known = any(name in line for name in KNOWN_FROZEN_FAILURES)
            assert known, f"Unexpected frozen diagnostic failure: {line}"

    def test_binary_size(self, oida_bin):
        """Onedir bundle is between 30MB and 500MB (sanity check).

        For onedir builds, oida_bin is the bootloader exe inside the bundle
        directory.  The bootloader is only ~20 MB; the full bundle (all .so
        libraries and bundled packages) lives in the parent directory.  Measure
        the parent so the check reflects real bundle size.
        """
        bundle_dir = oida_bin.parent
        if bundle_dir.is_dir() and bundle_dir != oida_bin:
            size_mb = (
                sum(f.stat().st_size for f in bundle_dir.rglob("*") if f.is_file())
                / (1024 * 1024)
            )
        else:
            size_mb = oida_bin.stat().st_size / (1024 * 1024)
        assert 30 <= size_mb <= 500, (
            f"Bundle size {size_mb:.1f}MB outside expected range [30MB, 500MB]"
        )

    def test_json_output_format(self, oida_bin):
        """oida modbus 127.0.0.1 --format json produces parseable JSON structure."""
        result = _run(
            oida_bin,
            "modbus",
            "127.0.0.1",
            "--timeout",
            "1",
            "--format",
            "json",
            "-o",
            "/tmp",
        )
        # Even on connection failure, check if a JSON file was produced
        json_files = list(Path("/tmp").glob("oida_modbus_*.json"))
        if json_files:
            latest = max(json_files, key=lambda p: p.stat().st_mtime)
            try:
                data = json.loads(latest.read_text())
                assert isinstance(data, (dict, list)), f"JSON root is {type(data).__name__}"
            finally:
                latest.unlink(missing_ok=True)
        else:
            # No JSON file — check stdout
            stdout = result.stdout.strip()
            if stdout.startswith(("{", "[")):
                data = json.loads(stdout)
                assert isinstance(data, (dict, list))
            else:
                pytest.skip("No JSON output produced (connection refused, no file written)")
