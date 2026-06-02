"""Axis 2 of the real-coverage suite: CVE replication.

For every (cve_id, mock_container, fuzzer_module) tuple, spin up the
vulnerable mock, point our fuzzer at it for a bounded number of test
cases, and assert at least one crash event is recorded.

A test failing here means EITHER:
- The mock is broken (it should crash on the documented input but
  doesn't), or
- The fuzzer is missing the request type that targets the CVE pattern.

Either way, the test produces a real signal — both are actionable.

Marked ``slow`` and ``cve_replication`` so it doesn't run in the default
unit / integration sweep. Run explicitly with::

    pytest tests/coverage/fuzz/ -m cve_replication -v

Or in the nightly CI job (``.github/workflows/coverage-nightly.yml``).

This file is the scaffold; the per-CVE assertions get filled in as
mocks land and per-fuzzer expectations stabilise.
"""

from __future__ import annotations

import socket

import pytest

# Each entry: (cve_id, mock_container, mock_port, fuzzer_protocol, max_test_cases, notes)
# When a row's mock is "*-fake", weight it lower in the scorecard — those
# return a canned crash on any input, so a pass proves the harness works,
# not that the fuzzer is competent.
CVE_REPLICATION_CASES: list[tuple[str, str, int, str, int, str]] = [
    # Modbus
    ("CVE-2019-14462", "modbus-cve-2019-14462-fake", 502, "modbus", 2000, "fake"),
    ("CVE-2022-0367", "modbus-cve-2022-0367-real", 502, "modbus", 2000, "real"),
    ("CVE-2024-10918", "modbus-cve-2024-10918-fake", 502, "modbus", 2000, "fake"),
    # MQTT
    ("CVE-2017-7651", "mqtt-cve-2017-7651", 1883, "mqtt", 2000, "real"),
    ("CVE-2017-7650", "mqtt-cve-2017-7650", 1883, "mqtt", 2000, "real"),
    ("CVE-2021-34432", "mqtt-cve-2021-34432", 1883, "mqtt", 2000, "real"),
    # OPC UA
    ("CVE-2019-19135", "opcua-cve-2019-19135", 4840, "opcua", 2000, "real"),
    ("CVE-2021-34821", "opcua-cve-2021-34821", 4840, "opcua", 2000, "real"),
    ("CVE-2022-25761", "opcua-cve-2022-25761", 4840, "opcua", 2000, "real"),
    # DNS (used by smart-discovery)
    ("CVE-2017-14491", "dns-dnsmasq-cve-2017-14491", 53, "dns", 2000, "real"),
    ("CVE-2020-25681", "dns-dnsmasq-cve-2020-25681", 53, "dns", 2000, "real"),
    ("CVE-2020-25682", "dns-cve-2020-25682", 53, "dns", 2000, "real"),
    # SMTP
    ("CVE-2019-15846", "smtp-exim-cve-2019-15846", 25, "smtp", 2000, "real"),
    ("CVE-2019-16928", "smtp-exim-cve-2019-16928", 25, "smtp", 2000, "real"),
    ("CVE-2020-7247", "smtp-opensmtpd-cve-2020-7247", 25, "smtp", 2000, "real"),
    # VNC
    ("CVE-2018-20019", "vnc-libvncserver-cve-2018-20019", 5900, "vnc", 2000, "real"),
    ("CVE-2019-8287", "vnc-tightvnc-cve-2019-8287", 5900, "vnc", 2000, "real"),
    ("CVE-2020-14397", "vnc-cve-2020-14397", 5900, "vnc", 2000, "real"),
    # CoAP
    ("CVE-2024-0962", "coap-libcoap-cve-2024-0962", 5683, "coap", 2000, "real"),
    ("CVE-2023-35862", "coap-cve-2023-35862", 5683, "coap", 2000, "real"),
    # DICOM
    ("CVE-2019-19016", "dicom-cve-2019-19016", 11112, "dicom", 2000, "real"),
]


def _mock_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """Quick TCP probe — used to skip pairs whose mock container isn't running."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def fuzzer_db_path(tmp_path_factory) -> str:
    """Per-session fuzzer DB so we can scan for crash events afterwards."""
    return str(tmp_path_factory.mktemp("cve_replication") / "fuzz.db")


@pytest.mark.cve_replication
@pytest.mark.slow
@pytest.mark.parametrize(
    "cve_id,mock_container,mock_port,fuzzer_protocol,max_test_cases,mock_quality",
    CVE_REPLICATION_CASES,
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_fuzzer_triggers_cve(
    cve_id: str,
    mock_container: str,
    mock_port: int,
    fuzzer_protocol: str,
    max_test_cases: int,
    mock_quality: str,
    fuzzer_db_path: str,
):
    """Run the protocol's fuzzer against the CVE mock; assert ≥1 crash.

    Currently a SCAFFOLD: skips when the mock isn't reachable on
    localhost. The fuzzer-driver invocation, crash-event query, and
    per-CVE budget tuning land as the harness matures (see
    ``docs/REAL_COVERAGE_PROPOSAL.md`` axis 2).
    """
    host = "127.0.0.1"
    if not _mock_reachable(host, mock_port):
        pytest.skip(
            f"{mock_container} not reachable on {host}:{mock_port} "
            f"(run: docker compose -f docker/mocks/compose.cve.yml up -d {mock_container})"
        )

    # TODO(coverage axis 2): drive the fuzzer here.
    # Sketch:
    #   from oida.fuzz.core import FuzzSession
    #   session = FuzzSession(protocol=fuzzer_protocol, target=(host, mock_port),
    #                         db_path=fuzzer_db_path, max_test_cases=max_test_cases)
    #   session.run()
    #   crashes = session.db.get_test_cases(result_filter="crash", limit=None)
    #   assert any(c.protocol == fuzzer_protocol for c in crashes), (
    #       f"{fuzzer_protocol} fuzzer did not trigger {cve_id} in "
    #       f"{max_test_cases} cases ({mock_quality} mock)"
    #   )
    pytest.skip("CVE replication harness pending — see docs/REAL_COVERAGE_PROPOSAL.md")
