"""Regression tests for DHCP option extraction against the tshark registry.

Authority: ``tshark -G fields`` (tshark 4.4.15). Option 119 (Domain Search
List) is emitted by the dissector under three filter names:

    dhcp.option.dhcp_dns_domain_search_list_fqdn                 (the value)
    dhcp.option.dhcp_dns_domain_search_list_rfc_3396_detected    (marker)
    dhcp.option.dhcp_dns_domain_search_list_refer_last_option    (marker)

There is NO ``dhcp.option.domain_search`` -- the token the listener used to
read -- so the harvested ``domain_search`` detail was always empty, silently
(no error, no log; ``get_field`` returns the default on a miss).

The same file reads Option 15 (``option_domain_name``, real) next to it, which
is why the dead token was easy to miss.
"""

import subprocess

import pytest

from oida.pcap.dhcp import DHCPPassiveListener  # noqa: F401  (import sanity)


def _tshark_fields() -> set:
    try:
        r = subprocess.run(
            ["tshark", "-G", "fields"], capture_output=True, text=True, timeout=90
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("tshark not installed")
    if r.returncode != 0:
        pytest.skip("tshark -G fields failed")
    return {line.split("\t")[2] for line in r.stdout.splitlines() if line.count("\t") >= 3}


def test_option_119_has_no_domain_search_field():
    fields = _tshark_fields()
    assert "dhcp.option.domain_search" not in fields


def test_option_119_fqdn_field_exists():
    fields = _tshark_fields()
    assert "dhcp.option.dhcp_dns_domain_search_list_fqdn" in fields


def test_listener_reads_a_real_option_119_token():
    import inspect
    import re

    import oida.pcap.dhcp as dhcp_mod

    src = inspect.getsource(dhcp_mod)
    m = re.search(
        r"domain_search\s*=\s*str\(\s*self\.get_field(?:_any)?\((.*?)\)\s*\)?",
        src,
        re.DOTALL,
    )
    assert m, "listener must read domain_search via get_field/get_field_any"
    call = m.group(1)
    assert "dhcp_dns_domain_search_list_fqdn" in call, (
        f"option 119 must be read via the real *_fqdn token, got: {call}"
    )
