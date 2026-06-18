"""Verify all listeners follow the unified interaction table format.

Every passive listener that records interactions must:

1. Set PROTOCOL_COLUMNS (protocol-specific table columns)
2. Override _format_protocol_columns() returning rows matching the column count
3. Use direction "request" or "response" on every interaction
4. _format_details_string() produces 'Col=val Col2=val2' from PROTOCOL_COLUMNS

This test discovers all listeners from the LISTENER_REGISTRY, feeds a
representative pcap through each, and validates the above invariants.
Listeners that produce interactions but lack PROTOCOL_COLUMNS will FAIL.
"""

import importlib
from pathlib import Path

import pytest

from oida.pcap.passive.pyshark_base import PySharkListenerBase

from .conftest import requires_pyshark

FIXTURES_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "pcap"

# Build test cases from the integration conftest LISTENER_PCAP_CASES.
# Each entry maps a listener to a pcap that produces interactions.
# We import lazily to avoid import-time failures.
_ALL_LISTENERS: list[dict] = [
    # ICS / SCADA
    {
        "module": "modbus",
        "cls": "ModbusPassiveListener",
        "filter": "mbtcp",
        "pcap": "modbus/cisagov_modbus_example.pcap",
    },
    {
        "module": "iec104",
        "cls": "IEC104PassiveListener",
        "filter": "iec60870_104",
        "pcap": "iec104/emreekin_iec104_baselines.pcap",
    },
    {
        "module": "opcua",
        "cls": "OPCUAPassiveListener",
        "filter": "opcua",
        "pcap": "opcua/cisagov_opcua_with-gap_with-handshake.pcap",
    },
    {
        "module": "s7comm",
        "cls": "S7commPassiveListener",
        "filter": "s7comm",
        "pcap": "s7comm/cisagov_snap7.pcap",
    },
    {
        "module": "enip",
        "cls": "EtherNetIPPassiveListener",
        "filter": "enip or cip",
        "pcap": "enip/cisagov_enip_cip_example.pcap",
    },
    {
        "module": "dnp3",
        "cls": "DNP3PassiveListener",
        "filter": "dnp3",
        "pcap": "dnp3/cisagov_dnp3_example.pcap",
    },
    {
        "module": "bacnet",
        "cls": "BACnetPassiveListener",
        "filter": "bacapp",
        "pcap": "bacnet/cisagov_bacnet_example.pcap",
    },
    {
        "module": "mms",
        "cls": "MMSPassiveListener",
        "filter": "acse or mms",
        "pcap": "mms/iti_iec61850_session.pcap",
    },
    {
        "module": "fins",
        "cls": "FINSPassiveListener",
        "filter": "omron",
        "pcap": "fins/cisagov_omron_fins_tcp.pcap",
    },
    {
        "module": "ads",
        "cls": "ADSPassiveListener",
        "filter": "ams",
        "pcap": "ads/iti_addroute1.pcapng",
    },
    {
        "module": "goose",
        "cls": "GOOSEPassiveListener",
        "filter": "goose",
        "pcap": "goose/goosestalker_GOOSE.pcap",
    },
    {
        "module": "profinet",
        "cls": "PROFINETPassiveListener",
        "filter": "pn_io || pn_dcp || pn_rt || pn_io.opnum",
        "pcap": "profinet/cisagov_profinet_io_cm_mixed_1.pcap",
    },
    {
        "module": "ethercat",
        "cls": "EtherCATPassiveListener",
        "filter": "ecat",
        "pcap": "ethercat/cisagov_ethercat_example.pcap",
    },
    {
        "module": "knx",
        "cls": "KNXPassiveListener",
        "filter": "kip",
        "pcap": "knx/ndpi_knxip.pcapng",
    },
    {
        "module": "hartip",
        "cls": "HARTIPPassiveListener",
        "filter": "hart_ip",
        "pcap": "hart/iti_hart_ip.pcap",
    },
    {"module": "sv", "cls": "SVPassiveListener", "filter": "sv", "pcap": "sv/generated_sv.pcap"},
    # Routing / FHRP / multicast
    {
        "module": "ospf",
        "cls": "OSPFPassiveListener",
        "filter": "ospf",
        "pcap": "ospf/generated_ospf.pcap",
    },
    {
        "module": "eigrp",
        "cls": "EIGRPPassiveListener",
        "filter": "eigrp",
        "pcap": "eigrp/generated_eigrp.pcap",
    },
    {
        "module": "rip",
        "cls": "RIPPassiveListener",
        "filter": "rip",
        "pcap": "rip/generated_rip.pcap",
    },
    {
        "module": "pim",
        "cls": "PIMPassiveListener",
        "filter": "pim",
        "pcap": "pim/generated_pim.pcap",
    },
    {
        "module": "glbp",
        "cls": "GLBPPassiveListener",
        "filter": "glbp",
        "pcap": "glbp/generated_glbp.pcap",
    },
    {
        "module": "hsrp",
        "cls": "HSRPPassiveListener",
        "filter": "hsrp",
        "pcap": "hsrp/filtered_hsrp.pcap",
    },
    {
        "module": "vrrp",
        "cls": "VRRPPassiveListener",
        "filter": "vrrp",
        "pcap": "vrrp/filtered_vrrp.pcap",
    },
    {
        "module": "bfd",
        "cls": "BFDPassiveListener",
        "filter": "bfd",
        "pcap": "bfd/generated_bfd.pcap",
    },
    {
        "module": "stp",
        "cls": "STPPassiveListener",
        "filter": "stp",
        "pcap": "stp/wireshark_stp_old.pcap",
    },
    {
        "module": "igmp",
        "cls": "IGMPPassiveListener",
        "filter": "igmp",
        "pcap": "igmp/filtered_igmp.pcap",
    },
    # Credential / auth
    {
        "module": "ftp",
        "cls": "FTPPassiveListener",
        "filter": "ftp",
        "pcap": "ftp/bruteshark_ftp.pcap",
    },
    {
        "module": "telnet",
        "cls": "TelnetPassiveListener",
        "filter": "telnet",
        "pcap": "telnet/bruteshark_telnet.pcap",
    },
    {
        "module": "imap",
        "cls": "IMAPPassiveListener",
        "filter": "imap",
        "pcap": "imap/bruteshark_imap_login1.pcap",
    },
    {
        "module": "smtp",
        "cls": "SMTPPassiveListener",
        "filter": "smtp",
        "pcap": "smtp/bruteshark_smtp_auth_login.pcap",
    },
    {
        "module": "pop3",
        "cls": "POP3PassiveListener",
        "filter": "pop",
        "pcap": "pop3/bruteshark_pop3.pcap",
    },
    {
        "module": "kerberos",
        "cls": "KerberosPassiveListener",
        "filter": "kerberos",
        "pcap": "kerberos/bruteshark_kerberos_v5_tcp.pcap",
    },
    {
        "module": "ntlm",
        "cls": "NTLMPassiveListener",
        "filter": "ntlmssp",
        "pcap": "smb/bruteshark_ntlm_smb.pcap",
    },
    {
        "module": "irc",
        "cls": "IRCPassiveListener",
        "filter": "irc",
        "pcap": "irc/generated_irc.pcap",
    },
    {
        "module": "tacacs",
        "cls": "TACACSPassiveListener",
        "filter": "tacacs or tacplus",
        "pcap": "tacacs/generated_tacacs.pcap",
    },
    {
        "module": "pap",
        "cls": "PAPPassiveListener",
        "filter": "pap",
        "pcap": "pap/generated_pap.pcap",
    },
    {
        "module": "socks",
        "cls": "SOCKSPassiveListener",
        "filter": "socks",
        "pcap": "socks/generated_socks.pcap",
    },
    {
        "module": "mqtt",
        "cls": "MQTTPassiveListener",
        "filter": "mqtt",
        "pcap": "mqtt/emreekin_mqtt_user_credentials.pcap",
    },
    {
        "module": "radius",
        "cls": "RADIUSPassiveListener",
        "filter": "radius",
        "pcap": "radius/generated_radius.pcap",
    },
    {
        "module": "sip",
        "cls": "SIPPassiveListener",
        "filter": "sip",
        "pcap": "sip/wireshark_sip_rtp.pcapng",
    },
    {
        "module": "vnc",
        "cls": "VNCPassiveListener",
        "filter": "vnc",
        "pcap": "vnc/generated_vnc.pcap",
    },
    {
        "module": "rdp",
        "cls": "RDPPassiveListener",
        "filter": "rdp",
        "pcap": "rdp/generated_rdp.pcap",
    },
    {
        "module": "bgp",
        "cls": "BGPPassiveListener",
        "filter": "bgp",
        "pcap": "bgp/generated_bgp.pcap",
    },
    # Database
    {
        "module": "pgsql",
        "cls": "PostgreSQLPassiveListener",
        "filter": "pgsql",
        "pcap": "pgsql/credslayer_pgsql.pcap",
    },
    {
        "module": "mysql",
        "cls": "MySQLPassiveListener",
        "filter": "mysql",
        "pcap": "mysql/credslayer_mysql.pcap",
    },
    {
        "module": "mssql",
        "cls": "MSSQLPassiveListener",
        "filter": "tds",
        "pcap": "mssql/generated_mssql.pcap",
    },
    # Network services
    {
        "module": "http",
        "cls": "HTTPPassiveListener",
        "filter": "http",
        "pcap": "http/bruteshark_http_basic.pcap",
    },
    {
        "module": "tls",
        "cls": "TLSPassiveListener",
        "filter": "tls.handshake or tls.alert_message",
        "pcap": "tls/zeek_client-certificate.pcap",
    },
    {
        "module": "dns",
        "cls": "DNSPassiveListener",
        "filter": "dns",
        "pcap": "dns/zeek_dns-binds.pcap",
    },
    {
        "module": "snmp",
        "cls": "SNMPPassiveListener",
        "filter": "snmp",
        "pcap": "snmp/zeek_snmpv1_get.pcap",
    },
    {
        "module": "ldap",
        "cls": "LDAPPassiveListener",
        "filter": "ldap",
        "pcap": "ldap/credslayer_ldap_simpleauth.pcap",
    },
    {
        "module": "smb",
        "cls": "SMBPassiveListener",
        "filter": "smb or smb2",
        "pcap": "smb/bruteshark_ntlm_smb.pcap",
    },
    {
        "module": "dhcp",
        "cls": "DHCPPassiveListener",
        "filter": "dhcp || bootp",
        "pcap": "dhcp/zeek_dhcp_flood.pcap",
    },
    # Discovery / broadcast
    {
        "module": "cdp",
        "cls": "CDPPassiveListener",
        "filter": "cdp",
        "pcap": "cdp/filtered_cdp.pcap",
    },
    {
        "module": "lldp",
        "cls": "LLDPPassiveListener",
        "filter": "lldp",
        "pcap": "lldp/wireshark_lldp_detailed.pcap",
    },
    {"module": "ssdp", "cls": "SSDPPassiveListener", "filter": "ssdp", "pcap": "ssdp/ssdp.pcap"},
    {
        "module": "mdns",
        "cls": "MDNSPassiveListener",
        "filter": "mdns",
        "pcap": "mdns/generated_mdns.pcap",
    },
    {
        "module": "tftp",
        "cls": "TFTPPassiveListener",
        "filter": "tftp",
        "pcap": "tftp/internet_tftp_rrq.pcap",
    },
]


def _ids(cases):
    return [c["module"] for c in cases]


_MAX_PACKETS = 1000  # Cap per-listener feeds to keep unit tests fast (ethercat has 44k)


def _load_listener(case, _retries: int = 4):
    """Import and instantiate a listener, feed packets, return it.

    tshark is spawned per call via pyshark; under heavy parallel test load
    (``-n auto`` across the whole unit suite) tshark intermittently crashes on
    resource contention. These crashes are transient, so retry a few times with
    a short backoff before giving up.
    """
    import itertools
    import time

    from pyshark.capture.capture import TSharkCrashException

    mod = importlib.import_module(f"oida.pcap.passive.{case['module']}")
    cls = getattr(mod, case["cls"])
    listener = cls(interface="lo", timeout=10)

    pcap_path = FIXTURES_ROOT / case["pcap"]
    if not pcap_path.exists():
        pytest.fail(f"Fixture not found: {pcap_path}")

    import pyshark

    cap = pyshark.FileCapture(
        str(pcap_path),
        display_filter=case["filter"],
        use_ek=True,
        include_raw=False,
    )
    try:
        listener.feed_packets(itertools.islice(iter(cap), _MAX_PACKETS))
    except TSharkCrashException:
        if _retries > 0:
            time.sleep(0.5)
            return _load_listener(case, _retries=_retries - 1)
        raise
    finally:
        try:
            cap.close()
        except Exception:
            pass  # TShark exits non-zero when killed after islice cap; not a real crash
    return listener


class TestAllListenersHaveProtocolColumns:
    """Every listener that produces interactions must have PROTOCOL_COLUMNS."""

    @requires_pyshark
    @pytest.mark.parametrize("case", _ALL_LISTENERS, ids=_ids(_ALL_LISTENERS))
    def test_listener_with_interactions_has_columns(self, case):
        """If a listener records interactions, it must set PROTOCOL_COLUMNS."""
        listener = _load_listener(case)
        if not listener.interactions:
            pytest.skip(f"{case['module']}: no interactions produced")

        assert listener.PROTOCOL_COLUMNS, (
            f"{case['cls']} records {len(listener.interactions)} interactions "
            f"but does not set PROTOCOL_COLUMNS. "
            f"Add PROTOCOL_COLUMNS and _format_protocol_columns() "
            f"so the unified table produces a Details column."
        )


class TestInteractionDirections:
    """Every interaction direction must be 'request' or 'response'."""

    @requires_pyshark
    @pytest.mark.parametrize("case", _ALL_LISTENERS, ids=_ids(_ALL_LISTENERS))
    def test_direction_values(self, case):
        """Interaction.direction must be 'request' or 'response'."""
        listener = _load_listener(case)
        if not listener.interactions:
            pytest.skip(f"{case['module']}: no interactions produced")

        bad = [
            (i, ix.direction)
            for i, ix in enumerate(listener.interactions)
            if ix.direction not in ("request", "response")
        ]
        assert not bad, (
            f"{case['cls']}: {len(bad)} interactions with invalid direction "
            f"(must be 'request' or 'response'): {bad[:5]}"
        )


class TestInteractionProtocolField:
    """Every interaction must have a non-empty protocol field."""

    @requires_pyshark
    @pytest.mark.parametrize("case", _ALL_LISTENERS, ids=_ids(_ALL_LISTENERS))
    def test_protocol_auto_set(self, case):
        """Interaction.protocol must be auto-set by _record_interaction."""
        listener = _load_listener(case)
        if not listener.interactions:
            pytest.skip(f"{case['module']}: no interactions produced")

        bad = [(i, ix.protocol) for i, ix in enumerate(listener.interactions) if not ix.protocol]
        assert not bad, (
            f"{case['cls']}: {len(bad)} interactions with empty protocol field: {bad[:5]}"
        )


class TestFormatDetailsString:
    """_format_details_string() must produce valid output for all listeners."""

    @requires_pyshark
    @pytest.mark.parametrize("case", _ALL_LISTENERS, ids=_ids(_ALL_LISTENERS))
    def test_details_string_is_str(self, case):
        """_format_details_string() must return a string."""
        listener = _load_listener(case)
        if not listener.interactions or not listener.PROTOCOL_COLUMNS:
            pytest.skip(f"{case['module']}: no interactions or no columns")

        for ix in listener.interactions[:20]:
            result = listener._format_details_string(ix)
            assert isinstance(result, str), (
                f"{case['cls']}: _format_details_string returned {type(result)}"
            )

    @requires_pyshark
    @pytest.mark.parametrize("case", _ALL_LISTENERS, ids=_ids(_ALL_LISTENERS))
    def test_details_string_column_count_matches(self, case):
        """_format_protocol_columns() must return len(PROTOCOL_COLUMNS) items."""
        listener = _load_listener(case)
        if not listener.interactions or not listener.PROTOCOL_COLUMNS:
            pytest.skip(f"{case['module']}: no interactions or no columns")

        expected = len(listener.PROTOCOL_COLUMNS)
        bad = []
        for ix in listener.interactions[:20]:
            values = listener._format_protocol_columns(ix)
            if len(values) != expected:
                bad.append((ix.operation, len(values), expected))
        assert not bad, f"{case['cls']}: _format_protocol_columns returned wrong count: {bad[:5]}"

    @requires_pyshark
    @pytest.mark.parametrize("case", _ALL_LISTENERS, ids=_ids(_ALL_LISTENERS))
    def test_no_raw_objects_in_details(self, case):
        """Details string must not contain repr of raw dicts, sets, or lists."""
        listener = _load_listener(case)
        if not listener.interactions or not listener.PROTOCOL_COLUMNS:
            pytest.skip(f"{case['module']}: no interactions or no columns")

        bad = []
        for ix in listener.interactions[:50]:
            values = listener._format_protocol_columns(ix)
            for j, cell in enumerate(values):
                if isinstance(cell, (dict, set, list)):
                    bad.append((ix.operation, j, type(cell).__name__))
        assert not bad, f"{case['cls']}: raw objects in protocol column cells: {bad[:5]}"


# Listeners that call get_port_info() — TCP/UDP protocols that must
# produce at least some interactions with non-zero src_port/dst_port.
_PORT_LISTENERS = [
    c
    for c in _ALL_LISTENERS
    if c["module"]
    in {
        "modbus",
        "opcua",
        "iec104",
        "s7comm",
        "enip",
        "mms",
        "hartip",
        "ftp",
        "telnet",
        "imap",
        "smtp",
        "pop3",
        "kerberos",
        "ntlm",
        "socks",
        "mqtt",
        "tacacs",
        "sip",
        "vnc",
        "rdp",
        "http",
        "tls",
        "snmp",
        "ldap",
        "smb",
        "pgsql",
        "mysql",
        "mssql",
    }
]


class TestInteractionPorts:
    """TCP/UDP listeners must populate src_port/dst_port on interactions."""

    @requires_pyshark
    @pytest.mark.parametrize("case", _PORT_LISTENERS, ids=_ids(_PORT_LISTENERS))
    def test_ports_populated(self, case):
        """At least some interactions should have non-zero ports."""
        listener = _load_listener(case)
        if not listener.interactions:
            pytest.skip(f"{case['module']}: no interactions produced")

        with_ports = [ix for ix in listener.interactions if ix.src_port != 0 or ix.dst_port != 0]
        assert with_ports, (
            f"{case['cls']}: {len(listener.interactions)} interactions but none "
            f"have src_port/dst_port set. Did process_packet() call "
            f"get_port_info() and pass ports to _record_interaction()?"
        )

    @requires_pyshark
    @pytest.mark.parametrize("case", _PORT_LISTENERS, ids=_ids(_PORT_LISTENERS))
    def test_all_interactions_have_ports(self, case):
        """Every interaction from a TCP/UDP listener should have ports."""
        listener = _load_listener(case)
        if not listener.interactions:
            pytest.skip(f"{case['module']}: no interactions produced")

        missing = [
            (i, ix.operation, ix.src_port, ix.dst_port)
            for i, ix in enumerate(listener.interactions)
            if ix.src_port == 0 and ix.dst_port == 0
        ]
        assert not missing, (
            f"{case['cls']}: {len(missing)}/{len(listener.interactions)} "
            f"interactions missing ports: {missing[:5]}"
        )


class TestFormatIpPort:
    """_format_ip_port() static method tests."""

    def test_with_port(self):
        assert PySharkListenerBase._format_ip_port("10.0.0.1", 502) == "10.0.0.1:502"

    def test_without_port(self):
        assert PySharkListenerBase._format_ip_port("10.0.0.1", 0) == "10.0.0.1"

    def test_ipv6_with_port(self):
        assert PySharkListenerBase._format_ip_port("::1", 80) == "::1:80"

    def test_empty_ip_no_port(self):
        assert PySharkListenerBase._format_ip_port("", 0) == ""
