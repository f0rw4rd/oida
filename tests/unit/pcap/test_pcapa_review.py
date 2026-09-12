"""Regression tests for pcapA bug-hunt findings B1-B3.

B1: msrpc.py winreg/srvsvc field names were missing the doubled
    "winreg_"/"srvsvc_" dissector-name prefix that pyshark's XmlLayer field
    sanitizer requires, so every WINREG/SRVSVC enrichment was silently dead.
B2: modbus.py `_parse_coil_data()` did not clip FC15 (Write Multiple Coils)
    values to the requested quantity, fabricating extra coil values from
    the padding bits in the last byte.
B3: ibmmq.py used a dead field name ("md_putapplname") that does not exist
    in the real mq tshark dissector; the real field is "md_applname".
"""

from typing import Any, Dict

from oida.pcap.ibmmq import IBMMQPassiveListener
from oida.pcap.modbus import ModbusPassiveListener
from oida.pcap.msrpc import MSRPCPassiveListener


class FakeXmlLayer:
    """Reproduces pyshark's XmlLayer field-name sanitization/matching.

    Real algorithm (pyshark.packet.layers.xml_layer.XmlLayer):
        _sanitize_field_name(name):
            name = name.replace(self._field_prefix, '')   # e.g. "winreg."
            return name.replace('.', '_').replace('-', '_').lower()

        get_field(name):
            for real_name in all_fields:
                if sanitize(name) == sanitize(real_name):
                    return all_fields[real_name]

    ``fields`` maps REAL dotted tshark field names (e.g.
    ``"winreg.winreg_OpenKey.keyname"``) to their string value. ``prefix``
    is the layer's field prefix (``"<layername>."``).
    """

    def __init__(self, prefix: str, fields: Dict[str, str]):
        object.__setattr__(self, "_prefix", prefix)
        object.__setattr__(self, "_fields", fields)

    def _sanitize(self, name: str) -> str:
        return name.replace(self._prefix, "").replace(".", "_").replace("-", "_").lower()

    def __getattr__(self, item: str) -> Any:
        target = self._sanitize(item)
        for real_name, value in self._fields.items():
            if self._sanitize(real_name) == target:
                return value
        raise AttributeError(item)


def _msrpc_listener() -> MSRPCPassiveListener:
    return MSRPCPassiveListener(interface="lo", timeout=1)


def _ibmmq_listener() -> IBMMQPassiveListener:
    return IBMMQPassiveListener(interface="lo", timeout=1)


# ---------------------------------------------------------------------------
# B1: msrpc.py winreg/srvsvc field names
# ---------------------------------------------------------------------------


def test_pyshark_prefix_strip_removes_only_first_occurrence():
    """Direct assertion of the sanitizer property that causes the bug.

    ``"winreg.winreg_OpenKey.keyname"`` contains the substring "winreg."
    exactly once (the second "winreg" is followed by "_", not "."), so
    only that first occurrence is stripped and the sanitized name keeps
    the second "winreg_" segment.
    """
    real = "winreg.winreg_OpenKey.keyname"
    prefix = "winreg."
    sanitized = real.replace(prefix, "").replace(".", "_").replace("-", "_").lower()
    assert sanitized == "winreg_openkey_keyname"

    # The current (buggy, pre-fix) code's candidate name sanitizes to a
    # DIFFERENT string and therefore never matches.
    old_candidate = "OpenKey.keyname".replace(".", "_").lower()
    assert old_candidate != sanitized

    # The prefixed candidate used by the fix sanitizes to the same string
    # as the real field, so it resolves correctly.
    new_candidate = "winreg_OpenKey.keyname".replace(prefix, "").replace(".", "_").lower()
    assert new_candidate == sanitized


def test_msrpc_winreg_field_names_resolve_against_real_tshark_names():
    listener = _msrpc_listener()
    layer = FakeXmlLayer(
        "winreg.",
        {
            "winreg.winreg_OpenKey.keyname": "HKLM\\Software\\Evil",
            "winreg.winreg_QueryValue.value_name": "AutorunPayload",
            "winreg.winreg_SetValue.name": "PersistValue",
            "winreg.winreg_SetValue.data": "C:\\evil.exe",
            "winreg.winreg_CreateKey.name": "NewKey",
            "winreg.winreg_DeleteKey.key": "OldKey",
            "winreg.winreg_DeleteValue.value": "OldValue",
            "winreg.winreg_EnumKey.name": "EnumeratedKey",
            "winreg.winreg_EnumValue.name": "EnumeratedValue",
        },
    )

    assert listener.get_field_any(layer, "winreg_OpenKey.keyname", "OpenKey.keyname") == (
        "HKLM\\Software\\Evil"
    )
    assert (
        listener.get_field_any(layer, "winreg_QueryValue.value_name", "QueryValue.value_name")
        == "AutorunPayload"
    )
    assert listener.get_field_any(layer, "winreg_SetValue.name", "SetValue.name") == (
        "PersistValue"
    )
    assert listener.get_field_any(layer, "winreg_SetValue.data", "SetValue.data") == (
        "C:\\evil.exe"
    )
    assert listener.get_field_any(layer, "winreg_CreateKey.name", "CreateKey.name") == "NewKey"
    assert listener.get_field_any(layer, "winreg_DeleteKey.key", "DeleteKey.key") == "OldKey"
    assert (
        listener.get_field_any(layer, "winreg_DeleteValue.value", "DeleteValue.value") == "OldValue"
    )
    assert listener.get_field_any(layer, "winreg_EnumKey.name", "EnumKey.name") == ("EnumeratedKey")
    assert listener.get_field_any(layer, "winreg_EnumValue.name", "EnumValue.name") == (
        "EnumeratedValue"
    )


def test_msrpc_srvsvc_field_names_resolve_against_real_tshark_names():
    listener = _msrpc_listener()
    layer = FakeXmlLayer(
        "srvsvc.",
        {
            "srvsvc.srvsvc_NetShareInfo1.name": "ADMIN$",
            "srvsvc.srvsvc_NetShareInfo1.type": "0",
            "srvsvc.srvsvc_NetShareInfo1.comment": "Remote Admin",
            "srvsvc.srvsvc_NetShareGetInfo.share_name": "C$",
            "srvsvc.srvsvc_NetShareEnumAll.server_unc": "\\\\SERVER",
        },
    )

    assert (
        listener.get_field_any(layer, "srvsvc_NetShareInfo1.name", "NetShareInfo1.name") == "ADMIN$"
    )
    assert listener.get_field_any(layer, "srvsvc_NetShareInfo1.type", "NetShareInfo1.type") == "0"
    assert (
        listener.get_field_any(layer, "srvsvc_NetShareInfo1.comment", "NetShareInfo1.comment")
        == "Remote Admin"
    )
    assert (
        listener.get_field_any(
            layer, "srvsvc_NetShareGetInfo.share_name", "NetShareGetInfo.share_name"
        )
        == "C$"
    )
    assert (
        listener.get_field_any(
            layer, "srvsvc_NetShareEnumAll.server_unc", "NetShareEnumAll.server_unc"
        )
        == "\\\\SERVER"
    )


def test_msrpc_process_winreg_end_to_end_extracts_key_path():
    """Full _process_winreg() call using a fake packet.winreg layer."""
    listener = _msrpc_listener()

    class FakePacket:
        pass

    packet = FakePacket()
    packet.winreg = FakeXmlLayer(
        "winreg.",
        {
            "winreg.opnum": "15",
            "winreg.winreg_OpenKey.keyname": "HKLM\\Software\\Evil",
        },
    )
    details: Dict[str, Any] = {}
    listener._process_winreg(packet, "10.0.0.1", "10.0.0.2", details)
    assert details.get("winreg_key") == "HKLM\\Software\\Evil"
    assert listener._winreg_ops[-1]["key"] == "HKLM\\Software\\Evil"


def test_msrpc_process_srvsvc_end_to_end_extracts_share_name():
    listener = _msrpc_listener()

    class FakePacket:
        pass

    packet = FakePacket()
    packet.srvsvc = FakeXmlLayer(
        "srvsvc.",
        {"srvsvc.srvsvc_NetShareGetInfo.share_name": "C$"},
    )
    details: Dict[str, Any] = {}
    listener._process_srvsvc(packet, "10.0.0.1", "10.0.0.2", details)
    assert details.get("share_name") == "C$"


# ---------------------------------------------------------------------------
# B2: modbus.py _parse_coil_data() FC15 clipping
# ---------------------------------------------------------------------------


def test_fc15_coil_values_clipped_to_quantity():
    # 0x07 = 0b00000111 -> bits 0,1,2 set -> ["1","1","1","0","0","0","0","0"]
    vals = ModbusPassiveListener._parse_coil_data("07", 0x0F, quantity=3)
    assert vals == ["1", "1", "1"]


def test_fc15_without_quantity_is_unclipped():
    vals = ModbusPassiveListener._parse_coil_data("07", 0x0F)
    assert len(vals) == 8


def test_fc5_single_coil_on_off_unchanged():
    assert ModbusPassiveListener._parse_coil_data("ff00", 0x05) == ["ON"]
    assert ModbusPassiveListener._parse_coil_data("00:00", 0x05) == ["OFF"]


# ---------------------------------------------------------------------------
# B3: ibmmq.py dead "md_putapplname" field
# ---------------------------------------------------------------------------


def test_ibmmq_put_application_name_uses_real_tshark_field():
    listener = _ibmmq_listener()
    layer = FakeXmlLayer("mq.", {"mq.md.applname": "AMQSPUT"})
    details: Dict[str, Any] = {}
    listener._handle_put(details, layer, "10.0.0.1", "10.0.0.2", True, "2026-09-11T00:00:00")
    assert details.get("put_app_name") == "AMQSPUT"
