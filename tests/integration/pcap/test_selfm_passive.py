"""Integration tests for the SEL Fast Message (SELFM) passive listener.

Tests cover:
- Command-word decoding (Relay Definition, Fast Meter Data, Fast Operate)
- Fast Operate control-command flagging (relay actuation)
- Relay vs. master role classification
- Control-operation harvest alerts
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

_PCAP = "selfm/oida_selfm_fastmsg.pcap"
_DECODE = {"tcp.port==23": "selfm"}


class TestSELFMPassive:
    def test_basic_extraction(self):
        listener, devices, result = _run_listener_test(
            "selfm",
            "SELFMPassiveListener",
            "selfm",
            _PCAP,
            min_devices=1,
            min_interactions=4,
            expect_details=["command_name", "command_word"],
            expect_operations=["Relay Definition", "Fast Meter Data"],
            decode_as=_DECODE,
        )
        assert len(listener.interactions) == 4

    def test_command_words_decoded(self):
        listener, _, _ = _run_listener_test(
            "selfm", "SELFMPassiveListener", "selfm", _PCAP, decode_as=_DECODE
        )
        names = {ix.details.get("command_name") for ix in listener.interactions}
        assert "Relay Definition" in names, f"got {names}"
        assert "Fast Meter Data" in names, f"got {names}"
        # no command should be Unknown -- the decimal msgtype must parse
        assert not any("Unknown" in (n or "") for n in names), f"unparsed cmd: {names}"

    def test_fast_operate_control_flagged(self):
        listener, _, result = _run_listener_test(
            "selfm", "SELFMPassiveListener", "selfm", _PCAP, decode_as=_DECODE
        )
        controls = [ix for ix in listener.interactions if ix.details.get("is_control")]
        names = {ix.details.get("command_name") for ix in controls}
        assert "Alt Fast Operate OPEN" in names, f"got {names}"
        assert "Alt Fast Operate CLOSE" in names, f"got {names}"
        # control ops must surface as harvest alerts
        alert_msgs = " ".join(a.get("message", "") for a in result.get("alerts", []))
        assert "CONTROL" in alert_msgs.upper(), f"no control alert: {result.get('alerts')}"

    def test_roles_classified(self):
        listener, devices, _ = _run_listener_test(
            "selfm", "SELFMPassiveListener", "selfm", _PCAP, decode_as=_DECODE
        )
        roles = {getattr(d, "selfm_passive_data", {}).get("role") for d in devices.values()}
        assert "master" in roles, f"expected master role; got {roles}"

    def test_control_op_count(self):
        listener, _, _ = _run_listener_test(
            "selfm", "SELFMPassiveListener", "selfm", _PCAP, decode_as=_DECODE
        )
        assert len(listener.get_control_operations()) == 2, (
            f"expected 2 control ops; got {listener.get_control_operations()}"
        )
