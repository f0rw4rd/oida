"""Regression: TFTP DATA server attribution must be scoped to the endpoint pair.

DATA/ACK arrive on a fresh ephemeral-TID flow, so the per-flow server map never
matches them. The listener used to fall back to a *global* set of every server
IP ever seen, which mislabels a host that is the server in one transfer and the
client in an unrelated transfer.
"""

import pytest

from oida.pcap.tftp import TFTPPassiveListener

pytestmark = [pytest.mark.integration]


def _mk():
    return TFTPPassiveListener(interface="lo", timeout=1)


class _FakeTftp:
    """Minimal pyshark tftp layer exposing only the fields the handlers read."""

    def __init__(self, **fields):
        self._fields = fields

    def get_field(self, name):
        return self._fields.get(name)

    def __getattr__(self, name):
        try:
            return self._fields[name]
        except KeyError as exc:  # pragma: no cover
            raise AttributeError(name) from exc


def _rrq(client, server):
    return _FakeTftp(opcode="1", source_file="boot.cfg", type="octet")


def _data():
    return _FakeTftp(opcode="3", blocknum="1")


class TestPairScopedServerRole:
    def test_host_that_was_server_is_not_server_in_a_client_transfer(self):
        listener = _mk()

        # Transfer 1: A read-requests from B -> B becomes a known server.
        listener._process_rrq(
            _rrq("10.0.0.1", "10.0.0.2"),
            "10.0.0.1",
            "10.0.0.2",
            "",
            "",
            flow_id="10.0.0.1:2000-10.0.0.2:69",
            now="1700000000.0",
        )
        # Transfer 2: B read-requests from C -> C is the server, B the client.
        listener._process_rrq(
            _rrq("10.0.0.2", "10.0.0.3"),
            "10.0.0.2",
            "10.0.0.3",
            "",
            "",
            flow_id="10.0.0.2:2010-10.0.0.3:69",
            now="1700000001.0",
        )

        # DATA from C to B on a fresh ephemeral-TID flow (server -> client).
        listener._process_data(
            _data(),
            "10.0.0.3",
            "10.0.0.2",
            "",
            "",
            flow_id="10.0.0.3:1025-10.0.0.2:2011",
            now="1700000002.0",
        )

        keys = set(listener.discovered_devices.keys())
        # C is the server for the {B,C} transfer. With the stale global set, B
        # (a server in transfer 1) matched as dst and C was tagged the client.
        assert "tftp-server:10.0.0.3" in keys, (
            "true server C was not recognized; DATA resolved via the stale set"
        )
        assert "tftp-client:10.0.0.3" not in keys, (
            "true server C mislabeled as client from the stale global server set"
        )

    def test_host_uploading_is_not_tagged_server_from_stale_set(self):
        listener = _mk()
        # Transfer 1: X reads from B -> B is a known server.
        listener._process_rrq(
            _rrq("10.0.0.5", "10.0.0.2"),
            "10.0.0.5",
            "10.0.0.2",
            "",
            "",
            flow_id="10.0.0.5:2000-10.0.0.2:69",
            now="1700000000.0",
        )
        # Transfer 2: B uploads (WRQ) to C -> C is server, B is client.
        listener._process_wrq(
            _FakeTftp(opcode="2", destination_file="cfg.bin", type="octet"),
            "10.0.0.2",
            "10.0.0.3",
            "",
            "",
            flow_id="10.0.0.2:2010-10.0.0.3:69",
            now="1700000001.0",
        )
        # DATA sourced BY B to C in the upload.
        listener._process_data(
            _data(),
            "10.0.0.2",
            "10.0.0.3",
            "",
            "",
            flow_id="10.0.0.2:1025-10.0.0.3:2011",
            now="1700000002.0",
        )

        keys = set(listener.discovered_devices.keys())
        # C is the true server (B uploads to it). With the bug, B was in the
        # global server set and its sourced DATA tagged B server / C client.
        assert "tftp-server:10.0.0.3" in keys, "true server C not recognized on upload DATA"
        assert "tftp-client:10.0.0.3" not in keys, (
            "true server C mislabeled as client from the stale global server set"
        )
