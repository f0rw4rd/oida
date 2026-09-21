"""Regression test for MQTT credential-table pollution
(src/oida/pcap/mqtt.py, ``_handle_connect``, ~line 350-358).

The credential-extraction gate was ``if username or client_id:`` -- but
``client_id`` is near-universal on real CONNECT packets (MQTT v3.1.1
technically permits an empty client_id only when clean_session=1, and in
practice brokers/clients almost always send one), so almost every CONNECT,
including fully anonymous ones with no username and no password, was
recorded as a "username_only" MQTTCredential. That pollutes the credential
table with entries that carry no actual secret. A client_id-only CONNECT is
still useful telemetry, so device/interaction tracking must still happen --
only the bogus credential row should disappear.
"""

from oida.pcap.mqtt import MQTTPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """A fake MQTT packet: eth + ip + tcp + mqtt layers."""

    def __init__(self, src_ip, dst_ip, mqtt_fields, *, src_port=44000, dst_port=1883, stream="0"):
        self.eth = _Layer(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=str(src_port), dstport=str(dst_port), stream=stream)
        self.mqtt = _Layer(**mqtt_fields)


CLIENT_IP = "10.0.1.50"
BROKER_IP = "10.0.1.10"


def _make_listener():
    return MQTTPassiveListener(interface="lo", timeout=1)


def test_client_id_only_connect_records_no_credential():
    """Anonymous CONNECT (no username, no password) must not create a
    credential row, even though client_id is present."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            CLIENT_IP,
            BROKER_IP,
            {
                "msgtype": "1",
                "ver": "4",
                "protoname": "MQTT",
                "clientid": "device-1",
                "username": "",
                "passwd": "",
            },
        )
    )

    assert listener.credentials == []
    # Device/interaction tracking must still happen for this CONNECT.
    assert len(listener.interactions) == 1
    assert listener.interactions[0].summary.startswith("CONNECT")


def test_connect_with_username_still_records_credential():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            CLIENT_IP,
            BROKER_IP,
            {
                "msgtype": "1",
                "ver": "4",
                "protoname": "MQTT",
                "clientid": "device-2",
                "username": "admin",
                "passwd": "s3cret",
            },
        )
    )

    assert len(listener.credentials) == 1
    cred = listener.credentials[0]
    assert cred.username == "admin"
    assert cred.password == "s3cret"
    assert cred.credential_type == "plaintext"
