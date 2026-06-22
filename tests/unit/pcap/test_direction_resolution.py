"""Unit tests for the shared direction-resolution cascade.

`PySharkListenerBase.resolve_direction()` replaces per-listener hardcoded
port checks (`dst_port == 502`) with a port-independent cascade:

  1. native protocol request/response signal (authoritative)
  2. known server port -- canonical SERVER_PORTS *plus* user --decode-as /
     OVERRIDE_PREFS overrides (configure_ports())
  3. heuristic -- lower-port-is-server, then first-seen-in-flow

These tests drive the cascade directly (no pyshark / tshark needed) and assert
that:
  - the right tier wins and reports the right confidence,
  - user port overrides promote a non-standard port to "known server" (so the
    result is high-confidence, not a heuristic guess),
  - a non-standard port never *drops* a packet (the old hardcoded bug).
"""

from oida.pcap.pyshark_base import PySharkListenerBase


class _FakeListener(PySharkListenerBase):
    PROTOCOL_NAME = "modbus"
    SERVER_PORTS = (502,)

    def process_packet(self, packet) -> None:  # pragma: no cover - unused
        pass


def _listener(**overrides):
    lst = _FakeListener(interface="lo", timeout=1)
    for k, v in overrides.items():
        setattr(lst, k, v)
    return lst


# --- Tier 1: native signal --------------------------------------------------


def test_native_request_overrides_ports():
    lst = _listener()
    # Even with both endpoints on the canonical port, native wins.
    r = lst.resolve_direction(None, native=True, src_ip="a", dst_ip="b", src_port=502, dst_port=502)
    assert r.is_request and r.client_ip == "a" and r.server_ip == "b"
    assert r.confidence == "native" and not r.inferred


def test_native_response_flips_roles():
    lst = _listener()
    r = lst.resolve_direction(
        None, native=False, src_ip="srv", dst_ip="cli", src_port=9999, dst_port=8888
    )
    assert not r.is_request and r.server_ip == "srv" and r.client_ip == "cli"
    assert r.confidence == "native"


# --- Tier 2: known server port ----------------------------------------------


def test_canonical_port_request():
    lst = _listener()
    r = lst.resolve_direction(
        None, native=None, src_ip="cli", dst_ip="srv", src_port=51000, dst_port=502
    )
    assert r.is_request and r.server_ip == "srv" and r.confidence == "port"
    assert not r.inferred


def test_canonical_port_response():
    lst = _listener()
    r = lst.resolve_direction(
        None, native=None, src_ip="srv", dst_ip="cli", src_port=502, dst_port=51000
    )
    assert not r.is_request and r.server_ip == "srv" and r.confidence == "port"


# --- Tier 3: heuristic fallback ---------------------------------------------


def test_nonstandard_port_lower_port_is_server():
    lst = _listener()
    # 8502 not known -> heuristic: lower port (8502) is the server.
    r = lst.resolve_direction(
        None, native=None, src_ip="cli", dst_ip="srv", src_port=51000, dst_port=8502
    )
    assert r.is_request and r.server_ip == "srv"
    assert r.confidence == "heuristic" and r.inferred


def test_equal_ports_first_seen_is_client():
    lst = _listener()
    r1 = lst.resolve_direction(
        None, native=None, src_ip="x", dst_ip="y", src_port=4000, dst_port=4000, flow_id="F"
    )
    assert r1.is_request and r1.client_ip == "x"
    # Reverse-direction packet in the same flow: x stays the client.
    r2 = lst.resolve_direction(
        None, native=None, src_ip="y", dst_ip="x", src_port=4000, dst_port=4000, flow_id="F"
    )
    assert not r2.is_request and r2.client_ip == "x"


# --- configure_ports: user --decode-as / OVERRIDE_PREFS ----------------------


def test_user_decode_as_promotes_nonstandard_port():
    """--decode-as 'tcp.port==8502,modbus' must make 8502 a known server port."""
    lst = _listener()
    lst.configure_ports({"tcp.port==8502": "modbus", "tcp.port==1234": "mqtt"})
    assert 8502 in lst._known_server_ports
    assert 1234 not in lst._known_server_ports  # different dissector ignored
    r = lst.resolve_direction(
        None, native=None, src_ip="cli", dst_ip="srv", src_port=51000, dst_port=8502
    )
    # Now high-confidence, not an inferred heuristic guess.
    assert r.is_request and r.server_ip == "srv"
    assert r.confidence == "port" and not r.inferred


def test_override_prefs_folded_in():
    lst = _listener(OVERRIDE_PREFS={"mbtcp.tcp.port": "5020"})
    lst.configure_ports({})
    assert 5020 in lst._known_server_ports
    assert 502 in lst._known_server_ports  # canonical still present


def test_dissector_names_match_decode_as():
    """A listener whose dissector is 'ssl' picks up ssl decode-as entries."""
    lst = _listener(DISSECTOR_NAMES=("tls", "ssl"))
    lst.configure_ports({"tcp.port==8883": "ssl"})
    assert 8883 in lst._known_server_ports


# --- Coverage across every migrated listener --------------------------------


def _all_listeners_with_server_ports():
    """Discover every registered listener class that declares SERVER_PORTS."""
    import importlib

    from oida.protocols.pcap.listener_registry import LISTENER_REGISTRY

    out = []
    for name, info in sorted(LISTENER_REGISTRY.items()):
        try:
            mod = importlib.import_module(f"oida.pcap{info['module']}")
            cls = getattr(mod, info["class"])
        except Exception:
            continue
        if getattr(cls, "SERVER_PORTS", ()):  # only migrated listeners
            out.append((name, cls))
    return out


import pytest  # noqa: E402

_MIGRATED = _all_listeners_with_server_ports()


@pytest.mark.parametrize("name,cls", _MIGRATED, ids=[n for n, _ in _MIGRATED])
def test_user_decode_as_override_honored_per_listener(name, cls):
    """Every migrated listener must honour a --decode-as port override.

    Mapping a non-standard port to the listener's protocol via --decode-as must
    promote it to a known server port, so a packet on that port is classified
    (confidence 'port', not an inferred heuristic) and the server side is the
    override-port endpoint -- i.e. traffic is never dropped on a custom port.
    """
    lst = cls(interface="lo", timeout=1)
    dissector = (cls.DISSECTOR_NAMES or (cls.PROTOCOL_NAME,))[0]
    weird_port = 39999  # well outside any canonical/ephemeral overlap
    lst.configure_ports({f"tcp.port=={weird_port}": dissector})
    assert weird_port in lst._known_server_ports

    r = lst.resolve_direction(
        None,
        native=None,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=51111,
        dst_port=weird_port,
    )
    assert r.confidence == "port" and not r.inferred
    assert r.is_request and r.server_ip == "10.0.0.2" and r.client_ip == "10.0.0.1"


def test_migration_coverage_floor():
    """Guard against the discovery silently finding nothing (e.g. import break)."""
    assert len(_MIGRATED) >= 20, f"expected >=20 migrated listeners, found {len(_MIGRATED)}"
