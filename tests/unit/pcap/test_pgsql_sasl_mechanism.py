"""Regression test: PGSQL SASL mechanism field name must use underscores.

The AUTH_SASL
branch read the mechanism via
`self.get_field(pgsql_layer, "auth.sasl.mech", "")`. get_field() resolves
field names with `getattr(layer, field_name)`, and a Python attribute name
can never contain dots, so the dotted form silently never matched and the
`sasl_mechanism` detail was never populated. The pyshark/EK field is the
underscore form `auth_sasl_mech` (consistent with every other field in this
file, e.g. `version_major`).

These tests drive `_handle_auth_request_msg()` directly with a lightweight
fake layer (no pyshark / tshark needed) and assert the SASL mechanism is
captured under the underscore field name and would have been missed under
the dotted name.
"""

from oida.pcap.pgsql import AUTH_SASL, PostgreSQLPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _make_listener():
    return PostgreSQLPassiveListener(interface="lo", timeout=1)


def _drive_auth_sasl(listener, layer):
    listener._handle_auth_request_msg(
        now="2026-01-01T00:00:00",
        client_ip="10.0.0.5",
        client_port=54321,
        server_ip="10.0.0.10",
        server_port=5432,
        server_mac="aa:bb:cc:dd:ee:ff",
        pgsql_layer=layer,
        fields={},
        flow_id="0",
    )


def _last_sasl_interaction(listener):
    sasl = [ix for ix in listener.interactions if "(SASL)" in ix.operation]
    assert sasl, "AUTH_SASL request produced no interaction"
    return sasl[-1]


def test_sasl_mechanism_extracted_from_underscore_field():
    """auth_sasl_mech (underscore form) populates the sasl_mechanism detail."""
    listener = _make_listener()
    layer = _Layer(authtype=str(AUTH_SASL), auth_sasl_mech="SCRAM-SHA-256")

    _drive_auth_sasl(listener, layer)

    ix = _last_sasl_interaction(listener)
    assert ix.details.get("sasl_mechanism") == "SCRAM-SHA-256"


def test_dotted_field_name_would_not_resolve():
    """The old dotted name 'auth.sasl.mech' can never resolve via getattr.

    A layer that only exposes the dotted attribute name (and not the
    underscore form) must yield no sasl_mechanism detail, proving the bug the
    fix addresses.
    """
    listener = _make_listener()
    layer = _Layer(authtype=str(AUTH_SASL))
    # Set a dotted attribute the only way possible (not reachable by getattr).
    setattr(layer, "auth.sasl.mech", "SCRAM-SHA-256")

    _drive_auth_sasl(listener, layer)

    ix = _last_sasl_interaction(listener)
    assert "sasl_mechanism" not in ix.details
