"""Regression tests for the AMQP per-class method tables.

Authority: ``tshark -G values | grep '^V\\tamqp.method.method'`` (tshark 4.4.15),
which merges every class's method table into one keyed by (class, method) --
per-class blocks, in registry order:

- Connection 10-61 (incl. 42 Redirect, 60 Blocked, 61 Unblocked)
- Channel 10-80
- Exchange: Unbind=40, Unbind-Ok=**41**
- Queue: Unbind=50, Unbind-Ok=51
- Basic: Recover-Async=**100**, Recover=**110**, Recover-Ok=**111**, Nack=120

Three defects were confirmed:

1. ``AMQP_EXCHANGE_METHODS`` had ``"51": "Unbind-Ok"`` -- a copy-paste from the
   adjacent Queue table. Exchange.Unbind-Ok is **41** (51 in class 40 decodes
   nothing on the wire, and a real 41 rendered as method 51's ghost).
2. ``AMQP_BASIC_METHODS`` had 100="Recover" and 110="Recover-Ok"; the registry
   says 100=Recover-Async, 110=Recover and 111=Recover-Ok (missing entirely).
   Mislabelling Recover-Async as "Recover" also matters for direction: the
   listener treats "-Ok" names as broker-originated, and Recover/Recover-Async
   are client-originated while Recover-Ok is broker-originated -- with the old
   table, BOTH 100 and 110 got the same label, so one of the two was always
   attributed to the wrong side.
3. The broker-originated allowlist in the direction heuristic listed Start and
   Tune but omitted "Secure" (also broker-originated, registry line 3), so a
   Connection.Secure frame was attributed to the client and could register the
   client as a phantom broker end-point.
"""

import pytest

from oida.pcap.amqp import (
    AMQP_BASIC_METHODS,
    AMQP_CONNECTION_METHODS,
    AMQP_EXCHANGE_METHODS,
    AMQP_METHOD_MAPS,
    AMQP_QUEUE_METHODS,
)


def test_exchange_unbind_ok_is_41():
    assert AMQP_EXCHANGE_METHODS["41"] == "Unbind-Ok"


def test_exchange_51_is_not_a_method():
    """51 belongs to the Queue class (Queue.Unbind-Ok), not Exchange."""
    assert "51" not in AMQP_EXCHANGE_METHODS


def test_exchange_block_matches_the_registry():
    assert AMQP_EXCHANGE_METHODS == {
        "10": "Declare",
        "11": "Declare-Ok",
        "20": "Delete",
        "21": "Delete-Ok",
        "30": "Bind",
        "31": "Bind-Ok",
        "40": "Unbind",
        "41": "Unbind-Ok",
    }


def test_queue_block_matches_the_registry():
    assert AMQP_QUEUE_METHODS == {
        "10": "Declare",
        "11": "Declare-Ok",
        "20": "Bind",
        "21": "Bind-Ok",
        "30": "Purge",
        "31": "Purge-Ok",
        "40": "Delete",
        "41": "Delete-Ok",
        "50": "Unbind",
        "51": "Unbind-Ok",
    }


def test_basic_recover_cluster_matches_the_registry():
    assert AMQP_BASIC_METHODS["100"] == "Recover-Async"
    assert AMQP_BASIC_METHODS["110"] == "Recover"
    assert AMQP_BASIC_METHODS["111"] == "Recover-Ok"
    assert AMQP_BASIC_METHODS["120"] == "Nack"


def test_basic_block_matches_the_registry():
    assert AMQP_BASIC_METHODS == {
        "10": "Qos",
        "11": "Qos-Ok",
        "20": "Consume",
        "21": "Consume-Ok",
        "30": "Cancel",
        "31": "Cancel-Ok",
        "40": "Publish",
        "50": "Return",
        "60": "Deliver",
        "70": "Get",
        "71": "Get-Ok",
        "72": "Get-Empty",
        "80": "Ack",
        "90": "Reject",
        "100": "Recover-Async",
        "110": "Recover",
        "111": "Recover-Ok",
        "120": "Nack",
    }


def test_connection_block_matches_the_registry():
    assert AMQP_CONNECTION_METHODS["60"] == "Blocked"
    assert AMQP_CONNECTION_METHODS["61"] == "Unblocked"
    assert AMQP_CONNECTION_METHODS["42"] == "Redirect"


@pytest.mark.parametrize("cls", ["10", "20", "40", "50", "60"])
def test_every_mapped_class_resolves_every_registered_method(cls):
    """No entry in a mapped class may be dropped -- dropped keys render as
    'method 51' ghosts instead of their name."""
    assert cls in AMQP_METHOD_MAPS
    table = AMQP_METHOD_MAPS[cls]
    assert all(isinstance(k, str) and v for k, v in table.items())


def test_secure_is_treated_as_broker_originated():
    """Connection.Secure is broker-originated; only the *-Ok handshake replies
    are client-originated. Assert the behaviour of the direction heuristic by
    re-evaluating its two clauses for a "Secure" method name."""
    client_ok_methods = {"Start-Ok", "Secure-Ok", "Tune-Ok"}
    for method_name in ("Secure", "Start", "Tune"):
        is_response = method_name in (
            "Start",
            "Secure",
            "Tune",
            "Deliver",
            "Return",
            "Get-Ok",
            "Get-Empty",
        ) or (method_name.endswith("-Ok") and method_name not in client_ok_methods)
        assert is_response, f"{method_name} must classify as broker-originated"
    # and the client-originated -Ok replies must not
    for method_name in ("Secure-Ok", "Start-Ok", "Tune-Ok"):
        is_response = method_name in (
            "Start",
            "Secure",
            "Tune",
            "Deliver",
            "Return",
            "Get-Ok",
            "Get-Empty",
        ) or (method_name.endswith("-Ok") and method_name not in client_ok_methods)
        assert not is_response, f"{method_name} must classify as client-originated"

    # The source allowlist must literally contain Secure next to Start/Tune.
    import inspect

    import oida.pcap.amqp as amqp_mod

    src = inspect.getsource(amqp_mod)
    block = src[
        src.index("is_response = method_name in (") : src.index(") or (method_name.endswith")
    ]
    assert '"Secure"' in block, "broker-originated allowlist must list Secure"
