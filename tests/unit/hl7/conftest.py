"""Shared helpers for HL7 unit tests.

HL7 NXC-style classes auto-run ``proto_flow()`` in the base ``__init__``
(``oida.connection.connection.__init__``), and ``proto_flow()`` opens a
real MLLP socket. Constructing ``hl7(args, db, host)`` directly therefore
makes a real network connection attempt.

``_make_hl7_instance`` builds an ``hl7`` instance WITHOUT connecting, by
patching out ``proto_flow`` and the base ``NetworkConnection.__init__`` and
constructing via ``__new__`` (mirrors ``tests/unit/ads/test_cli_runner.py``).
The attributes it sets reproduce the post-``__init__`` / post-``proto_flow``
state the tests rely on (e.g. a real ``segment_builder`` and a ``results``
dict with a ``data`` key), so callers can keep doing
``scanner.conn = MockSocket()`` / ``scanner.logger = Mock()`` afterward.
"""

from unittest.mock import Mock, patch


def _make_hl7_instance(args=None, db=None, host="192.168.1.100", **overrides):
    """Build an ``hl7`` NXC instance with ``proto_flow`` disabled (no socket).

    Drop-in for the old ``hl7(args, db, host)`` constructor calls in the
    unit tests: same positional signature, but never connects.

    Args:
        args: parsed-args object (usually a Mock); defaults to a bare Mock.
        db: database handle (tests pass None).
        host: target host string; also used as the resolved ``ip``.
        **overrides: extra attributes to set / replace on the instance.
    """
    with patch("oida.protocols.hl7.hl7.proto_flow"):
        with patch(
            "oida.connection.NetworkConnection.__init__",
            return_value=None,
        ):
            from oida.protocols.hl7 import hl7 as Hl7Class
            from oida.protocols.hl7.segments import HL7SegmentBuilder

            obj = Hl7Class.__new__(Hl7Class)

            # Mirror hl7.__init__ attribute setup.
            obj.protocol_name = "hl7"
            obj.default_port = 2575
            obj.all_responses = []
            obj.detected_version = None

            # Mirror base connection.__init__ state.
            obj.args = args if args is not None else Mock()
            obj.db = db
            obj.host = host
            obj.hostname = host
            obj.ip = host
            obj.conn = None
            obj.logger = Mock()
            obj.results = {
                "host": host,
                "ip": host,
                "protocol": "hl7",
                "port": getattr(obj.args, "port", None) or 2575,
                "success": None,
                "data": {},
            }

            # Mirror proto_flow() side effect: a real segment builder so the
            # message-creation helpers work without running proto_flow.
            obj.segment_builder = HL7SegmentBuilder(version="2.5")

            for key, val in overrides.items():
                setattr(obj, key, val)
            return obj
