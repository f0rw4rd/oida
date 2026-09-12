"""Regression tests for MMS passive-listener correctness bugs.

Two bugs found in the pcap bug hunt:

1. ``_has_layer_field`` returned ``layer.has_field(name)`` directly whenever
   the layer had a ``has_field`` attribute.  XML-mode layers *do* have one, but
   it reports False for zero-length ASN.1 ``*_element`` marker fields even
   though the key is present in ``layer._all_fields`` -- so the helper's own
   documented XML fallback was unreachable, and every PDU-type branch keyed off
   such a marker was dead on the live-capture path (``pyshark_base`` builds
   LiveCapture without ``use_ek``, i.e. XML mode).  All 29 Initiate PDUs in the
   MMS fixture corpus were classified as generic "MMS PDU" in XML mode.

   Note the prior diagnosis of this area -- "pyshark lowercases the field
   names, so the mixed-case literals are dead" -- was wrong: the names really
   are mixed case (``initiate_RequestPDU_element``) in both modes, and
   lowercasing them breaks EK mode.  ``test_mixed_case_literals_are_correct``
   pins that down so nobody "fixes" it that way again.

2. The responding-direction credential dedup passed ``(src_ip, dst_ip)`` to
   ``_is_duplicate`` while storing ``client_ip=dst_ip, server_ip=src_ip``, so
   the key never matched and the same credential was re-appended for every
   responding packet in an association.
"""

import asyncio
import datetime

import pytest

from .conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

FIXTURE = ("mms", "iti_mms-confirmedRequestPDU.pcap")


def _feed(pcap_path, use_ek):
    """Run the MMS listener over *pcap_path* in the requested pyshark mode."""
    import pyshark

    from oida.pcap.mms import MMSPassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    kwargs = {"input_file": str(pcap_path), "display_filter": "mms"}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    listener = MMSPassiveListener(interface="lo", timeout=10)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener.feed_packets(iter(packets))
    return listener, packets


def _ek_available():
    from .conftest import _ek_mode_available

    return _ek_mode_available


class TestHasLayerFieldXmlMode:
    """Bug 1: marker-element detection must work in XML mode too."""

    def test_mixed_case_literals_are_correct(self):
        """Guard against a well-meaning 'lowercase the field names' regression.

        tshark really does expose these ASN.1 elements in mixed case; the
        lowercase spelling matches nothing.
        """
        _skip_unless_pyshark()
        if not _ek_available():
            pytest.skip("pyshark EK-mode fork not installed")
        pcap = _pcap_path(*FIXTURE)
        _, packets = _feed(pcap, use_ek=True)
        names = set()
        for pkt in packets:
            layer = getattr(pkt, "mms", None)
            if layer is not None:
                names.update(getattr(layer, "all_field_names", None) or [])
        assert "initiate_RequestPDU_element" in names, (
            f"expected the mixed-case ASN.1 element name; saw {sorted(names)[:20]}"
        )
        assert "initiate_requestpdu_element" not in names, (
            "pyshark does NOT lowercase MMS field names -- do not lowercase the literals in mms.py"
        )

    def test_marker_element_detected_in_xml_mode(self):
        """The precise mechanism: has_field() is False but _all_fields has it."""
        _skip_unless_pyshark()
        from oida.pcap.mms import MMSPassiveListener

        pcap = _pcap_path(*FIXTURE)
        _, packets = _feed(pcap, use_ek=False)
        listener = MMSPassiveListener(interface="lo", timeout=10)

        checked = False
        for pkt in packets:
            layer = getattr(pkt, "mms", None)
            if layer is None:
                continue
            all_fields = getattr(layer, "_all_fields", None) or {}
            for key in all_fields:
                if key.endswith("_element"):
                    short = key.split(".", 1)[-1]
                    checked = True
                    assert listener._has_layer_field(layer, short), (
                        f"_has_layer_field missed {short!r} even though "
                        f"_all_fields contains {key!r}"
                    )
        assert checked, "fixture exposed no ASN.1 *_element marker fields to check"

    def test_xml_mode_classifies_initiate_like_ek_mode(self):
        """End-to-end: the two pyshark modes must agree on operations."""
        _skip_unless_pyshark()
        if not _ek_available():
            pytest.skip("pyshark EK-mode fork not installed")
        pcap = _pcap_path(*FIXTURE)

        xml_listener, _ = _feed(pcap, use_ek=False)
        ek_listener, _ = _feed(pcap, use_ek=True)

        def ops(listener):
            counts = {}
            for ix in listener.interactions:
                counts[ix.operation] = counts.get(ix.operation, 0) + 1
            return counts

        xml_ops, ek_ops = ops(xml_listener), ops(ek_listener)
        assert xml_ops == ek_ops, (
            f"XML mode (the live-capture path) classifies differently from EK mode:\n"
            f"  xml={xml_ops}\n  ek ={ek_ops}"
        )
        # Before the fix the XML side lost this entirely.
        assert not any("unrecognized" in (op or "").lower() for op in xml_ops), (
            f"MMS PDUs falling through to the unrecognized bucket: {xml_ops}"
        )


class TestRespondingCredentialDedup:
    """Bug 2: responding-direction dedup key orientation.

    No MMS fixture in tests/fixtures/pcap/mms/ carries an ACSE authentication
    value (credentials == 0 across all 26 of them in both pyshark modes), so
    this drives the store/lookup pair directly rather than through a capture.
    """

    @staticmethod
    def _record(listener, direction, src_ip, dst_ip):
        """Mirror exactly what _handle_acse_auth stores for *direction*."""
        from oida.pcap.mms import MMSCredential

        if direction == "responding":
            lookup = (dst_ip, src_ip)
            server_ip, client_ip = src_ip, dst_ip
        else:
            lookup = (src_ip, dst_ip)
            server_ip, client_ip = dst_ip, src_ip

        if listener._is_duplicate("s3cr3t", direction, *lookup):
            return
        listener.credentials.append(
            MMSCredential(
                auth_value="s3cr3t",
                auth_direction=direction,
                credential_type="plaintext",
                mechanism_name="mech",
                server_ip=server_ip,
                client_ip=client_ip,
                timestamp=datetime.datetime.now(),
            )
        )

    @pytest.mark.parametrize("direction", ["calling", "responding"])
    def test_identical_credential_recorded_once(self, direction):
        from oida.pcap.mms import MMSPassiveListener

        listener = MMSPassiveListener(interface="lo", timeout=10)
        for _ in range(5):
            self._record(listener, direction, "10.0.0.1", "10.0.0.2")

        # Before the fix the "responding" case produced 5.
        assert len(listener.credentials) == 1, (
            f"{direction} credential re-recorded {len(listener.credentials)} times; "
            f"the dedup lookup and the stored record disagree on client/server orientation"
        )

    def test_distinct_peers_still_recorded_separately(self):
        """The fix must not over-deduplicate across different associations."""
        from oida.pcap.mms import MMSPassiveListener

        listener = MMSPassiveListener(interface="lo", timeout=10)
        self._record(listener, "responding", "10.0.0.1", "10.0.0.2")
        self._record(listener, "responding", "10.0.0.1", "10.0.0.3")
        assert len(listener.credentials) == 2, (
            "credentials from different clients were collapsed into one"
        )


class TestRespondingCredentialDedupRealHandler:
    """Bug 2 again, but through the real ``_extract_acse_auth`` handler.

    ``TestRespondingCredentialDedup`` mirrors the store/lookup pair by hand,
    which would keep passing if the handler drifted from the mirror.  These
    tests drive the production handler directly with a minimal fake ACSE
    layer (attribute access only, exactly what ``get_field`` uses), so the
    dedup fix is exercised end to end: extraction -> orientation -> dedup ->
    storage.  No MMS fixture carries an ACSE auth value, so this is the only
    way to hit the branch from a test.

    All of these run in the plain (no-pyshark-layer) mode; the handler's
    dedup logic is mode-independent because it sits downstream of get_field.
    """

    @staticmethod
    def _fake_acse(auth_value, direction, mechanism=""):
        layer = type("Acse", (), {})()
        if auth_value:
            setattr(layer, "charstring", auth_value)
        setattr(layer, "mechanism_name", mechanism)
        if direction == "calling":
            setattr(layer, "calling_authentication_value", "1")
        else:
            setattr(layer, "responding_authentication_value", "1")
        return layer

    @classmethod
    def _feed(cls, listener, direction, src_ip="10.101.1.3", dst_ip="10.101.1.2", auth="s3cr3t"):
        from oida.pcap.mms import MMSPassiveListener  # noqa: F401  (import sanity)

        listener._extract_acse_auth(
            cls._fake_acse(auth, direction),
            src_ip,
            dst_ip,
            "2026-01-01T00:00:00",
            "flow-1",
            src_port=49152,
            dst_port=102,
            stream_id="7",
        )

    def test_responding_credential_deduped_across_repeated_aare(self):
        """An association's AARE retransmissions must yield ONE credential.

        Before the dedup-orientation fix this produced one credential per
        responding packet in the association.
        """
        from oida.pcap.mms import MMSPassiveListener

        listener = MMSPassiveListener(interface="lo", timeout=10)
        for _ in range(5):
            self._feed(listener, "responding")

        assert len(listener.credentials) == 1, (
            f"responding credential re-recorded {len(listener.credentials)} times "
            f"by _extract_acse_auth: {[c.auth_value for c in listener.credentials]}"
        )

    def test_responding_credential_orientation(self):
        """The responding branch records the SERVER as src_ip.

        src_ip is the AARE sender (the server); the credential must therefore
        carry server_ip=src_ip / client_ip=dst_ip, which is also what makes the
        dedup lookup agree with the stored record.
        """
        from oida.pcap.mms import MMSPassiveListener

        listener = MMSPassiveListener(interface="lo", timeout=10)
        self._feed(listener, "responding", src_ip="10.101.1.2", dst_ip="10.101.1.3")

        assert len(listener.credentials) == 1
        cred = listener.credentials[0]
        assert cred.server_ip == "10.101.1.2"
        assert cred.client_ip == "10.101.1.3"
        assert cred.auth_direction == "responding"

    def test_calling_and_responding_of_same_value_both_kept(self):
        """Two directions are two credentials; the fix must not over-dedup."""
        from oida.pcap.mms import MMSPassiveListener

        listener = MMSPassiveListener(interface="lo", timeout=10)
        self._feed(listener, "calling", auth="s3cr3t")
        self._feed(listener, "responding", auth="s3cr3t")
        assert len(listener.credentials) == 2

    def test_credentials_summary_survives_dedup(self):
        """get_credentials_summary() sees the single deduped credential."""
        from oida.pcap.mms import MMSPassiveListener

        listener = MMSPassiveListener(interface="lo", timeout=10)
        for _ in range(3):
            self._feed(listener, "responding")
        summary = listener.get_credentials_summary()
        assert len(summary) == 1
        assert summary[0]["username"] == "s3cr3t"
        assert summary[0]["auth_direction"] == "responding"
        assert summary[0]["protocol"] == "MMS/ACSE"
