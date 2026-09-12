"""Regression test: G6 review finding.

DICOM_CStore_UID_Traversal used to place the Windows/deep-traversal payload
alternatives in a *separate sibling* Group block placed directly after the
AffectedSOPInstanceUID SmartString field. Because Request children render
sequentially/concatenated, and boofuzz mutates one primitive at a time
(holding all siblings at their default value), every non-baseline Group
mutation was rendered as the *default unix traversal string with the
alternate payload appended immediately after it* -- e.g. the "Windows-style"
test case never actually reached the wire as a clean
``..\\..\\..\\..\\windows\\win.ini`` value; it appeared as
``../../../../etc/passwd..\\..\\..\\..\\windows\\win.ini``, garbling the test
intent for 3 of 4 declared variants (only the first, empty-string Group
value happened to look correct because it left the SmartString value
untouched).

Fix: the alternate traversal strings are now passed as ``fuzz_values`` on
the SmartString primitive itself, so each one is mutated in as a
standalone, clean value for the AffectedSOPInstanceUID element -- not
appended after a sibling field's unrelated default content.
"""

from boofuzz.mutation_context import MutationContext

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections.base import MockConnectionFactory
from oida.fuzz.protocols.dicom import DICOMFuzzer

EXPECTED_VARIANTS = {
    b"..\\..\\..\\..\\windows\\win.ini",
    b"../../../../../../etc/shadow",
    b"....//....//etc/passwd",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=104,
        protocol_type=ProtocolType.TCP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build_cstore_request():
    config = _make_config(enabled_requests=["DICOM_CStore_UID_Traversal"])
    fuzzer = DICOMFuzzer(config=config, connection_factory=MockConnectionFactory())
    session = fuzzer.session
    for node in session.nodes.values():
        if node.name == "DICOM_CStore_UID_Traversal":
            return node
    raise AssertionError("DICOM_CStore_UID_Traversal not connected")


def test_traversal_variants_reach_wire_as_clean_standalone_values():
    """Every declared traversal variant must appear in SOME rendered mutation
    of the AffectedSOPInstanceUID element as a clean, standalone value --
    not concatenated after the default unix traversal string.
    """
    req = _build_cstore_request()

    fld = None
    for child in req.walk():
        if getattr(child, "name", None) == "affected_sop_instance_uid":
            fld = child
            break
    assert fld is not None, "affected_sop_instance_uid field not found"

    # affected_sop_instance_uid is the LAST child rendered in this Request, so
    # whatever value it takes must be an exact trailing slice of the full
    # rendered PDU -- i.e. data.endswith(mutated_value). This sidesteps having
    # to hand-parse DICOM element/length encoding.
    found_variants = set()
    for mutation in fld.get_mutations():
        m = mutation[0]
        value = m.value
        if callable(value) or not isinstance(value, (bytes, bytearray)):
            continue
        ctx = MutationContext(mutations={fld.qualified_name: m})
        data = req.render(mutation_context=ctx)
        assert data.endswith(bytes(value)), (
            f"expected rendered request to end with the mutated field value "
            f"{bytes(value)!r}, got tail {data[-60:]!r}"
        )
        if bytes(value) in EXPECTED_VARIANTS:
            found_variants.add(bytes(value))

    assert found_variants == EXPECTED_VARIANTS, (
        f"not all declared traversal variants reached the wire as a clean, "
        f"standalone UID value: missing {EXPECTED_VARIANTS - found_variants!r}"
    )
