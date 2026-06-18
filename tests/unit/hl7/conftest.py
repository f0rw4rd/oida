import pytest


def pytest_collection_modifyitems(items):
    """Mark all HL7 tests as network-dependent.

    HL7 NXC-style classes trigger proto_flow() -> socket.connect() on instantiation.
    """
    for item in items:
        if "/hl7/" in str(item.fspath):
            item.add_marker(pytest.mark.network)
