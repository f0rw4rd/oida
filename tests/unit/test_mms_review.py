"""Regression test: MMSScanner._get_data_objects must respect --max-objects.

Its siblings (_discover_logical_devices, _get_logical_nodes) both bound
materialization against a hostile/misbehaving server returning an oversized
name list. _get_data_objects did not, so a single logical node could make
the scanner materialize an unbounded list into memory regardless of the
operator's --max-objects setting.
"""

from oida.protocols.mms import MMSScanner


class _HugeNameListConnection:
    """Fake connection whose get_data_objects is a generator yielding far
    more entries than the configured cap.

    Tracks how many items were actually pulled from the generator so the
    test can prove the loop short-circuits instead of consuming everything.
    """

    def __init__(self, total: int):
        self.total = total
        self.yielded = 0

    def get_data_objects(self, device_name, ln_name):
        for i in range(self.total):
            self.yielded += 1
            yield f"DO{i}"


def test_get_data_objects_bounded_by_max_objects():
    scanner = MMSScanner({"rhost": "127.0.0.1", "rport": 102, "max-objects": 5})
    conn = _HugeNameListConnection(total=100_000)

    result = scanner._get_data_objects(conn, "device1", "ln1")

    assert len(result) <= scanner.max_objects, (
        f"expected at most {scanner.max_objects} data objects, got {len(result)}"
    )
    # Prove the generator was short-circuited rather than fully consumed.
    # (The `for x in gen: if len(...) >= cap: break` pattern used by the
    # sibling methods pulls one extra item off the generator before the
    # bound check fires, so allow that same one-item slack.)
    assert conn.yielded <= scanner.max_objects + 1, (
        f"generator was drained past the cap: pulled {conn.yielded} items"
    )
