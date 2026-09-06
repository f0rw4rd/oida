"""Verify the pymodbus slave= -> device_id= migration is complete.

CODE_REVIEW.md CRITICAL modbus. Static check that no remaining
'slave=' kwargs appear in src/oida/protocols/modbus/ or its tests.
"""

import pathlib
import re
import unittest


SRC = pathlib.Path("src/oida/protocols/modbus")
TESTS = pathlib.Path("tests/unit/modbus")


class TestSlaveKwargMigration(unittest.TestCase):
    def test_no_slave_kwarg_in_src(self):
        offenders = []
        for f in SRC.rglob("*.py"):
            for i, line in enumerate(f.read_text().splitlines(), 1):
                # Skip false positives (comments mentioning 'slave', etc.)
                if re.search(r"\bslave\s*=", line) and "device_id" not in line:
                    # Allow string mentions of 'slave' in docstrings/comments.
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith('"'):
                        continue
                    offenders.append(f"{f}:{i}: {line.strip()}")
        self.assertFalse(
            offenders,
            "Found unmigrated slave= kwargs:\n" + "\n".join(offenders),
        )

    def test_no_slave_kwarg_in_tests(self):
        offenders = []
        for f in TESTS.rglob("*.py"):
            # Skip THIS file - it has 'slave=' inside regex / docstring.
            if f.name == "test_pymodbus_migration_complete.py":
                continue
            for i, line in enumerate(f.read_text().splitlines(), 1):
                if re.search(r"\bslave\s*=", line) and "device_id" not in line:
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith('"'):
                        continue
                    offenders.append(f"{f}:{i}: {line.strip()}")
        self.assertFalse(
            offenders,
            "Found unmigrated slave= kwargs in tests:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
