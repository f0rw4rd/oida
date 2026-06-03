"""Contract: uv.lock must be in sync with pyproject.toml.

When a developer edits dependencies in pyproject.toml without
re-running `uv lock`, the lockfile drifts. CI installs from the
lockfile (`uv sync --frozen`) so drift causes silent version
inconsistencies between dev and CI environments.

This contract runs `uv lock --check` (or the equivalent `--dry-run`
behavior) which exits non-zero when the lockfile needs an update.

Skipped gracefully when uv isn't installed (so a contributor without
uv on PATH can still run the wider test suite).
"""

import shutil
import subprocess
import unittest

import pytest


@pytest.fixture(scope="module")
def uv_path():
    path = shutil.which("uv")
    if not path:
        pytest.skip("uv not installed (install via `pip install uv`)")
    return path


class TestUvLockfileInSync:
    def test_lock_check_passes(self, uv_path):
        """`uv lock --check` must exit 0 — lockfile is in sync."""
        # `uv lock --check` was added in uv 0.5.0; works in 0.11.x.
        # The `--frozen` alternative is more conservative (errors on any
        # lockfile change) but --check is the explicit drift test.
        result = subprocess.run(
            [uv_path, "lock", "--check"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(
                "uv.lock is out of date with pyproject.toml. "
                "Run `uv lock` and commit the updated uv.lock.\n\n"
                f"stderr:\n{result.stderr}\n\n"
                f"stdout:\n{result.stdout}"
            )


class TestLockfileShape(unittest.TestCase):
    """Source-level sanity: uv.lock has the expected top-level shape."""

    def test_lockfile_exists(self):
        import pathlib

        self.assertTrue(
            pathlib.Path("uv.lock").exists(),
            "uv.lock must be committed — it's the source of truth for CI installs",
        )

    def test_lockfile_pins_oida(self):
        import pathlib

        content = pathlib.Path("uv.lock").read_text()
        self.assertIn('name = "oida"', content, "uv.lock must include the oida package itself")

    def test_lockfile_records_requires_python(self):
        import pathlib

        content = pathlib.Path("uv.lock").read_text()
        self.assertIn('requires-python = ">=3.10"', content)

    def test_lockfile_includes_core_deps(self):
        """Spot-check: lockfile names at least 50 packages (full env is ~300)."""
        import pathlib

        content = pathlib.Path("uv.lock").read_text()
        package_count = content.count("[[package]]")
        self.assertGreater(
            package_count, 50,
            f"uv.lock has only {package_count} packages — full env is ~300; "
            "lockfile is likely incomplete",
        )


if __name__ == "__main__":
    unittest.main()
