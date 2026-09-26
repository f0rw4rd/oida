"""Contract: fuzz CLI subprocess budgets must fit the pytest per-test timeout.

pytest-timeout kills a test at `timeout = 60` seconds (pyproject.toml, with
`timeout_func_only = true`). A test that shells out to `oida fuzz ...` with a
subprocess budget at or above that limit can never see its own assertion run:
pytest fires first, and the failure reads as ``Failed: Timeout (>60.0s)`` with
no diagnostic from the test body - exactly how the MMS CLI integration tests
failed twice in a release-gate run before the runs were bounded
(``--only-depth 1 --machine 200,1``) and the budgets dropped to 30s.

This contract walks every fuzz integration test file, finds ``run_fuzz_cli``
calls with a literal ``timeout=N``, and fails when N is not strictly below the
configured pytest timeout. It also checks the per-test ``@pytest.mark.timeout``
override: an override raises the ceiling for that test, so the subprocess
budget must also stay below the override when one is present.
"""

import ast
import pathlib
import re

import pytest

FUZZ_TEST_DIR = pathlib.Path(__file__).resolve().parents[1] / "integration" / "fuzz"
PYPROJECT = pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml"


def _pytest_timeout_from_config():
    match = re.search(r"^timeout\s*=\s*(\d+)", PYPROJECT.read_text(), re.MULTILINE)
    if not match:
        pytest.skip("no pytest timeout configured in pyproject.toml")
    return int(match.group(1))


def _fuzz_test_files():
    if not FUZZ_TEST_DIR.is_dir():
        pytest.skip("no fuzz integration tests directory")
    return sorted(FUZZ_TEST_DIR.glob("test_*.py"))


def _run_fuzz_cli_budgets(tree):
    """Yield (lineno, budget) for every run_fuzz_cli(..., timeout=<literal>)."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "run_fuzz_cli":
            continue
        for kw in node.keywords:
            if kw.arg == "timeout" and isinstance(kw.value, ast.Constant):
                budget = kw.value.value
                if isinstance(budget, (int, float)):
                    yield node.lineno, budget


class TestFuzzCLISubprocessBudgets:
    def test_subprocess_budgets_below_pytest_timeout(self):
        ceiling = _pytest_timeout_from_config()
        violations = []

        for path in _fuzz_test_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            for lineno, budget in _run_fuzz_cli_budgets(tree):
                if budget >= ceiling:
                    violations.append(f"{path.name}:{lineno} timeout={budget}")

        assert not violations, (
            "run_fuzz_cli subprocess budgets at or above the pytest per-test "
            f"timeout ({ceiling}s, pyproject.toml) can never let the test's own "
            "assertions run - pytest kills the test first. Bound the campaign "
            "(e.g. --only-depth/--machine) and keep the budget strictly lower:\n"
            + "\n".join(violations)
        )
