"""Contract: CLI subprocess budgets must fit the pytest per-test timeout.

pytest-timeout kills a test at `timeout = 60` seconds (pyproject.toml, with
`timeout_func_only = true`). A test that shells out to the oida CLI with a
subprocess budget at or above that limit can never see its own assertion run:
pytest fires first, and the failure reads as ``Failed: Timeout (>60.0s)`` with
no diagnostic from the test body - exactly how the MMS CLI integration tests
failed twice in a release-gate run before the runs were bounded
(``--only-depth 1 --machine 200,1``) and the budgets dropped to 30s.

Two runners are guarded:

- ``run_fuzz_cli`` (tests/integration/fuzz/conftest.py): every call with a
  literal ``timeout=N`` must stay strictly below the ceiling.
- ``cli_runner.run`` (tests/integration/cli_runner.py): same rule.

An explicit ``@pytest.mark.timeout`` override raises the ceiling for that one
test, so the budget is checked against the override when one is present.

This is intentionally an AST walk over literals: a budget computed at runtime
cannot be checked here, but it also cannot silently regress the way a copied
literal does.
"""

import ast
import pathlib
import re

import pytest

INTEGRATION_DIR = pathlib.Path(__file__).resolve().parents[1] / "integration"
FUZZ_TEST_DIR = INTEGRATION_DIR / "fuzz"
PYPROJECT = pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml"

# Call shapes guarded: run_fuzz_cli(...) by name, cli_runner.run(...) by
# attribute path. Everything else (socket waits, docker waits) is out of
# scope - their timeouts bound waits, not a CLI subprocess.
NAMED_CALLS = {"run_fuzz_cli"}
ATTR_CALLS = {"run"}


def _pytest_timeout_from_config():
    match = re.search(r"^timeout\s*=\s*(\d+)", PYPROJECT.read_text(), re.MULTILINE)
    if not match:
        pytest.skip("no pytest timeout configured in pyproject.toml")
    return int(match.group(1))


def _iter_files():
    yield from sorted(INTEGRATION_DIR.rglob("test_*.py"))
    conftest = INTEGRATION_DIR / "conftest.py"
    if conftest.is_file():
        yield conftest
    fuzz_conftest = FUZZ_TEST_DIR / "conftest.py"
    if fuzz_conftest.is_file():
        yield fuzz_conftest


def _guarded_budgets(tree):
    """Yield (lineno, runner, budget) for guarded calls with literal timeouts."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            runner = func.id if func.id in NAMED_CALLS else None
        elif isinstance(func, ast.Attribute):
            is_runner = (
                func.attr in ATTR_CALLS
                and isinstance(func.value, ast.Name)
                and func.value.id == "cli_runner"
            )
            runner = "cli_runner.run" if is_runner else None
        else:
            runner = None
        if runner is None:
            continue
        for kw in node.keywords:
            if kw.arg == "timeout" and isinstance(kw.value, ast.Constant):
                budget = kw.value.value
                if isinstance(budget, (int, float)):
                    yield node.lineno, runner, budget


def _timeout_override(tree):
    """Return literals from @pytest.mark.timeout(N) marks in this module.

    Matches the real AST shape of ``@pytest.mark.timeout(N)``: the mark call's
    func is ``Attribute(attr='timeout')`` whose value is ``Attribute(mark)``
    hanging off ``Name(pytest)`` - not ``Name('pytest')`` directly.
    """
    overrides = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "timeout"):
            continue
        mark = func.value
        if not (isinstance(mark, ast.Attribute) and mark.attr == "mark"):
            continue
        if not (isinstance(mark.value, ast.Name) and mark.value.id == "pytest"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, float)):
                overrides.append(arg.value)
    return overrides


def _enclosing_function(tree, lineno):
    """Innermost FunctionDef whose source range contains *lineno*."""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= lineno <= (node.end_lineno or node.lineno):
                if best is None or node.lineno > best.lineno:
                    best = node
    return best


def _decorator_timeouts(func):
    """@pytest.mark.timeout(N) literals on one function's decorator list."""
    return _timeout_override(ast.Module(body=list(func.decorator_list), type_ignores=[]))


class TestCLISubprocessBudgets:
    def test_subprocess_budgets_below_pytest_timeout(self):
        ceiling = _pytest_timeout_from_config()
        violations = []

        for path in _iter_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            for lineno, runner, budget in _guarded_budgets(tree):
                enc = _enclosing_function(tree, lineno)
                local = _decorator_timeouts(enc) if enc else []
                effective = max(local) if local else ceiling
                if budget >= effective:
                    violations.append(f"{path}:{lineno} {runner} timeout={budget}")

        assert not violations, (
            "CLI subprocess budgets at or above the pytest per-test timeout "
            f"({ceiling}s, pyproject.toml; @pytest.mark.timeout overrides the "
            "ceiling per test) can never let the test's own assertions run - "
            "pytest kills the test first. Bound the work and keep the budget "
            "strictly lower, or add @pytest.mark.timeout if the scan is "
            "legitimately slow:\n" + "\n".join(violations)
        )
