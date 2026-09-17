"""importlib.metadata must be queried with the DISTRIBUTION name, not the import name.

The import package is ``oida``; the PyPI distribution is ``oida-ics`` (pyproject
explains the bare name was taken). ``importlib.metadata`` keys off the
distribution, so ``metadata("oida")`` raises ``PackageNotFoundError``.

That is not hypothetical: the ``oida`` -> ``oida-ics`` rename updated the
user-facing ``pip install`` strings but left the metadata lookups alone. The
result went unnoticed because ``lazy_import`` swallowed the exception -- every
install silently had ``PROTOCOL_DEPENDENCIES == {}``, so dependency hints,
install suggestions and ``_KNOWN_PROTOCOLS`` were all dead, and ``oida.spec``
crashed the PyInstaller build outright.

Other suites catch this only as a side effect (an empty protocol list). These
tests name the invariant directly, so the next rename fails with a message that
says what actually broke.
"""

import re
import tomllib
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Any importlib.metadata accessor called with the *import* package name.
BAD_LOOKUP = re.compile(r"""\b(?:requires|metadata|version|distribution)\(\s*["']oida["']\s*\)""")

SEARCH_ROOTS = [REPO_ROOT / "src", REPO_ROOT / "oida.spec"]


def _project_name() -> str:
    with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["name"]


def test_resolved_dist_name_is_the_installed_distribution():
    from oida.utils.lazy_import import _resolve_dist_name

    name = _resolve_dist_name()
    assert name == _project_name()
    distribution(name)  # raises PackageNotFoundError if we resolved a fiction


def test_protocol_dependencies_is_populated():
    """The symptom the rename produced: silently empty, in every install."""
    from oida.utils.lazy_import import PROTOCOL_DEPENDENCIES

    assert PROTOCOL_DEPENDENCIES, (
        "PROTOCOL_DEPENDENCIES is empty -- package metadata lookup failed. "
        "Dependency hints and install suggestions are dead."
    )


def test_import_name_is_not_a_valid_distribution():
    """Guards the premise. If this ever fails, the bug class is gone."""
    with pytest.raises(PackageNotFoundError):
        distribution("oida")


def _python_sources():
    for root in SEARCH_ROOTS:
        if root.is_file():
            yield root
        else:
            yield from root.rglob("*.py")


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment.

    Crude but sufficient here: the point is that prose *describing* the bug
    (including this module's own docstrings) must not be reported as the bug.
    A ``#`` inside a string literal would truncate early, which can only cause a
    false negative on the same line, never a false positive.
    """
    return line.split("#", 1)[0]


@pytest.mark.parametrize("path", sorted(_python_sources()), ids=lambda p: str(p.name))
def test_no_metadata_lookup_uses_the_import_name(path):
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()}"
        for i, line in enumerate(path.read_text().splitlines(), 1)
        if BAD_LOOKUP.search(_strip_comment(line))
    ]
    assert not offenders, (
        "importlib.metadata called with the import name 'oida'; use the "
        "distribution name via _resolve_dist_name():\n" + "\n".join(offenders)
    )
