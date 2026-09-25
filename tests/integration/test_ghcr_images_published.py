"""Verify the core mock images are published on GHCR (ghcr.io/f0rw4rd).

The expected image set is derived from ``docker/mocks/compose.yml`` - the single
source of truth for the core mocks - so this test tracks the real ``image:``
refs and needs no hand-maintained list.

By default it asserts each core image is **anonymously pullable**, which proves
both presence AND public visibility (the end state we want: users pull the
mocks without auth). GHCR keeps new packages private until they are flipped
public by hand, so while that flip is pending set ``OIDA_GHCR_ALLOW_PRIVATE=1``
to fall back to an authenticated presence check (token read from
``~/.docker/config.json``) - the test then passes on a *present* image
regardless of visibility.

Marked ``network`` so it is excluded from the default run (``-m 'not network'``).
Run it explicitly::

    pytest -m network tests/integration/test_ghcr_images_published.py
    OIDA_GHCR_ALLOW_PRIVATE=1 pytest -m network \
        tests/integration/test_ghcr_images_published.py
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests.service_gate import require_service

pytestmark = pytest.mark.network

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_CORE = REPO_ROOT / "docker" / "mocks" / "compose.yml"

# Namespace the core images are published under: ghcr.io/<namespace>/oida-mock-*
GHCR_NAMESPACE = os.environ.get("OIDA_GHCR_NAMESPACE", "f0rw4rd")
_ALLOW_PRIVATE = os.environ.get("OIDA_GHCR_ALLOW_PRIVATE") == "1"
_TIMEOUT = 15
_RETRIES = 4  # ghcr.io/token rate-limits bursts (HTTP 429); back off and retry

_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def _core_images() -> list[str]:
    """Return sorted ``oida-mock-<name>:<tag>`` refs from the core compose file.

    compose.yml holds only the core mocks (CVE targets live in compose.cve.yml),
    so this is exactly the public-core set. Tags are captured too, which keeps
    multi-tag images (e.g. oida-mock-profinet:siemens-et200sp) honest.
    """
    text = COMPOSE_CORE.read_text()
    return sorted(set(re.findall(r"oida-mock-[a-z0-9._-]+:[a-z0-9._-]+", text)))


def _ghcr_basic_from_docker_config() -> str | None:
    """Return the base64 ``user:token`` Basic-auth blob from the docker login.

    docker stores exactly this (base64 of ``username:token``) in the ``auth``
    field, which is what the ghcr.io token endpoint expects as ``Basic <blob>``
    - so it is used verbatim, not decoded.
    """
    cfg = Path.home() / ".docker" / "config.json"
    try:
        blob = json.loads(cfg.read_text())["auths"]["ghcr.io"]["auth"]
        base64.b64decode(blob)  # validate it is real base64
        return blob
    except (OSError, KeyError, ValueError):
        return None


def _registry_token(repo: str, basic: str | None) -> tuple[str | None, int]:
    """Exchange for a ghcr.io pull token (authenticated if ``basic`` given).

    Returns ``(token, status)``. ``status`` is 200 when a token was granted,
    the HTTP error code otherwise (401 = access denied - a *private* or missing
    repo for an anonymous request), or 0 when the endpoint was unreachable. A
    429 burst is retried with exponential backoff so a large parametrized run
    doesn't collapse mid-way.
    """
    req = urllib.request.Request(f"https://ghcr.io/token?scope=repository:{repo}:pull")
    if basic:
        req.add_header("Authorization", f"Basic {basic}")
    for attempt in range(_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                return json.load(r).get("token"), r.status
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < _RETRIES - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            return None, e.code
        except urllib.error.URLError:
            return None, 0
    return None, 0


def _manifest_status(repo: str, tag: str, bearer: str | None) -> int:
    """HTTP status for a manifest GET. 0 means the registry was unreachable."""
    req = urllib.request.Request(f"https://ghcr.io/v2/{repo}/manifests/{tag}")
    req.add_header("Accept", _MANIFEST_ACCEPT)
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    for attempt in range(_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < _RETRIES - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            return e.code
        except urllib.error.URLError:
            return 0
    return 0


_IMAGES = _core_images()


def test_core_image_set_is_nonempty():
    assert _IMAGES, f"no oida-mock-*:tag refs found in {COMPOSE_CORE}"


@pytest.mark.parametrize("ref", _IMAGES)
def test_core_image_present_on_ghcr(ref):
    name, tag = ref.split(":", 1)
    repo = f"{GHCR_NAMESPACE}/{name}"

    if _ALLOW_PRIVATE:
        # Presence-only: authenticate with the local docker login and confirm
        # the manifest exists, regardless of public/private visibility.
        basic = _ghcr_basic_from_docker_config()
        if basic is None:
            require_service(
                "OIDA_GHCR_ALLOW_PRIVATE=1 but no ghcr.io login in "
                "~/.docker/config.json to check presence"
            )
        token, tstatus = _registry_token(repo, basic)
        if tstatus == 0:
            require_service("cannot reach ghcr.io token endpoint (offline)")
        assert token is not None, (
            f"ghcr.io/{repo}: no pull token even with auth (HTTP {tstatus}) "
            f"- repo missing or login lacks access"
        )
        status = _manifest_status(repo, tag, token)
        if status == 0:
            require_service("cannot reach ghcr.io registry (offline)")
        assert status == 200, (
            f"ghcr.io/{repo}:{tag} not present (HTTP {status}) - image was not pushed"
        )
        return

    # Default: assert anonymous pullability, which proves present AND public.
    token, tstatus = _registry_token(repo, basic=None)
    if tstatus == 0:
        require_service("cannot reach ghcr.io token endpoint (offline)")
    assert token is not None and tstatus == 200, (
        f"ghcr.io/{repo}:{tag} not anonymously accessible (token HTTP {tstatus}): "
        "still PRIVATE (flip the package to Public) or MISSING. "
        "Set OIDA_GHCR_ALLOW_PRIVATE=1 to check presence only."
    )
    status = _manifest_status(repo, tag, token)
    if status == 0:
        require_service("cannot reach ghcr.io registry (offline)")
    assert status == 200, (
        f"ghcr.io/{repo}:{tag} anon token granted but manifest HTTP {status} "
        "- unexpected (tag missing?)"
    )
