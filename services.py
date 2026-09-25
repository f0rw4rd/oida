#!/usr/bin/env python3
"""OIDA service manager - manages mock ICS services for testing and development.

Usage:
    python services.py up [core|cve|all|<group>|<service>]  # <group> starts core members (add --with-cve for CVE targets)
    python services.py down
    python services.py status [filter] [-v]   # health overview; -v adds per-container detail
    python services.py logs [service...]
    python services.py list
    python services.py groups                 # list oida.group values (valid `up <group>` args)
    python services.py ports
    python services.py push                   # build & push all mock images to $OIDA_REGISTRY
    python services.py stale                  # which images are outdated vs the registry (exit 1 if any)
    python services.py up-cve <proto>         # start a vuln-<proto> CVE group
    ...

Install: no extra dependencies (stdlib only).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import functools
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
COMPOSE_DIR = PROJECT_ROOT / "docker" / "mocks"
COMPOSE_CORE = str(COMPOSE_DIR / "compose.yml")
COMPOSE_CVE = str(COMPOSE_DIR / "compose.cve.yml")
MOCK_HOST = os.environ.get("MOCK_HOST", "127.0.0.1")
# Public home for the pre-built mock images. Used as the fallback when
# OIDA_REGISTRY is unset so a fresh clone can `up`/`pull` with zero config;
# override via docker/mocks/.env to push/pull your own registry.
DEFAULT_REGISTRY = "ghcr.io/f0rw4rd"

WAIT_HEALTHY_TIMEOUT = 90
WAIT_HEALTHY_INTERVAL = 3
PORT_CHECK_TIMEOUT = 2
STARTUP_DELAY = 3

# ANSI colours - disabled when piped or NO_COLOR is set (#8)
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RST = "\033[0m"

if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = RST = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compose_cmd(*extra: str) -> list[str]:
    """Build a docker compose command list with the given extra args."""
    return ["docker", "compose", *extra]


def _core_args() -> list[str]:
    return ["-f", COMPOSE_CORE]


def _all_args() -> list[str]:
    return ["-f", COMPOSE_CORE, "-f", COMPOSE_CVE]


def _run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    suppress_stderr: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command."""
    kwargs: dict = {"check": check}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
        kwargs["text"] = True
    elif suppress_stderr:
        kwargs["stderr"] = subprocess.DEVNULL
    return subprocess.run(cmd, **kwargs)  # noqa: S603


def _load_dotenv() -> None:
    """Load ``docker/mocks/.env`` into the environment.

    ``docker compose`` auto-loads it for compose runs, but ``buildx bake`` and our
    own target enumeration need ``OIDA_REGISTRY`` present in ``os.environ``.
    Existing environment values win (so an explicit export overrides the file).
    """
    env_file = COMPOSE_DIR / ".env"
    if not env_file.exists():
        os.environ.setdefault("OIDA_REGISTRY", DEFAULT_REGISTRY)
        return
    for raw in env_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())
    os.environ.setdefault("OIDA_REGISTRY", DEFAULT_REGISTRY)


def _buildable_contexts(config: dict) -> dict[str, str]:
    """Map service name -> absolute build-context dir, for services with a ``build:``.

    Used by the drift guard to tell which on-disk source belongs to which mock
    image. *config* is a parsed compose config (see ``_get_compose_config``);
    an empty/partial config simply yields no contexts, so callers degrade to the
    plain pull-everything path.
    """
    out: dict[str, str] = {}
    for name, svc in (config.get("services") or {}).items():
        build = svc.get("build")
        if not build:
            continue
        ctx = build.get("context") if isinstance(build, dict) else build
        if not ctx:
            continue
        ctx_abs = ctx if os.path.isabs(ctx) else str((COMPOSE_DIR / ctx).resolve())
        out[name] = ctx_abs
    return out


def _git_dirty_services(contexts: dict[str, str]) -> set[str]:
    """Subset of *contexts* whose build-context has uncommitted git changes.

    This is the drift guard: a service is "locally modified" when ``git status``
    reports tracked changes or untracked files anywhere under its build context.
    Returns an empty set outside a git work tree (graceful no-op).
    """
    probe = _run(["git", "rev-parse", "--is-inside-work-tree"], check=False, capture=True)
    if probe.returncode != 0:
        return set()
    dirty: set[str] = set()
    for name, ctx in contexts.items():
        st = _run(["git", "status", "--porcelain", "--", ctx], check=False, capture=True)
        if st.returncode == 0 and st.stdout.strip():
            dirty.add(name)
    return dirty


# ---------------------------------------------------------------------------
# Content-hash image tags
# ---------------------------------------------------------------------------
#
# Each mock image is tagged with a hash derived from its build definition
# (build context + dockerfile + build args), so a tag deterministically
# identifies a source state. This lets `push` skip images already in the
# registry and de-dups services that share one build context (they compute the
# same tag, so the image is built once). `:latest` is kept as a floating
# convenience pointer alongside the hash tag.


def _dir_digest(path: str) -> str:
    """SHA-256 over a directory's file paths + contents (fallback when the
    context isn't in git HEAD, e.g. never committed)."""
    h = hashlib.sha256()
    root = Path(path)
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            try:
                h.update(p.read_bytes())
            except OSError:
                h.update(b"<unreadable>")
    return h.hexdigest()


def _image_specs(config: dict) -> dict[str, dict]:
    """Map image base ref (no ``:tag``) -> build spec for buildable services.

    Returns ``{base: {"context": abs, "dockerfile": str, "args": dict,
    "services": [names]}}``. Services that share an image base are collapsed
    into one entry (the build context is identical), which is what de-dups the
    push set.
    """
    specs: dict[str, dict] = {}
    for name, svc in (config.get("services") or {}).items():
        build = svc.get("build")
        image = svc.get("image", "")
        if not build or not image:
            continue
        base = image.rsplit(":", 1)[0]
        ctx = build.get("context") if isinstance(build, dict) else build
        if not ctx:
            continue
        ctx_abs = ctx if os.path.isabs(ctx) else str((COMPOSE_DIR / ctx).resolve())
        dockerfile = (
            build.get("dockerfile", "Dockerfile") if isinstance(build, dict) else "Dockerfile"
        )
        args = build.get("args") if isinstance(build, dict) else None
        if isinstance(args, list):  # compose may emit ["K=V", ...]
            args = dict(a.split("=", 1) for a in args if "=" in a)
        args = args or {}
        entry = specs.setdefault(
            base, {"context": ctx_abs, "dockerfile": dockerfile, "args": args, "services": []}
        )
        entry["services"].append(name)
    return specs


def _content_tag(spec: dict) -> str:
    """Deterministic 12-hex content tag for one image build spec.

    Uses the git tree SHA of the build context **at HEAD** (changes iff
    *committed* tracked files in that context change), folded with the
    dockerfile name + build args.

    NB: an uncommitted working-tree change to a tracked file does NOT move the
    tag, so ``push`` treats the image as unchanged and skips it - commit the
    change first (see ``_context_is_dirty``, which warns about exactly this).
    Falls back to an on-disk digest only when the context isn't tracked in HEAD
    at all (a brand-new, never-committed directory).
    """
    ctx = spec["context"]
    relpath = os.path.relpath(ctx, PROJECT_ROOT)
    tree = _run(["git", "rev-parse", f"HEAD:{relpath}"], check=False, capture=True)
    seed = tree.stdout.strip() if tree.returncode == 0 and tree.stdout.strip() else _dir_digest(ctx)
    h = hashlib.sha256()
    h.update(seed.encode())
    h.update(os.path.basename(spec["dockerfile"]).encode())
    for k in sorted(spec["args"]):
        h.update(f"{k}={spec['args'][k]}".encode())
    return h.hexdigest()[:12]


def _image_tags(config: dict) -> dict[str, str]:
    """Map image base ref -> computed content tag for every buildable image."""
    return {base: _content_tag(spec) for base, spec in _image_specs(config).items()}


def _context_is_dirty(ctx: str) -> bool:
    """True if the build context has uncommitted changes to tracked files.

    ``_content_tag`` hashes HEAD, so a dirty context means ``push`` computes the
    same (already-published) tag and SKIPS the image even though its source has
    actually changed. Used to warn about that footgun so a fix isn't silently
    left unpushed. Untracked files are ignored (they can't affect a HEAD-based
    tag until added + committed anyway).
    """
    relpath = os.path.relpath(ctx, PROJECT_ROOT)
    res = _run(["git", "status", "--porcelain", "-uno", "--", relpath], check=False, capture=True)
    return res.returncode == 0 and bool(res.stdout.strip())


def _dirty_contexts(contexts: list[str]) -> set[str]:
    """Batched ``_context_is_dirty``: the subset of *contexts* with uncommitted
    tracked changes.

    One ``git status`` over the repo, matched by path prefix, instead of ~120
    per-context probes. Same semantics as ``_context_is_dirty`` (tracked files
    only - untracked ones can't move a HEAD-based tag until committed).
    """
    res = _run(["git", "status", "--porcelain", "-uno"], check=False, capture=True)
    if res.returncode != 0:
        return set()
    changed: list[str] = []
    for line in res.stdout.splitlines():
        path = line[3:].strip()
        if not path:
            continue
        if " -> " in path:  # rename entry: "old -> new"
            path = path.split(" -> ", 1)[1]
        changed.append(str((PROJECT_ROOT / path.strip('"')).resolve()))
    dirty = set()
    for ctx in contexts:
        prefix = ctx.rstrip("/") + "/"  # guard: /ctx-other must not match /ctx
        if any(c == ctx or c.startswith(prefix) for c in changed):
            dirty.add(ctx)
    return dirty


PROBE_PRESENT = "present"
PROBE_ABSENT = "absent"
PROBE_DENIED = "denied"


def _registry_probe(ref: str) -> str:
    """Tri-state existence check for *ref* (``repo:tag``): present/absent/denied.

    Uses ``docker manifest inspect`` - the reliable probe (``buildx imagetools
    inspect`` was observed to false-negative under registry load).

    The three states matter because a failed probe is NOT proof of absence.
    Registries answer an unreadable repository and a nonexistent one identically:
    ghcr returns 403 ``DENIED`` both for a private repo we aren't logged in to and
    for a name that was never pushed, so ``denied`` means "cannot tell". Only
    ``manifest unknown`` - the repo is readable, that tag isn't there - is
    trustworthy evidence of absence.
    """
    # One retry on the ambiguous verdict: a wide concurrent sweep gets throttled,
    # and a throttled reply is indistinguishable from a permission denial. Observed
    # live - an image that answers 200 on its own probed "denied" under 48-way
    # concurrency. Present/absent are definitive, so only `denied` is worth re-asking.
    for attempt in range(2):
        res = _run(["docker", "manifest", "inspect", ref], check=False, capture=True)
        if res.returncode == 0:
            return PROBE_PRESENT
        err = (res.stderr or "").lower()
        if "manifest unknown" in err or "not found" in err or "no such manifest" in err:
            return PROBE_ABSENT
        if attempt == 0:
            time.sleep(0.5)
    return PROBE_DENIED


def _registry_has(ref: str) -> bool:
    """True if *ref* (``repo:tag``) exists in its registry.

    Collapses ``_registry_probe``'s denied/absent distinction into "not usable",
    which is what ``push`` wants: it rebuilds when it can't confirm a hit.
    """
    return _registry_probe(ref) == PROBE_PRESENT


def _registry_digest(ref: str) -> str | None:
    """Canonical content digest of *ref* in the registry, or None on failure.

    ``imagetools inspect --raw`` emits the registry's exact manifest bytes, so
    hashing them reproduces the digest the registry itself serves - verified equal
    to ghcr's ``Docker-Content-Digest`` header. That single value is comparable
    both between registry tags and against a pulled image's ``RepoDigests``, for a
    single-platform manifest and for the multi-platform index buildx actually
    pushes alike.

    None means "could not read", NOT "absent" - establish presence with
    ``_registry_probe`` first so a transient error is never read as unpublished.
    """
    # Bytes, not text: the digest must cover the registry's exact bytes, and
    # `_run(capture=True)` would decode them with newline translation.
    res = subprocess.run(  # noqa: S603
        ["docker", "buildx", "imagetools", "inspect", ref, "--raw"],
        capture_output=True,
        check=False,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return None
    return "sha256:" + hashlib.sha256(res.stdout).hexdigest()


def _local_ident(ref: str) -> str | None:
    """Digest of the locally-present image *ref*, or None if it isn't pulled.

    Reads ``RepoDigests``, which records the digest the image was pulled by - the
    same value ``_registry_digest`` computes. Locally-*built* images have no
    RepoDigest at all (they were never pulled) and return None, indistinguishable
    from "not present", which is why the local check reports UNKNOWN rather than
    stale in that case.
    """
    res = _run(
        ["docker", "image", "inspect", ref, "--format", "{{json .RepoDigests}}"],
        check=False,
        capture=True,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return None
    try:
        digests = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(digests, list):
        return None
    repo = ref.rsplit(":", 1)[0]
    for entry in digests:
        if isinstance(entry, str) and entry.startswith(f"{repo}@"):
            return entry.split("@", 1)[1]
    return None


def _bearer_token(challenge: str) -> str | None:
    """Anonymous pull token for a ``WWW-Authenticate: Bearer ...`` *challenge*.

    The registry spec's auth handshake: an unauthenticated request is answered 401
    with the token endpoint (``realm``) plus the ``service``/``scope`` to ask for,
    and re-requesting with the returned token succeeds. For a public repository no
    credentials are needed, which is all the tag listing below requires.
    """
    if not challenge.lower().startswith("bearer "):
        return None
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.get("realm")
    if not realm:
        return None
    query = urllib.parse.urlencode({k: params[k] for k in ("service", "scope") if params.get(k)})
    try:
        with urllib.request.urlopen(  # noqa: S310 - scheme fixed by the realm below
            f"{realm}?{query}" if query else realm, timeout=10
        ) as resp:
            body = json.load(resp)
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None
    tok = body.get("token") or body.get("access_token")
    return tok if isinstance(tok, str) else None


@functools.lru_cache(maxsize=None)
def _registry_tags(repo: str) -> tuple[str, ...] | None:
    """Every tag published for image repo *repo* (``host/path``), or None if unknown.

    Speaks the registry v2 API directly - ``GET /v2/<name>/tags/list`` - because the
    docker CLI has no tag-listing command, and the answer is what distinguishes "this
    image is behind" from "this image was never content-tagged at all". A repo holding
    any tag besides ``latest`` is proof that ``push`` published it, so a *missing*
    content tag there means the registry is genuinely behind the source; a repo with
    only ``latest`` proves the opposite and must not fail a release.

    None means "could not ask" - a private repo, a registry with no tag catalogue, a
    network error. It is never evidence that a repo has no tags, so callers must treat
    it as unknown and fall back rather than reading it as absence.
    """
    host, _, path = repo.partition("/")
    if "." not in host and ":" not in host and host != "localhost":
        # Bare name like `alpine` or `user/img`: Docker Hub, which namespaces
        # single-segment official images under `library/`.
        host, path = "registry-1.docker.io", repo
        if "/" not in path:
            path = f"library/{path}"
    if not path:
        return None
    url = f"https://{host}/v2/{path}/tags/list?n=1000"

    token: str | None = None
    for _ in range(2):  # at most one retry, to carry the token from a 401 challenge
        req = urllib.request.Request(url)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - https above
                tags = json.load(resp).get("tags")
            return tuple(t for t in tags if isinstance(t, str)) if tags else ()
        except urllib.error.HTTPError as exc:
            if exc.code != 401 or token is not None:
                return None
            token = _bearer_token(exc.headers.get("WWW-Authenticate", ""))
            if not token:
                return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError, AttributeError):
            return None
    return None


def _repo_hash_tagged(repo: str) -> bool | None:
    """True if *repo* carries any tag beyond ``latest``; None if it can't be read.

    The evidence behind the UNPUBLISHED/NO-HASH-TAGS split: content tags are the only
    other thing anything publishes here, so their presence means ``push`` has run
    against this repo and the gate can hold it to a strict source match.
    """
    tags = _registry_tags(repo)
    if tags is None:
        return None
    return any(t != "latest" for t in tags)


def check_port(port: int, label: str, *, udp: bool = False, host: str | None = None) -> bool:
    """Check whether a TCP or UDP port is reachable.

    Returns True if the port responds, False otherwise.
    """
    target = host or MOCK_HOST
    if udp:
        # (#2) Proper UDP check: send a datagram, then try to recv.
        # TimeoutError = no ICMP unreachable received = port likely open.
        # ConnectionRefusedError = ICMP port unreachable = port closed.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(PORT_CHECK_TIMEOUT)
                sock.sendto(b"\x00", (target, port))
                try:
                    sock.recvfrom(1024)
                except TimeoutError:
                    # No rejection - port is likely open
                    pass
            print(f"  {GREEN}[OK]{RST} {label} (UDP:{port})")
            return True
        except ConnectionRefusedError:
            print(f"  {RED}[!!]{RST} {label} (UDP:{port}) not reachable")
            return False
        except OSError:
            print(f"  {RED}[!!]{RST} {label} (UDP:{port}) not reachable")
            return False
    else:
        try:
            with socket.create_connection((target, port), timeout=PORT_CHECK_TIMEOUT) as conn:
                _ = conn
            print(f"  {GREEN}[OK]{RST} {label} (:{port})")
            return True
        except OSError:
            print(f"  {RED}[!!]{RST} {label} (:{port}) not reachable")
            return False


def check_port_udp(port: int, label: str, *, host: str | None = None) -> bool:
    """Convenience wrapper for UDP port check."""
    return check_port(port, label, udp=True, host=host)


def wait_healthy(compose_args: list[str], *, timeout: int = WAIT_HEALTHY_TIMEOUT) -> bool:
    """Wait for all compose services to report healthy.

    Returns True if all healthy within timeout, False otherwise.
    """
    print(f"{YELLOW}[*]{RST} Waiting for services to be healthy (timeout: {timeout}s)...")

    # Get running container names
    cmd = _compose_cmd(*compose_args, "ps", "--format", "{{.Name}}")
    result = _run(cmd, capture=True, check=False)
    services = sorted(result.stdout.strip().split("\n")) if result.stdout.strip() else []

    if not services:
        print(f"{RED}[!!]{RST} No containers found")
        return False

    elapsed = 0
    while elapsed < timeout:
        all_healthy = True
        for name in services:
            health_cmd = [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                name,
            ]
            health_result = _run(health_cmd, capture=True, check=False)

            # (#13) Differentiate "not found" from "no healthcheck"
            if health_result.returncode != 0:
                # Container not found or inspect failed
                all_healthy = False
                continue

            health = health_result.stdout.strip()

            if health in ("healthy", "none"):
                continue
            elif health == "unhealthy":
                print(f"  {RED}[!!]{RST} {name} unhealthy")
                all_healthy = False
            else:
                all_healthy = False

        if all_healthy:
            print(f"{GREEN}[OK]{RST} All services healthy")
            # Show status table
            table_cmd = _compose_cmd(
                *compose_args,
                "ps",
                "--format",
                "table {{.Name}}\t{{.Status}}\t{{.Ports}}",
            )
            _run(table_cmd, check=False)
            return True

        print(f"\r{YELLOW}[*]{RST} Waiting... {elapsed}/{timeout}s", end="", flush=True)
        time.sleep(WAIT_HEALTHY_INTERVAL)
        elapsed += WAIT_HEALTHY_INTERVAL

    print()
    print(f"{RED}[!!]{RST} Timeout. Current status:")
    _run(_compose_cmd(*compose_args, "ps"), check=False)
    return False


def _get_compose_config(compose_args: list[str]) -> dict:
    """Get parsed compose config as a dict.

    Include ``--profile <name>`` in *compose_args* to surface profile-gated
    services in the output (see callers that prepend ``[*_all_args(), ...]``).
    """
    cmd = _compose_cmd(*compose_args, "config", "--format", "json")
    result = _run(cmd, capture=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def _resolve_services_by_group(
    group: str, compose_args: list[str], *, config: dict | None = None
) -> list[str]:
    """Resolve service names from oida.group label."""
    if config is None:
        config = _get_compose_config(compose_args)
    services = []
    for svc_name, svc_def in config.get("services", {}).items():
        labels = svc_def.get("labels", {})
        if labels.get("oida.group") == group:
            services.append(svc_name)
    return sorted(services)


def _all_groups(config: dict) -> set[str]:
    """Distinct non-empty oida.group label values present in a compose config."""
    groups: set[str] = set()
    for svc_def in config.get("services", {}).values():
        g = svc_def.get("labels", {}).get("oida.group", "")
        if g:
            groups.add(g)
    return groups


def _clear_conflicting_containers(config: dict, services: set[str] | None = None) -> None:
    """Force-remove containers that would abort ``up`` with a name conflict.

    Mock services pin a fixed ``container_name`` (e.g. ``s7comm-snap7-server``).
    That name is global to the Docker daemon - it is *not* scoped to the compose
    project. The pytest harness brings the same stack up under the ``oida-test``
    project while ``services.py`` uses ``mocks``; a stale container left behind by
    the other project (or a stray ``docker run``) owns the name and makes the
    whole ``up`` fail with "container name is already in use", taking every other
    mock down with it.

    Compose can always reuse a name owned by *its own* project, so we only remove
    containers whose name we need but whose compose project differs from ours
    (label-less strays included). Best-effort: any docker error is ignored so a
    transient daemon hiccup never blocks ``up``.
    """
    project = config.get("name")
    declared = {
        svc_def["container_name"]
        for svc_name, svc_def in (config.get("services") or {}).items()
        if svc_def.get("container_name") and (services is None or svc_name in services)
    }
    if not declared:
        return
    result = _run(
        ["docker", "ps", "-a", "--format", '{{.Names}}\t{{.Label "com.docker.compose.project"}}'],
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        return
    conflicting = []
    for line in result.stdout.splitlines():
        name, _, owner = line.partition("\t")
        if name.strip() in declared and owner.strip() != project:
            conflicting.append(name.strip())
    conflicting.sort()
    if conflicting:
        print(
            f"{YELLOW}[~]{RST} Removing {len(conflicting)} conflicting container(s) "
            f"from another compose project: {', '.join(conflicting)}"
        )
        _run(["docker", "rm", "-f", *conflicting], check=False)


def _pull(
    compose_args: list[str],
    *,
    profiles: tuple[str, ...] = (),
    services: tuple[str, ...] = (),
    quiet: bool = False,
) -> None:
    """Best-effort pull of pre-built images from the configured registry.

    Buildable services carry an ``image:`` of ``$OIDA_REGISTRY/oida-mock-*``,
    so ``pull`` grabs the published image when available. ``OIDA_REGISTRY`` is
    required (compose fails hard if unset); set it in a gitignored
    ``docker/mocks/.env`` - see ``docker/mocks/.env.example``. Failures (offline,
    image not yet published, third-party images) are expected - the subsequent
    ``up`` builds whatever is still missing locally.

    Drift guard: image tags are the mutable ``:latest``, so a plain pull would
    overwrite a locally-built image with the published one. When a buildable
    mock's source has uncommitted git changes, we therefore exclude it from the
    pull and rebuild it locally instead - so editing a mock and re-running
    ``up`` can never silently run the stale published image. (See the
    ads-twincat dynamic-NetId work for the bug this prevents.)

    By default the pull runs with normal docker output (progress bars + the
    expected ``--ignore-pull-failures`` warnings). Pass ``quiet=True`` to hide
    that stderr (used by ``up --quiet-pull`` for CI/scripted runs).
    """
    profile_args: list[str] = []
    for p in profiles:
        profile_args.extend(["--profile", p])

    _load_dotenv()  # ensure OIDA_REGISTRY is present for `compose config`
    config = _get_compose_config([*compose_args, *profile_args])
    contexts = _buildable_contexts(config)
    if services:
        contexts = {n: c for n, c in contexts.items() if n in services}
    dirty = _git_dirty_services(contexts)

    if dirty:
        print(
            f"{YELLOW}[*]{RST} Skipping pull for locally-modified service(s) "
            f"(will build instead): {', '.join(sorted(dirty))}"
        )
        if services:
            pull_list = [s for s in services if s not in dirty]
        else:
            pull_list = [s for s in (config.get("services") or {}) if s not in dirty]
    else:
        pull_list = list(services)  # empty tuple => pull everything

    # Pull pre-built images (skip entirely if every requested service is dirty).
    if pull_list or not dirty:
        print(f"{YELLOW}[*]{RST} Pulling pre-built images (will build locally on miss)...")
        _run(
            _compose_cmd(
                *compose_args, *profile_args, "pull", "--ignore-pull-failures", *pull_list
            ),
            check=False,
            suppress_stderr=quiet,
        )

    # Rebuild locally-modified services over any stale published image.
    if dirty:
        print(f"{YELLOW}[~]{RST} Building locally-modified service(s): {', '.join(sorted(dirty))}")
        _run(_compose_cmd(*compose_args, *profile_args, "build", *sorted(dirty)), check=False)


def _check_docker() -> bool:
    """Pre-flight check that Docker is available. Returns True if Docker is OK."""
    try:
        result = subprocess.run(  # noqa: S603, S607
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            print(f"{RED}[!!]{RST} Docker is not available. Please start Docker and try again.")
            return False
        return True
    except FileNotFoundError:
        print(f"{RED}[!!]{RST} Docker is not installed. Please install Docker and try again.")
        return False


def _check_compose_file() -> bool:
    """Check that the core compose file exists."""
    if not Path(COMPOSE_CORE).exists():
        print(f"{RED}[!!]{RST} Compose file not found: {COMPOSE_CORE}")
        return False
    return True


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_up(args: argparse.Namespace) -> int:
    """Start mock services."""
    stack = args.stack

    build_flag = ["--build"] if args.build else []

    if stack == "core":
        print(f"{BLUE}=== Starting Core Services ==={RST}")
        if not args.build and not args.no_pull:
            _pull(_core_args(), quiet=args.quiet_pull)
        _clear_conflicting_containers(_get_compose_config(_core_args()))
        _run(_compose_cmd(*_core_args(), "up", "-d", *build_flag))
        ok = wait_healthy(_all_args())
        return 0 if ok else 1

    elif stack in ("cve", "all"):
        label = "Core + CVE" if stack == "cve" else "All"
        print(f"{BLUE}=== Starting {label} Services ==={RST}")
        if not args.build and not args.no_pull:
            _pull(_all_args(), profiles=("vuln-services",), quiet=args.quiet_pull)
        _clear_conflicting_containers(
            _get_compose_config([*_all_args(), "--profile", "vuln-services"])
        )
        _run(_compose_cmd(*_all_args(), "--profile", "vuln-services", "up", "-d", *build_flag))
        ok = wait_healthy(_all_args())
        return 0 if ok else 1

    else:
        # Treat as protocol group name - delegate to the data-driven group path
        return _up_proto_impl(stack, quiet_pull=args.quiet_pull, with_cve=args.with_cve)


def cmd_down(args: argparse.Namespace) -> int:
    """Stop all mock services."""
    _ = args
    print(f"{BLUE}=== Stopping Mock Services ==={RST}")
    _run(_compose_cmd(*_all_args(), "--profile", "vuln-services", "down"))
    print(f"{GREEN}[OK]{RST} Services stopped")
    return 0


def cmd_restart(args: argparse.Namespace) -> int:
    """Restart mock services."""
    _ = args
    print(f"{BLUE}=== Restarting Mock Services ==={RST}")
    _run(_compose_cmd(*_all_args(), "restart"))
    ok = wait_healthy(_all_args())
    return 0 if ok else 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show a compact health overview of the mock containers.

    Groups containers by their ``oida.group`` label and prints per-group
    healthy/starting/issue counts, then lists every container that is
    unhealthy or stopped so problems stand out - instead of dumping the raw
    wide ``docker compose ps`` table.

    To drill in: ``status <filter>`` narrows to containers whose name or group
    matches *filter*, and ``-v/--verbose`` adds a per-container Name/Status/Ports
    table (filtered too). For live output, use ``logs <service>``.
    """
    filt = (getattr(args, "filter", None) or "").lower()
    verbose = bool(getattr(args, "verbose", False))
    print(f"{BOLD}{CYAN}=== OIDA Mock Services Status ==={RST}")
    print()

    # ``-a`` so exited/stopped containers show up as issues, not silent gaps.
    ps_cmd = _compose_cmd(*_all_args(), "ps", "-a", "--format", "json")
    result = _run(ps_cmd, capture=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        print(f"  {DIM}No containers found. Start with: python services.py up{RST}")
        print()
        return 0

    containers = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not containers:
        print(f"  {DIM}No containers found. Start with: python services.py up{RST}")
        print()
        return 0

    # group -> [healthy, starting, issues, total]
    groups: dict[str, list[int]] = {}
    issues: list[tuple[str, str]] = []  # (name, reason)
    detail: list[tuple[str, str, str, str]] = []  # (name, state-class, status, ports)

    for c in containers:
        name = c.get("Name", "")
        state = (c.get("State") or "").lower()
        health = (c.get("Health") or "").lower()

        m = re.search(r"oida\.group=([^,]*)", c.get("Labels", ""))
        group = (m.group(1) if m else "") or "other"

        if filt and filt not in name.lower() and filt not in group.lower():
            continue

        counts = groups.setdefault(group, [0, 0, 0, 0])
        counts[3] += 1

        if state == "running" and health in ("healthy", "", "none"):
            counts[0] += 1
            cls = "ok"
        elif state == "running" and health == "starting":
            counts[1] += 1
            cls = "starting"
        elif state == "running" and health == "unhealthy":
            counts[2] += 1
            cls = "bad"
            issues.append((name, "unhealthy"))
        else:
            counts[2] += 1
            cls = "bad"
            reason = state or "unknown"
            exit_code = c.get("ExitCode")
            if state == "exited" and exit_code is not None:
                reason = f"exited ({exit_code})"
            issues.append((name, reason))

        detail.append((name, cls, c.get("Status", ""), c.get("Ports", "")))

    if not groups:
        print(f"  {DIM}No containers match filter: {filt!r}{RST}")
        print()
        return 0

    print(
        f"  {BOLD}{CYAN}{'GROUP':<16} {'HEALTHY':>8} {'STARTING':>9} {'ISSUES':>7} {'TOTAL':>6}{RST}"
    )
    print(f"  {DIM}{'---':<16} {'---':>8} {'---':>9} {'---':>7} {'---':>6}{RST}")
    tot = [0, 0, 0, 0]
    for group in sorted(groups):
        healthy, starting, bad, total = groups[group]
        for i, v in enumerate((healthy, starting, bad, total)):
            tot[i] += v
        h = f"{GREEN}{healthy:>8}{RST}" if healthy else f"{DIM}{healthy:>8}{RST}"
        s = f"{YELLOW}{starting:>9}{RST}" if starting else f"{DIM}{starting:>9}{RST}"
        b = f"{RED}{bad:>7}{RST}" if bad else f"{DIM}{bad:>7}{RST}"
        print(f"  {group:<16} {h} {s} {b} {total:>6}")

    print(f"  {DIM}{'---':<16} {'---':>8} {'---':>9} {'---':>7} {'---':>6}{RST}")
    print(f"  {BOLD}{'TOTAL':<16}{RST} {tot[0]:>8} {tot[1]:>9} {tot[2]:>7} {tot[3]:>6}")
    print()

    if issues:
        print(f"  {BOLD}{RED}Issues ({len(issues)}):{RST}")
        for name, reason in sorted(issues):
            print(f"    {name:<32} {RED}{reason}{RST}")
    else:
        scope = f"matching {filt!r}" if filt else "containers"
        print(f"  {GREEN}[OK]{RST} All {tot[3]} {scope} healthy.")
    print()

    if verbose:
        colour = {"ok": GREEN, "starting": YELLOW, "bad": RED}
        print(f"  {BOLD}{CYAN}{'CONTAINER':<32} {'STATUS':<28} PORTS{RST}")
        print(f"  {DIM}{'---':<32} {'---':<28} ---{RST}")
        for name, cls, status, ports in sorted(detail):
            dot = f"{colour[cls]}●{RST}"
            print(f"  {dot} {name:<30} {status:<28} {DIM}{ports}{RST}")
        print()
    else:
        print(
            f"  {DIM}Details: status -v [filter] · per-container · "
            f"logs <service> for live output{RST}"
        )
        print()
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    """Follow logs for services."""
    cmd = _compose_cmd(*_all_args(), "logs", "-f", "--tail=100")
    if args.service:
        cmd.extend(args.service)
    _run(cmd, check=False)
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    """Build images without starting."""
    stack = args.stack
    if stack == "core":
        _run(_compose_cmd(*_core_args(), "build"))
    elif stack in ("cve", "all"):
        _run(_compose_cmd(*_all_args(), "build"))
    else:
        # (#15) Unknown stack should error
        print(f"{RED}[!!]{RST} Unknown stack: {stack}. Use 'core', 'cve', or 'all'.")
        return 1
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    """Build and push mock images to ``$OIDA_REGISTRY``, skipping unchanged ones.

    Each image is tagged with a content hash of its build definition (see
    ``_content_tag``) plus a floating ``:latest``. Before building, push checks
    whether ``<image>:<hash>`` already exists in the registry and skips it if so
    - so re-running with no source changes does nothing, and only edited mocks
    rebuild. Services sharing a build context collapse to one image (built once).
    Pass ``--force`` to rebuild + re-push everything regardless of presence.

    Two warts are handled so it stays one command:
    - Targets whose build context is missing on disk (e.g. the never-committed
      ``services/memcached/cve``) are skipped - a raw ``bake --push`` aborts the
      whole graph on the first missing context.
    - Work is split into small sequential batches so buildkit isn't swamped by
      100+ concurrent compiles + remote pushes (which drops jobs and aborts).
    """
    _load_dotenv()
    registry = os.environ.get("OIDA_REGISTRY")
    if not registry:
        print(
            f"{RED}[!!]{RST} OIDA_REGISTRY is unset. Copy docker/mocks/.env.example "
            f"to docker/mocks/.env and set your registry."
        )
        return 1

    config = _get_compose_config([*_all_args(), "--profile", "vuln-services"])
    tags = _image_tags(config)  # image base ref -> content hash
    if not tags:
        print(f"{RED}[!!]{RST} No buildable images found.")
        return 1

    # Bake targets carry the build defs (context/dockerfile/args). Group them by
    # image base and keep one representative per base (shared-context services
    # build the same image - that's the de-dup).
    bake_files = ["-f", COMPOSE_CORE, "-f", COMPOSE_CVE]
    res = _run(["docker", "buildx", "bake", *bake_files, "--print"], check=False, capture=True)
    if res.returncode != 0:
        print(f"{RED}[!!]{RST} 'docker buildx bake --print' failed:\n{res.stderr}")
        return 1
    targets = json.loads(res.stdout).get("target", {})

    rep: dict[str, tuple[str, dict]] = {}  # image base -> (target name, spec)
    missing_ctx: list[str] = []
    for name, spec in targets.items():
        tgt_tags = spec.get("tags") or []
        if not tgt_tags:
            continue
        base = tgt_tags[0].rsplit(":", 1)[0]
        ctx = spec.get("context", ".")
        ctx_abs = ctx if os.path.isabs(ctx) else str((COMPOSE_DIR / ctx).resolve())
        if not Path(ctx_abs).is_dir():
            missing_ctx.append(name)
            continue
        if base in rep:
            continue  # one representative per distinct image
        spec = dict(spec)
        spec["context"] = ctx_abs
        rep[base] = (name, spec)

    if missing_ctx:
        print(
            f"{YELLOW}[~~]{RST} Skipping {len(missing_ctx)} target(s) with a missing build "
            f"context: {', '.join(sorted(missing_ctx))}"
        )

    # Partition by registry presence of the content tag. The presence probes
    # are independent registry round-trips, so run them concurrently (a serial
    # sweep of ~120 images costs minutes; threaded it's seconds).
    candidates = [
        (base, tname, spec, tags[base])
        for base, (tname, spec) in sorted(rep.items())
        if tags.get(base)
    ]
    if args.force:
        present_bases: set[str] = set()
    else:
        print(f"{YELLOW}[*]{RST} Checking registry for {len(candidates)} images...")
        workers = min(48, len(candidates)) or 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            flags = ex.map(lambda c: _registry_has(f"{c[0]}:{c[3]}"), candidates)
            present_bases = {c[0] for c, ok in zip(candidates, flags) if ok}

    # A published content tag says nothing about where `:latest` points, and `:latest`
    # is what `up`/`pull` actually resolve. An image can be present and still serve an
    # older `:latest` - a `--force` push of an earlier state, or a bake that retagged
    # it - and because presence alone skips it, nothing here would ever repair it.
    # `stale` reports that as LATEST-DRIFT; find it and fix it rather than only naming
    # it. (Under `--force` everything is rebuilt and both tags re-pushed, so the check
    # is pointless there.)
    drifted: list[tuple[str, str]] = []  # (base, content tag)

    def _has_drifted(item: tuple[str, str]) -> tuple[str, str] | None:
        base, tag = item
        want = _registry_digest(f"{base}:{tag}")
        if want is None:
            return None  # unreadable: never act on a probe that merely failed
        return item if _registry_digest(f"{base}:latest") != want else None

    if present_bases:
        pairs = [(c[0], c[3]) for c in candidates if c[0] in present_bases]
        workers = min(48, len(pairs)) or 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            drifted = [r for r in ex.map(_has_drifted, pairs) if r]

    to_build: dict[str, dict] = {}  # target name -> spec (tags rewritten to :hash + :latest)
    present = 0
    dirty_skipped: list[str] = []
    for base, tname, spec, tag in candidates:
        if base in present_bases:
            present += 1
            # Skipped because the HEAD-based content tag is already published --
            # but if the context has uncommitted edits, that "unchanged" image
            # actually has changed source that WON'T be pushed. Flag it.
            if _context_is_dirty(spec["context"]):
                dirty_skipped.append(base.rsplit("/", 1)[-1])
            continue
        spec = dict(spec)
        spec["tags"] = [f"{base}:{tag}", f"{base}:latest"]
        to_build[tname] = spec

    print(
        f"{BLUE}=== {len(rep)} distinct images: {present} already published, "
        f"{len(to_build)} to build/push ==={RST}"
    )
    if dirty_skipped:
        print(
            f"{YELLOW}[~~]{RST} {len(dirty_skipped)} skipped image(s) have UNCOMMITTED context "
            f"changes and will NOT be re-pushed until committed: {', '.join(sorted(dirty_skipped))}"
        )
    retag_failed: list[str] = []
    if drifted:
        print(
            f"{YELLOW}[~~]{RST} {len(drifted)} published image(s) serve a stale `:latest`; "
            f"re-pointing it at the content tag..."
        )
        for base, tag in drifted:
            # `imagetools create` copies an existing manifest under a new tag: no
            # rebuild, no pull, and the multi-platform index is preserved as-is. The
            # bytes we want `:latest` to serve are already in the registry.
            cmd = ["docker", "buildx", "imagetools", "create", "-t", f"{base}:latest"]
            res = _run([*cmd, f"{base}:{tag}"], check=False)
            short = base.rsplit("/", 1)[-1]
            if res.returncode == 0:
                print(f"{GREEN}[OK]{RST} {short}:latest -> {tag}")
            else:
                retag_failed.append(short)
        if retag_failed:
            print(
                f"{RED}[!!]{RST} could not re-tag {len(retag_failed)} image(s): "
                f"{', '.join(sorted(retag_failed))}"
            )

    if not to_build:
        if retag_failed:
            return 1
        if drifted:
            print(f"{GREEN}[OK]{RST} Re-pointed {len(drifted)} `:latest` tag(s); nothing to build.")
        else:
            print(f"{GREEN}[OK]{RST} Registry already up to date - nothing to build.")
        return 0

    names = sorted(to_build)
    failed: list[str] = []
    for start in range(0, len(names), args.batch):
        chunk = names[start : start + args.batch]
        bn = start // args.batch + 1
        defn = {
            "target": {n: to_build[n] for n in chunk},
            "group": {"default": {"targets": chunk}},
        }
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        try:
            json.dump(defn, fh)
            fh.close()
            print(f"{CYAN}--- batch {bn}: {', '.join(chunk)} ---{RST}")
            cmd = ["docker", "buildx", "bake", "-f", fh.name, "--push"]
            ok = _run(cmd, check=False).returncode == 0
            if not ok:
                print(f"{YELLOW}[~~]{RST} batch {bn} failed; retrying once...")
                ok = _run(cmd, check=False).returncode == 0
            if not ok:
                print(f"{RED}[!!]{RST} batch {bn} failed again")
                failed.extend(chunk)
        finally:
            os.unlink(fh.name)

    if failed:
        print(f"{RED}[!!]{RST} {len(failed)} target(s) failed: {', '.join(failed)}")
        return 1
    if retag_failed:
        return 1
    print(f"{GREEN}[OK]{RST} Pushed {len(names)} images to {registry}")
    return 0


def cmd_tags(args: argparse.Namespace) -> int:
    """Print the content-hash tag computed for each distinct mock image.

    Read-only: lets you eyeball the tags (and the service-sharing/de-dup) before
    `push`/`up` use them. Services that share a build context collapse to one
    image and share a tag.
    """
    _load_dotenv()
    config = _get_compose_config([*_all_args(), "--profile", "vuln-services"])
    specs = _image_specs(config)
    if not specs:
        print(
            f"{RED}[!!]{RST} No buildable images found (is OIDA_REGISTRY set in docker/mocks/.env?)."
        )
        return 1

    total_services = sum(len(s["services"]) for s in specs.values())
    print(
        f"{BLUE}=== {len(specs)} distinct images across {total_services} services "
        f"(de-dup saves {total_services - len(specs)} redundant builds) ==={RST}"
    )
    for base in sorted(specs):
        spec = specs[base]
        tag = _content_tag(spec)
        name = base.rsplit("/", 1)[-1]
        svcs = sorted(spec["services"])
        shared = f"  {DIM}<- {', '.join(svcs)}{RST}" if len(svcs) > 1 else ""
        print(f"  {name:<42} {GREEN}:{tag}{RST}{shared}")
    return 0


# Verdicts emitted by `stale`, worst first. This is both the report's sort order
# and the precedence when more than one could apply.
STALE_OK = "current"
STALE_MISSING = "MISSING"
STALE_UNCOMMITTED = "UNCOMMITTED"
STALE_UNPUBLISHED = "UNPUBLISHED"
STALE_DRIFT = "LATEST-DRIFT"
STALE_PROBE_ERROR = "PROBE-ERROR"
STALE_LOCAL = "LOCAL-STALE"
STALE_UNKNOWN = "LOCAL-UNKNOWN"
STALE_UNTAGGED = "NO-HASH-TAGS"
# Verdicts meaning "the registry does not serve the committed source" - these make
# `stale` exit non-zero and abort a release. UNPUBLISHED is appended conditionally
# in `cmd_stale`: it only blocks where content-hash tags are actually in use, so a
# publisher that pushes bare `:latest` can't wedge the gate permanently red.
STALE_BLOCKING = (STALE_MISSING, STALE_UNCOMMITTED, STALE_DRIFT)
_STALE_ORDER = (
    STALE_MISSING,
    STALE_UNCOMMITTED,
    STALE_UNPUBLISHED,
    STALE_DRIFT,
    STALE_PROBE_ERROR,
    STALE_LOCAL,
    STALE_UNKNOWN,
    STALE_UNTAGGED,
    STALE_OK,
)
_STALE_HINT = {
    STALE_MISSING: "never published - python services.py push",
    STALE_UNCOMMITTED: "commit the context, then: python services.py push",
    STALE_UNPUBLISHED: "python services.py push",
    STALE_DRIFT: "python services.py push --force",
    STALE_PROBE_ERROR: "registry unreadable - check `docker login`, then retry",
    STALE_LOCAL: "docker pull <image>:latest (or: python services.py up)",
    STALE_UNKNOWN: "built locally, never pulled - can't compare to the registry",
    STALE_UNTAGGED: "only ever published as :latest - python services.py push",
}


def _stale_report(
    *, check_local: bool = False, detail: bool = False
) -> tuple[list[dict], int] | None:
    """Classify every distinct mock image against the registry.

    Returns ``(rows, distinct_count)`` where each row is
    ``{image, tag, status, services}``, or None if there was nothing to check.
    """
    config = _get_compose_config([*_all_args(), "--profile", "vuln-services"])
    specs = _image_specs(config)
    if not specs:
        return None

    dirty = _dirty_contexts([s["context"] for s in specs.values()])
    tags = {base: _content_tag(spec) for base, spec in specs.items()}

    # Uncommitted contexts are classified without a probe: their HEAD-based tag
    # describes a source state that is NOT the working tree, so whatever the
    # registry holds under it can't be "current" either way.
    probe = [b for b in sorted(specs) if specs[b]["context"] not in dirty]

    def _classify(base: str) -> str:
        hash_ref, latest_ref = f"{base}:{tags[base]}", f"{base}:latest"
        # Tri-state presence first. A probe that merely *failed* is not evidence of
        # absence: an unauthenticated private repo is indistinguishable from one
        # that was never pushed, and calling that "never published" would abort a
        # release over a missing `docker login`.
        hash_state, latest_state = _registry_probe(hash_ref), _registry_probe(latest_ref)
        if PROBE_DENIED in (hash_state, latest_state):
            return STALE_PROBE_ERROR
        has_hash = hash_state == PROBE_PRESENT
        has_latest = latest_state == PROBE_PRESENT
        if not has_hash and not has_latest:
            return STALE_MISSING
        if not has_hash:
            # `:latest` is there but this source state isn't. Whether that means
            # "behind" depends on whether this repo is content-tagged at all: a repo
            # holding other tags was published by `push`, so a missing one is a real
            # gap; a repo holding only `:latest` was never tagged that way and cannot
            # be judged against the source. Unreadable (None) stays UNPUBLISHED and
            # defers to the sweep-wide fallback in `cmd_stale`.
            return STALE_UNTAGGED if _repo_hash_tagged(base) is False else STALE_UNPUBLISHED
        want = _registry_digest(hash_ref)
        got = _registry_digest(latest_ref) if has_latest else None
        if want is None or (has_latest and got is None):
            return STALE_PROBE_ERROR
        if got != want:
            return STALE_DRIFT
        if not check_local:
            return STALE_OK
        have = _local_ident(latest_ref)
        if have is None:
            return STALE_UNKNOWN
        return STALE_OK if have == want else STALE_LOCAL

    # Independent registry round-trips - threaded, as in `push` (a serial sweep of
    # ~120 images costs minutes).
    verdicts: dict[str, str] = {}
    if probe:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(48, len(probe))) as ex:
            verdicts = dict(zip(probe, ex.map(_classify, probe)))

    # Tag-list evidence, threaded for the same reason. Only asked where the answer
    # means something: UNPUBLISHED/NO-HASH-TAGS already have it cached from `_classify`
    # (it is what told them apart), and `detail` wants it for the rest so a verdict can
    # be read back to the registry state that produced it. Repos that just proved
    # unreadable are skipped - re-asking only fails again, one blocking call per image.
    detail_wanted = (STALE_OK, STALE_DRIFT, STALE_LOCAL, STALE_UNKNOWN)
    needs_tags = [
        b
        for b in probe
        if verdicts[b] in (STALE_UNPUBLISHED, STALE_UNTAGGED)
        or (detail and verdicts[b] in detail_wanted)
    ]
    seen_tags: dict[str, tuple[str, ...] | None] = {}
    if needs_tags:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(48, len(needs_tags))) as ex:
            seen_tags = dict(zip(needs_tags, ex.map(_registry_tags, needs_tags)))

    def _tagged(base: str) -> bool | None:
        """True/False/None: does this repo carry any tag besides `latest`?"""
        found = seen_tags.get(base)
        return None if found is None else any(t != "latest" for t in found)

    def _rel(path: str) -> str:
        """Context shown relative to the repo - absolute if it points outside it."""
        try:
            return str(Path(path).relative_to(PROJECT_ROOT))
        except ValueError:
            return path

    rows = [
        {
            "image": base.rsplit("/", 1)[-1],
            "tag": tags[base],
            "status": verdicts.get(base, STALE_UNCOMMITTED),
            # Lets `cmd_stale` decide whether UNPUBLISHED is real evidence of a stale
            # registry from what the registry actually says, rather than guessing from
            # the shape of the other verdicts.
            "hash_tagged": _tagged(base),
            "tags_seen": list(seen_tags.get(base) or ()) or None,
            "context": _rel(specs[base]["context"]),
            "services": sorted(specs[base]["services"]),
        }
        for base in sorted(specs)
    ]
    rows.sort(key=lambda r: (_STALE_ORDER.index(r["status"]), r["image"]))
    return rows, len(specs)


def cmd_stale(args: argparse.Namespace) -> int:
    """Report which mock images are outdated relative to the committed source.

    The read-only counterpart to ``push``: it answers "is the registry behind?"
    without building or pushing anything, so it can gate a release. Each distinct
    image gets one verdict:

    - ``current``       ``<image>:<hash>`` is published and ``:latest`` points at it.
    - ``MISSING``       no tag at all for this image - never published.
    - ``UNCOMMITTED``   the build context has uncommitted changes, so the
      HEAD-based content tag describes something other than the working tree and
      no image can match the source. Reported *instead of* ``current`` so an
      "up to date" summary never covers source that was never built.
    - ``UNPUBLISHED``   ``:latest`` exists and the repo *is* content-tagged, but not
      with this source state's tag - the registry is genuinely behind the source.
    - ``NO-HASH-TAGS``  ``:latest`` exists and is the only tag the repo has ever
      held, so there is nothing to compare the source against. Reported, never
      blocking: absence of tagging is not evidence of staleness.
    - ``LATEST-DRIFT``  ``<image>:<hash>`` exists but ``:latest`` resolves
      elsewhere. Compose pins ``:latest``, so ``up`` would run the wrong image.
    - ``PROBE-ERROR``   the registry could not be read (commonly: private repo, no
      ``docker login``). Never counted as outdated - "cannot verify" exits 2, so
      neither a flaky network nor a missing credential can fail a release.
    - ``LOCAL-STALE``   (``--local``) the image on this machine isn't the published
      one. Not a release blocker - it's a ``docker pull`` away.
    - ``LOCAL-UNKNOWN`` (``--local``) the local image was built here, not pulled,
      so it has no RepoDigest to compare.

    The UNPUBLISHED/NO-HASH-TAGS split is decided per image by listing the repo's
    tags: one holding anything besides ``:latest`` was published by ``push``, so a
    missing content tag there is a real gap and blocks. That keeps images published
    as bare ``:latest`` from wedging the gate red - the CI workflow that did that
    (a raw ``buildx bake --push``) is gone, but the tags it left in the registry
    are not - without hiding an image that ``push`` once tagged and has since
    fallen behind, the case the gate exists for. Where the tag list can't be
    read the verdict stays UNPUBLISHED, and blocks only if hash tags are in use
    elsewhere in the sweep.

    Exit: 0 = registry serves the committed source, 1 = something is outdated,
    2 = could not check (no docker, no compose config, registry unreadable).
    """
    _load_dotenv()
    if not _check_docker():
        return 2

    verbose = bool(getattr(args, "verbose", False))
    report = _stale_report(check_local=bool(getattr(args, "local", False)), detail=verbose)
    if report is None:
        print(f"{RED}[!!]{RST} No buildable images found.")
        return 2
    rows, distinct = report

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    # Is content-hash tagging actually in use? Ask the registry first: any repo holding
    # a tag besides `latest` was published by `push`, which is proof regardless of
    # whether that image is currently up to date. The verdict-based fallback behind it
    # only sees repos whose *current* hash tag resolved, so on its own it misses the
    # case this gate exists for - an image tagged by a past `push` that has since
    # fallen behind reads exactly like one that was never tagged at all.
    hash_tagging_in_use = any(row["hash_tagged"] for row in rows) or any(
        counts.get(s) for s in (STALE_OK, STALE_DRIFT, STALE_LOCAL, STALE_UNKNOWN)
    )
    blocking_statuses = list(STALE_BLOCKING)
    if hash_tagging_in_use:
        blocking_statuses.append(STALE_UNPUBLISHED)
    blocking = sum(counts.get(s, 0) for s in blocking_statuses)
    unverifiable = counts.get(STALE_PROBE_ERROR, 0)

    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "images": rows,
                    "counts": counts,
                    "outdated": blocking,
                    "unverifiable": unverifiable,
                    "hash_tagging_in_use": hash_tagging_in_use,
                },
                indent=2,
            )
        )
        return 2 if unverifiable and not blocking else (1 if blocking else 0)

    colour = {
        STALE_OK: GREEN,
        STALE_MISSING: RED,
        STALE_UNCOMMITTED: RED,
        STALE_UNPUBLISHED: RED if hash_tagging_in_use else YELLOW,
        STALE_DRIFT: RED,
        STALE_PROBE_ERROR: YELLOW,
        STALE_LOCAL: YELLOW,
        STALE_UNKNOWN: DIM,
        STALE_UNTAGGED: DIM,
    }
    print(f"{BLUE}=== {distinct} distinct images vs {os.environ['OIDA_REGISTRY']} ==={RST}")
    for row in rows:
        status = row["status"]
        if status == STALE_OK and not verbose:
            continue
        print(
            f"  {row['image']:<42} {DIM}:{row['tag']}{RST} "
            f"{colour[status]}{status:<14}{RST}{DIM}{_STALE_HINT.get(status, '')}{RST}"
        )
        if not verbose:
            continue
        # The evidence behind the verdict: which tags the registry actually serves,
        # and which committed directory produced the content tag it was compared to.
        # Without those, a verdict is an assertion the reader has to take on faith.
        served = ", ".join(row["tags_seen"]) if row["tags_seen"] else "(none)"
        print(f"{DIM}      registry tags: {served}{RST}")
        print(f"{DIM}      context:       {row['context']}{RST}")
        print(f"{DIM}      services:      {', '.join(row['services'])}{RST}")
    summary = "  ".join(f"{colour[s]}{counts[s]} {s}{RST}" for s in _STALE_ORDER if counts.get(s))
    print(f"{BLUE}---{RST} {summary}")

    if counts.get(STALE_UNTAGGED):
        print(
            f"{YELLOW}[~~]{RST} {counts[STALE_UNTAGGED]} image(s) carry no content-hash "
            f"tag at all, so they cannot be checked against the source - reported, not "
            f"failed.\n"
            f"{DIM}     They were published as bare `:latest` by the retired CI bake "
            f"workflow, which bypassed the content-hash tagging in `services.py push`. "
            f"For these images this check can prove an image exists, not that it "
            f"matches the source - `python services.py push` gives them a content tag.{RST}"
        )

    if blocking:
        print(
            f"{RED}[!!]{RST} {blocking} image(s) are not published from the committed "
            f"source. Run: {BOLD}python services.py push{RST}"
        )
        return 1

    if unverifiable:
        print(
            f"{YELLOW}[~~]{RST} {unverifiable} image(s) could not be read from "
            f"{os.environ['OIDA_REGISTRY']} - unverified, not outdated. "
            f"Check `docker login`."
        )
        return 2

    print(f"{GREEN}[OK]{RST} Registry serves the committed source for every mock image.")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove containers, volumes, and local images."""
    _ = args
    print(f"{BLUE}=== Cleaning Mock Resources ==={RST}")
    _run(
        _compose_cmd(*_all_args(), "--profile", "vuln-services", "down", "-v", "--rmi", "local"),
        check=False,
    )
    logs_dir = PROJECT_ROOT / "docker" / "logs"
    if logs_dir.exists():
        shutil.rmtree(logs_dir, ignore_errors=True)
        logs_dir.mkdir(exist_ok=True)
    print(f"{GREEN}[OK]{RST} Cleanup complete")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all available services from compose labels."""
    filt = (getattr(args, "filter", None) or "").lower()

    def _match(row: dict) -> bool:
        if not filt:
            return True
        return filt in row.get("group", "").lower() or filt in row.get("service", "").lower()

    def _render_services(rows: list[dict], show_cve: bool = False) -> None:
        prev_group = ""
        for row in rows:
            group = row.get("group", "")
            if not group:
                continue
            if group != prev_group:
                if prev_group:
                    print()
                print(f"  {BOLD}{group:<16}{RST}", end="")
                prev_group = group
            else:
                print(f"  {'':<16}", end="")

            svc = row.get("service", "")
            ports = row.get("ports", "")
            desc = row.get("description", "")
            cve = row.get("cve", "")
            if show_cve and cve:
                print(f" {DIM}{svc:<32}{RST} {ports:<14} {RED}{cve:<20}{RST} {desc}")
            else:
                print(f" {DIM}{svc:<32}{RST} {ports:<14} {'':<20} {desc}")

    # --- Core services ---
    core_config = _get_compose_config(_core_args())
    core_rows = []
    for svc_name, svc_def in sorted(core_config.get("services", {}).items()):
        labels = svc_def.get("labels", {})
        group = labels.get("oida.group", "")
        if group:
            core_rows.append(
                {
                    "group": group,
                    "service": svc_name,
                    "ports": labels.get("oida.ports", ""),
                    "description": labels.get("oida.description", ""),
                    "cve": "",
                }
            )
    core_rows.sort(key=lambda r: r["group"])
    core_rows = [r for r in core_rows if _match(r)]

    if core_rows or not filt:
        print(f"{BOLD}{CYAN}=== Core Services ==={RST}  {DIM}python services.py up{RST}")
        hdr = (
            f"  {BOLD}{CYAN}{'GROUP':<16} {'SERVICE':<32} {'PORT(S)':<14} "
            f"{'':<20} {'DESCRIPTION'}{RST}"
        )
        sep = f"  {DIM}{'---':<16} {'---':<32} {'---':<14} {'':<20} {'---'}{RST}"
        print(hdr)
        print(sep)
        _render_services(core_rows)
        print()

    # --- CVE services ---
    cve_config = _get_compose_config([*_all_args(), "--profile", "vuln-services"])
    cve_rows = []
    for svc_name, svc_def in sorted(cve_config.get("services", {}).items()):
        labels = svc_def.get("labels", {})
        cve_id = labels.get("oida.cve", "")
        if cve_id:
            cve_rows.append(
                {
                    "group": labels.get("oida.group", ""),
                    "service": svc_name,
                    "ports": labels.get("oida.ports", ""),
                    "description": labels.get("oida.description", ""),
                    "cve": cve_id,
                }
            )
    cve_rows.sort(key=lambda r: r["group"])
    cve_rows = [r for r in cve_rows if _match(r)]

    if cve_rows or not filt:
        print(f"{BOLD}{CYAN}=== CVE Services ==={RST}  {DIM}python services.py up cve{RST}")
        hdr_cve = (
            f"  {BOLD}{CYAN}{'GROUP':<16} {'SERVICE':<32} {'PORT(S)':<14} {'CVE':<20}"
            f" {'DESCRIPTION'}{RST}"
        )
        sep_cve = f"  {DIM}{'---':<16} {'---':<32} {'---':<14} {'---':<20} {'---'}{RST}"
        print(hdr_cve)
        print(sep_cve)
        _render_services(cve_rows, show_cve=True)
        print()

    if filt and not core_rows and not cve_rows:
        print(f"{YELLOW}[~~]{RST} No services match '{filt}'. Try: python services.py groups")
    return 0


def cmd_ports(args: argparse.Namespace) -> int:
    """Show port mappings of currently running containers."""
    _ = args

    print(f"{BOLD}{CYAN}=== Running Service Ports ==={RST}")
    print(f"  {BOLD}{'PORT':<8} {'PROTOCOL':<20} {'SERVICE':<30} {'STATUS'}{RST}")
    print(f"  {DIM}{'---':<8} {'---':<20} {'---':<30} {'---'}{RST}")

    # (#5) Use JSON output from docker compose ps
    ps_cmd = _compose_cmd(*_all_args(), "ps", "--format", "json")
    result = _run(ps_cmd, capture=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        print(f"  {DIM}No running services. Start with: python services.py up{RST}")
        print()
        return 0

    # Parse JSON - docker compose ps --format json outputs one JSON object per line
    containers = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not containers:
        print(f"  {DIM}No running services. Start with: python services.py up{RST}")
        print()
        return 0

    found = 0
    seen: set[str] = set()

    for container in sorted(containers, key=lambda c: c.get("Name", "")):
        name = container.get("Name", "")
        state_str = container.get("State", "").lower()
        health = container.get("Health", "").lower()

        if health == "healthy":
            state = "healthy"
        elif state_str == "running":
            state = "running"
        elif state_str == "exited":
            state = "exited"
        else:
            state = state_str or "unknown"

        # Get protocol group label
        inspect_cmd = [
            "docker",
            "inspect",
            "--format",
            '{{index .Config.Labels "oida.group"}}',
            name,
        ]
        inspect_result = _run(inspect_cmd, capture=True, check=False)
        proto = inspect_result.stdout.strip() if inspect_result.returncode == 0 else ""
        if not proto or proto == "<no value>":
            proto = "unknown"

        # Extract host port mappings from Publishers array or fall back to Ports string
        publishers = container.get("Publishers", [])
        if publishers:
            for pub in publishers:
                host_port = str(pub.get("PublishedPort", 0))
                if host_port == "0":
                    continue
                key = f"{host_port}:{name}"
                if key in seen:
                    continue
                seen.add(key)

                if state in ("healthy", "running"):
                    status = f"{GREEN}{state}{RST}"
                else:
                    status = f"{RED}{state}{RST}"

                print(f"  {host_port:<8} {proto:<20} {name:<30} {status}")
                found += 1
        else:
            # Fallback: parse Ports string
            ports_str = container.get("Ports", "")
            for match in re.finditer(r"0\.0\.0\.0:(\d+)->", ports_str):
                host_port = match.group(1)
                key = f"{host_port}:{name}"
                if key in seen:
                    continue
                seen.add(key)

                if state in ("healthy", "running"):
                    status = f"{GREEN}{state}{RST}"
                else:
                    status = f"{RED}{state}{RST}"

                print(f"  {host_port:<8} {proto:<20} {name:<30} {status}")
                found += 1

    if found == 0:
        print(f"  {DIM}No running services. Start with: python services.py up{RST}")
    print()
    return 0


def cmd_up_cve(args: argparse.Namespace) -> int:
    """Start specific CVE protocol group."""
    proto = args.proto
    print(f"{BLUE}=== Starting CVE services: vuln-{proto} ==={RST}")
    _pull(_all_args(), profiles=(f"vuln-{proto}",))
    _run(_compose_cmd(*_all_args(), "--profile", f"vuln-{proto}", "up", "-d"))
    return 0


def _up_proto_impl(group: str, *, quiet_pull: bool = False, with_cve: bool = False) -> int:
    """Start every service in an oida.group - core members by default.

    CVE members (services carrying an ``oida.cve`` label) are excluded unless
    *with_cve* is set: they are vulnerable-by-design targets that must be
    started deliberately (``up <group> --with-cve`` or ``up-cve <proto>``),
    and unlike the core mocks many are not published to the registry, so a
    group up would otherwise trigger a fleet of fragile source builds.

    Reads config with the ``vuln-services`` umbrella profile active so CVE
    members of the group resolve (mirrors ``cmd_list``); the actual profiles to
    enable are then collected per-service from each resolved service's
    ``profiles:`` field, so ``vuln-*`` and core profiles (goose-l2, ...) get
    picked up automatically.
    """
    compose_args = _all_args()
    config = _get_compose_config([*compose_args, "--profile", "vuln-services"])
    services = _resolve_services_by_group(group, compose_args, config=config)
    if not with_cve:
        core_only = [
            s
            for s in services
            if not config.get("services", {}).get(s, {}).get("labels", {}).get("oida.cve")
        ]
        if core_only != services:
            skipped = sorted(set(services) - set(core_only))
            print(
                f"{YELLOW}[*]{RST} Skipping {len(skipped)} CVE service(s) "
                f"(opt in with --with-cve or up-cve): {', '.join(skipped)}"
            )
        services = core_only

    # Fallback: exact compose service name (e.g. `up hl7-mock` to start one
    # container instead of the whole `hl7` group). A group match takes
    # precedence, so an oida.group value always wins if a group and a service
    # ever share a name; a service name is only tried once no group matched.
    banner = f"{group} services"
    if not services and group in config.get("services", {}):
        services = [group]
        banner = group

    if not services:
        print(
            f"{RED}[!!]{RST} No services found for '{group}' (no matching oida.group or service name)"
        )
        print("    Available groups (or run: services.py groups):")
        for g in sorted(_all_groups(config)):
            print(f"      {g}")
        return 1

    print(f"{BLUE}=== Starting {banner} ==={RST}")

    # (#1) Collect profiles required by resolved services - set-based dedup
    seen_profiles: set[str] = set()
    profile_args: list[str] = []
    for svc in services:
        svc_def = config.get("services", {}).get(svc, {})
        for p in svc_def.get("profiles", []):
            if p not in seen_profiles:
                seen_profiles.add(p)
                profile_args.extend(["--profile", p])

    # Pull pre-built images first, then start (building anything still missing)
    _pull(compose_args, profiles=tuple(seen_profiles), services=tuple(services), quiet=quiet_pull)
    _clear_conflicting_containers(config, services=set(services))
    cmd = _compose_cmd(*compose_args, *profile_args, "up", "-d", *services)
    _run(cmd)

    # Wait for healthchecks
    print(f"{YELLOW}[*]{RST} Waiting for healthchecks...")
    all_ok = True
    for svc in services:
        if not _wait_service_healthy(svc, compose_args, timeout=60):
            all_ok = False

    # Show results
    for svc in services:
        svc_def = config.get("services", {}).get(svc, {})
        labels = svc_def.get("labels", {})
        ports = labels.get("oida.ports", "L2")
        desc = labels.get("oida.description", "")
        if all_ok:
            print(f"  {GREEN}[OK]{RST} {svc} ({ports}) - {desc}")
        else:
            print(f"  {YELLOW}[??]{RST} {svc} ({ports}) - {desc}")

    return 0


def _wait_service_healthy(service: str, compose_args: list[str], *, timeout: int = 60) -> bool:
    """Wait for a single service to become healthy.

    Returns True if healthy, False if unhealthy or timed out.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Get container ID
        id_cmd = _compose_cmd(*compose_args, "ps", "-q", service)
        id_result = _run(id_cmd, capture=True, check=False)
        container_id = id_result.stdout.strip()
        if not container_id:
            time.sleep(2)
            continue

        health_cmd = [
            "docker",
            "inspect",
            "--format",
            "{{.State.Health.Status}}",
            container_id,
        ]
        health_result = _run(health_cmd, capture=True, check=False)

        # (#13) Non-zero return = container not found
        if health_result.returncode != 0:
            time.sleep(2)
            continue

        health = health_result.stdout.strip()

        if health == "healthy":
            return True
        elif health == "none":
            # No healthcheck defined - treat as OK
            return True
        elif health == "unhealthy":
            print(f"  {RED}[!!]{RST} {service} unhealthy")
            return False
        time.sleep(2)

    # Timed out
    return False


def cmd_up_proto(args: argparse.Namespace) -> int:
    """Start services by oida.group label (alias of `up <group>`)."""
    return _up_proto_impl(args.group, with_cve=getattr(args, "with_cve", False))


def cmd_groups(args: argparse.Namespace) -> int:
    """List every oida.group value from compose labels (valid `up <group>` args)."""
    _ = args
    core = _get_compose_config(_core_args())
    full = _get_compose_config([*_all_args(), "--profile", "vuln-services"])
    groups = _all_groups(full)
    if not groups:
        print(
            f"{RED}[!!]{RST} No service groups found (is docker/mocks/.env set with OIDA_REGISTRY?)"
        )
        return 1

    print(f"{BLUE}=== Service groups ({len(groups)}) ==={RST}")
    for g in sorted(groups):
        n_core = len(_resolve_services_by_group(g, [], config=core))
        n_total = len(_resolve_services_by_group(g, [], config=full))
        n_cve = n_total - n_core
        if n_core and n_cve:
            origin = f"{n_core} core + {n_cve} cve"
        elif n_cve:
            origin = f"{n_cve} cve"
        else:
            origin = f"{n_core} core"
        print(f"  {GREEN}{g:<18}{RST} {DIM}{origin}{RST}")
    print(f"\n{DIM}Start a group with:  services.py up <group>{RST}")
    print(f"{DIM}Start one service:   services.py up <service>  (e.g. hl7-mock){RST}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="services.py",
        description="OIDA task runner - mock/docker service management",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # Infrastructure commands
    p_up = sub.add_parser("up", help="Start mock services [core|cve|all|<group>|<service>]")
    p_up.add_argument(
        "stack",
        nargs="?",
        default="core",
        help="What to start: core|cve|all, an oida.group (e.g. hl7), "
        "or a single compose service name (e.g. hl7-mock). Default: core",
    )
    p_up.add_argument(
        "--build",
        action="store_true",
        help="Force a local image rebuild instead of pulling pre-built images from $OIDA_REGISTRY",
    )
    p_up.add_argument(
        "--no-pull",
        action="store_true",
        help="Skip the registry pull; build any missing images locally",
    )
    p_up.add_argument(
        "--quiet-pull",
        action="store_true",
        help="Hide docker pull progress/warnings (default shows normal docker output)",
    )
    p_up.add_argument(
        "--with-cve",
        action="store_true",
        help="Include CVE/vulnerable services when starting a group "
        "(they are skipped by default; also available via up-cve)",
    )

    sub.add_parser("down", help="Stop all mock services")
    sub.add_parser("restart", help="Restart mock services")
    p_status = sub.add_parser("status", help="Show a health overview of the containers")
    p_status.add_argument(
        "filter", nargs="?", default=None, help="Only show containers matching this name or group"
    )
    p_status.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Also print a per-container Name/Status/Ports table",
    )

    p_logs = sub.add_parser("logs", help="Follow logs (optionally for a specific service)")
    p_logs.add_argument("service", nargs="*", default=[], help="Service name(s)")

    p_build = sub.add_parser("build", help="Build images without starting")
    p_build.add_argument("stack", nargs="?", default="core", help="Stack to build (default: core)")

    p_push = sub.add_parser(
        "push", help="Build & push mock images to $OIDA_REGISTRY (skips unchanged)"
    )
    p_push.add_argument(
        "--batch",
        type=int,
        default=10,
        help="Targets to build+push per batch (default: 10; lower if buildkit drops jobs)",
    )
    p_push.add_argument(
        "--force",
        action="store_true",
        help="Rebuild and re-push every image even if its content tag is already published",
    )

    sub.add_parser("clean", help="Remove containers, volumes, and local images")

    # Discovery commands
    p_list = sub.add_parser("list", help="List all available services (reads compose labels)")
    p_list.add_argument(
        "filter",
        nargs="?",
        help="Only show services whose group or name contains this text "
        "(e.g. `list modbus`). Omit to list everything.",
    )
    sub.add_parser("ports", help="Show port mappings of currently running containers")
    sub.add_parser("groups", help="List oida.group values from compose (valid `up <group>` args)")
    sub.add_parser("tags", help="Show the content-hash tag computed for each distinct image")

    p_stale = sub.add_parser(
        "stale",
        help="Check which mock images are outdated vs the registry (exit 1 if any)",
    )
    p_stale.add_argument(
        "--local",
        action="store_true",
        help="Also check whether the image pulled on this machine is the published one",
    )
    p_stale.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="List up-to-date images too (default: only outdated ones)",
    )
    p_stale.add_argument("--json", action="store_true", help="Emit the report as JSON")

    # CVE command
    p_cve = sub.add_parser("up-cve", help="Start specific CVE protocol group")
    p_cve.add_argument("proto", help="CVE protocol group (smtp, dns, mqtt, ...)")

    # Generic proto command - alias of `up <group>`
    p_proto = sub.add_parser("up-proto", help="Start services by oida.group label")
    p_proto.add_argument("group", help="Protocol group name")
    p_proto.add_argument(
        "--with-cve",
        action="store_true",
        help="Include CVE/vulnerable services (skipped by default)",
    )

    return parser


# (#11) Proper type annotation for dispatch table
COMMAND_DISPATCH: dict[str, Callable[[argparse.Namespace], int]] = {
    "up": cmd_up,
    "down": cmd_down,
    "restart": cmd_restart,
    "status": cmd_status,
    "logs": cmd_logs,
    "build": cmd_build,
    "push": cmd_push,
    "clean": cmd_clean,
    "list": cmd_list,
    "ports": cmd_ports,
    "up-cve": cmd_up_cve,
    "up-proto": cmd_up_proto,
    "groups": cmd_groups,
    "tags": cmd_tags,
    "stale": cmd_stale,
}


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handler = COMMAND_DISPATCH.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    # (#9) Docker pre-flight check for commands that need it. `list`/`groups`
    # only read compose labels (no daemon required).
    label_only = ("list", "groups", "tags")
    needs_docker = args.command not in label_only
    if needs_docker and not _check_docker():
        return 1

    # (#10) Compose file check for commands that need compose
    needs_compose = args.command not in label_only
    if needs_compose and not _check_compose_file():
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
