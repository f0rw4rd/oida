#!/usr/bin/env python3
"""OIDA service manager — manages mock ICS services for testing and development.

Usage:
    python services.py up [core|cve|all|<group>]
    python services.py down
    python services.py status
    python services.py logs [service...]
    python services.py list
    python services.py ports
    python services.py push                  # build & push all mock images to $OIDA_REGISTRY
    python services.py up-goose
    python services.py up-proto <group>
    ...

Install: no extra dependencies (stdlib only).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
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

WAIT_HEALTHY_TIMEOUT = 90
WAIT_HEALTHY_INTERVAL = 3
PORT_CHECK_TIMEOUT = 2
STARTUP_DELAY = 3

# ANSI colours — disabled when piped or NO_COLOR is set (#8)
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
        return
    for raw in env_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


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
                    # No rejection — port is likely open
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
    """Get parsed compose config as a dict."""
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


def _pull(
    compose_args: list[str],
    *,
    profiles: tuple[str, ...] = (),
    services: tuple[str, ...] = (),
) -> None:
    """Best-effort pull of pre-built images from the configured registry.

    Buildable services carry an ``image:`` of ``$OIDA_REGISTRY/oida-mock-*``,
    so ``pull`` grabs the published image when available. ``OIDA_REGISTRY`` is
    required (compose fails hard if unset); set it in a gitignored
    ``docker/mocks/.env`` — see ``docker/mocks/.env.example``. Failures (offline,
    image not yet published, third-party images) are swallowed — the subsequent
    ``up`` builds whatever is still missing locally.
    """
    profile_args: list[str] = []
    for p in profiles:
        profile_args.extend(["--profile", p])
    print(f"{YELLOW}[*]{RST} Pulling pre-built images (will build locally on miss)...")
    _run(
        _compose_cmd(*compose_args, *profile_args, "pull", "--ignore-pull-failures", *services),
        check=False,
        suppress_stderr=True,
    )


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
            _pull(_core_args())
        _run(_compose_cmd(*_core_args(), "up", "-d", *build_flag))
        ok = wait_healthy(_all_args())
        return 0 if ok else 1

    elif stack in ("cve", "all"):
        label = "Core + CVE" if stack == "cve" else "All"
        print(f"{BLUE}=== Starting {label} Services ==={RST}")
        if not args.build and not args.no_pull:
            _pull(_all_args(), profiles=("vuln-services",))
        _run(_compose_cmd(*_all_args(), "--profile", "vuln-services", "up", "-d", *build_flag))
        ok = wait_healthy(_all_args())
        return 0 if ok else 1

    else:
        # Treat as protocol group name — delegate to up-proto logic
        return _up_proto_impl(stack)


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
    """Show status of running containers."""
    _ = args
    print(f"{BLUE}=== OIDA Mock Services Status ==={RST}")
    print("")
    result = _run(_compose_cmd(*_all_args(), "ps"), check=False)
    if result.returncode != 0:
        print("  No containers found")
    print("")
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
    """Build every buildable mock image and push it to ``$OIDA_REGISTRY``.

    This is the registry sync command: re-run it after editing ``docker/mocks/**``
    and bake's content-addressed cache only rebuilds/re-pushes what changed.

    Two warts are handled so it stays one command:
    - Targets whose build context is missing on disk (e.g. the never-committed
      ``services/memcached/cve``) are skipped — a raw ``bake --push`` aborts the
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

    # Enumerate every bake target from the compose files (profiles are ignored
    # by bake, so this covers core mocks + all CVE services).
    bake_files = ["-f", COMPOSE_CORE, "-f", COMPOSE_CVE]
    res = _run(["docker", "buildx", "bake", *bake_files, "--print"], check=False, capture=True)
    if res.returncode != 0:
        print(f"{RED}[!!]{RST} 'docker buildx bake --print' failed:\n{res.stderr}")
        return 1
    targets = json.loads(res.stdout).get("target", {})

    # Drop targets whose build context dir is missing; rewrite the rest to
    # absolute paths so the generated per-batch bake files resolve regardless of
    # the current working directory.
    valid: dict[str, dict] = {}
    skipped: list[str] = []
    for name, spec in targets.items():
        ctx = spec.get("context", ".")
        ctx_abs = ctx if os.path.isabs(ctx) else str((COMPOSE_DIR / ctx).resolve())
        if not Path(ctx_abs).is_dir():
            skipped.append(name)
            continue
        spec["context"] = ctx_abs
        valid[name] = spec

    if skipped:
        print(
            f"{YELLOW}[~~]{RST} Skipping {len(skipped)} target(s) with a missing build "
            f"context: {', '.join(sorted(skipped))}"
        )

    names = sorted(valid)
    if not names:
        print(f"{RED}[!!]{RST} No buildable targets found.")
        return 1
    print(f"{BLUE}=== Pushing {len(names)} mock images to {registry} ==={RST}")

    failed: list[str] = []
    for start in range(0, len(names), args.batch):
        chunk = names[start : start + args.batch]
        bn = start // args.batch + 1
        defn = {
            "target": {n: valid[n] for n in chunk},
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
    print(f"{GREEN}[OK]{RST} Pushed {len(names)} images to {registry}")
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
    _ = args

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

    print(f"{BOLD}{CYAN}=== Core Services ==={RST}  {DIM}python services.py up{RST}")
    hdr = (
        f"  {BOLD}{CYAN}{'GROUP':<16} {'SERVICE':<32} {'PORT(S)':<14} {'':<20} {'DESCRIPTION'}{RST}"
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

    # Parse JSON — docker compose ps --format json outputs one JSON object per line
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


def _up_proto_impl(group: str) -> int:
    """Start services by oida.group label (shared implementation)."""
    compose_args = _core_args()
    # (#3) Call _get_compose_config once and pass it through
    config = _get_compose_config(compose_args)
    services = _resolve_services_by_group(group, compose_args, config=config)

    if not services:
        print(f"{RED}[!!]{RST} No services found with oida.group={group}")
        print("    Available groups:")
        groups: set[str] = set()
        for svc_def in config.get("services", {}).values():
            g = svc_def.get("labels", {}).get("oida.group", "")
            if g:
                groups.add(g)
        for g in sorted(groups):
            print(f"      {g}")
        return 1

    print(f"{BLUE}=== Starting {group} services ==={RST}")

    # (#1) Collect profiles required by resolved services — set-based dedup
    seen_profiles: set[str] = set()
    profile_args: list[str] = []
    for svc in services:
        svc_def = config.get("services", {}).get(svc, {})
        for p in svc_def.get("profiles", []):
            if p not in seen_profiles:
                seen_profiles.add(p)
                profile_args.extend(["--profile", p])

    # Pull pre-built images first, then start (building anything still missing)
    _pull(compose_args, profiles=tuple(seen_profiles), services=tuple(services))
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
            # No healthcheck defined — treat as OK
            return True
        elif health == "unhealthy":
            print(f"  {RED}[!!]{RST} {service} unhealthy")
            return False
        time.sleep(2)

    # Timed out
    return False


def cmd_up_proto(args: argparse.Namespace) -> int:
    """Start services by oida.group label."""
    return _up_proto_impl(args.group)


# ---------------------------------------------------------------------------
# Data-driven per-protocol commands (#6)
# ---------------------------------------------------------------------------

PROTO_SPECS: dict[str, dict] = {
    "up-goose": {
        "header": "GOOSE L2 Publisher",
        "services": ["goose-l2-publisher"],
        "ports": [],
        "compose_args": ["--profile", "goose-l2"],
        "info_lines": [],
    },
    "up-ocpp": {
        "header": "OCPP Mock CSMS",
        "services": ["ocpp-insecure"],
        "ports": [(9000, "OCPP Insecure", False), (9001, "OCPP Secure", False)],
        "compose_args": [],
        "info_lines": [
            f"{GREEN}[+]{RST} Insecure CSMS: ws://localhost:9000/CP_001",
            f"{GREEN}[+]{RST} Secure CSMS:   ws://localhost:9001/CP_001 (CP001:SecureKey123)",
        ],
    },
    "up-can": {
        "header": "CAN Bus Mock Server",
        "services": ["can-mock"],
        "ports": [],
        "compose_args": ["--profile", "can"],
        "info_lines": [
            f"{GREEN}[OK]{RST} CAN mock started on UDP multicast 239.0.0.1:43113 (host networking)",
        ],
    },
    "up-hart": {
        "header": "HART Mock Servers",
        "services": ["hart-mock", "hart-secondary", "hart-tertiary"],
        "ports": [(5094, "HART-IP UDP", True), (5095, "HART-IP TCP", False)],
        "compose_args": [],
        "info_lines": [],
    },
    "up-mqtt": {
        "header": "MQTT Mock Brokers",
        "services": [
            "mqtt-insecure",
            "mqtt-auth",
            "mqtt-sparkplug",
            "mqtt-busy",
            "mqtt-tls",
            "mqtt-busy-tls",
        ],
        "ports": [
            (1883, "MQTT Insecure", False),
            (1884, "MQTT Auth", False),
            (8883, "MQTT TLS", False),
        ],
        "compose_args": [],
        "info_lines": [],
    },
    "up-opcua": {
        "header": "OPC UA Mock Servers",
        "services": ["opcua-advanced", "opcua-gds", "opcua-insecure"],
        "ports": [
            (4841, "OPC UA Advanced", False),
            (4842, "OPC UA Insecure", False),
            (4850, "OPC UA GDS", False),
        ],
        "compose_args": [],
        "info_lines": [],
    },
    "up-snmp": {
        "header": "SNMP Mock Server",
        "services": ["snmp-mock"],
        "ports": [(10161, "SNMP", True)],
        "compose_args": [],
        "info_lines": [],
    },
    "up-snmp-v3only": {
        "header": "SNMPv3-Only Mock Server",
        "services": ["snmp-v3only"],
        "ports": [(10164, "SNMP-v3only", True)],
        "compose_args": [],
        "info_lines": [],
    },
    "up-http2": {
        "header": "HTTP/2 Mock Servers",
        "services": ["http2-nghttp2", "http2-python"],
        "ports": [
            (8280, "HTTP/2 nghttp2 TLS", False),
            (9443, "HTTP/2 Python TLS", False),
        ],
        "compose_args": [],
        "info_lines": [],
    },
    "up-astm": {
        "header": "ASTM Mock Servers",
        "services": ["astm-mock", "astm-hematology", "astm-data"],
        "ports": [
            (1394, "ASTM E1394", False),
            (1395, "ASTM Hematology", False),
            (1396, "ASTM Data", False),
        ],
        "compose_args": [],
        "info_lines": [],
    },
    "up-fhir": {
        "header": "FHIR Mock Server",
        "services": ["fhir-mock"],
        "ports": [(8081, "FHIR R4", False)],
        "compose_args": [],
        "info_lines": [],
    },
    "up-opener": {
        "header": "OpENer EtherNet/IP Server",
        "services": ["ethernetip-opener"],
        "ports": [(44819, "OpENer EtherNet/IP", False)],
        "compose_args": [],
        "info_lines": [],
    },
    "up-modbus-vuln": {
        "header": "Modbus Vuln + SunSpec Servers",
        "services": [
            "modbus-vuln",
            "modbus-sunspec",
            "modbus-cve-2024-10918",
            "modbus-cve-2022-0367",
            "modbus-cve-2023-26793",
            "modbus-cve-2019-14462",
            "modbus-cve-2019-14463",
        ],
        "ports": [
            (5020, "Modbus Vuln", False),
            (5502, "Modbus SunSpec", False),
        ],
        "compose_args": [],
        "info_lines": [],
    },
}


def _cmd_up_proto_generic(args: argparse.Namespace, spec: dict) -> int:
    """Generic handler for data-driven per-protocol commands."""
    _ = args
    print(f"{BLUE}=== Starting {spec['header']} ==={RST}")
    spec_profiles = tuple(spec["compose_args"][1::2])  # ["--profile", p, ...] -> (p, ...)
    _pull(_core_args(), profiles=spec_profiles, services=tuple(spec["services"]))
    compose = _compose_cmd(*_core_args(), *spec["compose_args"], "up", "-d", *spec["services"])
    _run(compose)

    if spec["ports"]:
        time.sleep(STARTUP_DELAY)
        for port, label, is_udp in spec["ports"]:
            if is_udp:
                check_port_udp(port, label)
            else:
                check_port(port, label)

    for line in spec.get("info_lines", []):
        print(line)

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="services.py",
        description="OIDA task runner — mock/docker service management",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # Infrastructure commands
    p_up = sub.add_parser("up", help="Start mock services [core|cve|all|<group>]")
    p_up.add_argument("stack", nargs="?", default="core", help="Stack to start (default: core)")
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

    sub.add_parser("down", help="Stop all mock services")
    sub.add_parser("restart", help="Restart mock services")
    sub.add_parser("status", help="Show status of running containers")

    p_logs = sub.add_parser("logs", help="Follow logs (optionally for a specific service)")
    p_logs.add_argument("service", nargs="*", default=[], help="Service name(s)")

    p_build = sub.add_parser("build", help="Build images without starting")
    p_build.add_argument("stack", nargs="?", default="core", help="Stack to build (default: core)")

    p_push = sub.add_parser("push", help="Build & push all mock images to $OIDA_REGISTRY")
    p_push.add_argument(
        "--batch",
        type=int,
        default=10,
        help="Targets to build+push per batch (default: 10; lower if buildkit drops jobs)",
    )

    sub.add_parser("clean", help="Remove containers, volumes, and local images")

    # Discovery commands
    sub.add_parser("list", help="List all available services (reads compose labels)")
    sub.add_parser("ports", help="Show port mappings of currently running containers")

    # CVE command
    p_cve = sub.add_parser("up-cve", help="Start specific CVE protocol group")
    p_cve.add_argument("proto", help="CVE protocol group (smtp, dns, mqtt, ...)")

    # Generic proto command
    p_proto = sub.add_parser("up-proto", help="Start services by oida.group label")
    p_proto.add_argument("group", help="Protocol group name")

    # Per-protocol commands — registered from PROTO_SPECS
    for name, spec in PROTO_SPECS.items():
        sub.add_parser(name, help=f"Start {spec['header']}")

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
}


def _make_handler(spec: dict) -> Callable[[argparse.Namespace], int]:
    """Create a closure-based handler for a protocol spec."""

    def handler(args: argparse.Namespace) -> int:
        return _cmd_up_proto_generic(args, spec)

    return handler


# Add per-protocol commands to dispatch
for _name, _spec in PROTO_SPECS.items():
    COMMAND_DISPATCH[_name] = _make_handler(_spec)


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

    # (#9) Docker pre-flight check for commands that need it
    needs_docker = args.command not in ("list",)  # list could work offline with cached config
    if needs_docker and not _check_docker():
        return 1

    # (#10) Compose file check for commands that need compose
    needs_compose = args.command not in ("list",)
    if needs_compose and not _check_compose_file():
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
