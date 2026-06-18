"""Validate MOCK_PORTS stays in sync with Docker compose service definitions.

This test parses the compose YAML files and cross-references every published
host port against the MOCK_PORTS dict in integration/conftest.py.  It catches
drift *without* Docker running — pure file-level consistency check.
"""

import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.core

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_CORE = ROOT / "docker" / "mocks" / "compose.yml"

# ── helpers ──────────────────────────────────────────────────────────────


def _parse_host_ports(compose_path: Path) -> dict[str, list[int]]:
    """Parse a compose file and return {service_name: [host_ports]}."""
    if not compose_path.exists():
        pytest.fail(f"{compose_path} not found")

    data = yaml.safe_load(compose_path.read_text())
    result: dict[str, list[int]] = {}
    for svc_name, svc_def in (data.get("services") or {}).items():
        ports = []
        for mapping in svc_def.get("ports", []):
            # formats: "8281:8080", "502:502/tcp", "47808:47808/udp"
            m = re.match(r"(\d+):", str(mapping))
            if m:
                ports.append(int(m.group(1)))
        if ports:
            result[svc_name] = sorted(set(ports))
    return result


def _get_mock_ports() -> dict[str, int]:
    """Import MOCK_PORTS from integration conftest."""
    from tests.integration.conftest import MOCK_PORTS

    return dict(MOCK_PORTS)


def _all_compose_host_ports() -> set[int]:
    """Collect every host port from both compose files."""
    ports: set[int] = set()
    for path in (COMPOSE_CORE,):
        if path.exists():
            for svc_ports in _parse_host_ports(path).values():
                ports.update(svc_ports)
    return ports


# ── tests ────────────────────────────────────────────────────────────────


def test_compose_files_exist():
    """Compose files must be present for the rest of the suite to work."""
    assert COMPOSE_CORE.exists(), f"Missing {COMPOSE_CORE}"


def test_docker_compose_path_is_correct():
    """DOCKER_COMPOSE_PATH in integration/conftest.py must resolve to a real file."""
    from tests.integration.conftest import DOCKER_COMPOSE_PATH

    assert DOCKER_COMPOSE_PATH.exists(), (
        f"DOCKER_COMPOSE_PATH points to {DOCKER_COMPOSE_PATH} which does not exist"
    )


def test_every_compose_port_in_mock_ports():
    """Every host port published in compose files must appear in MOCK_PORTS."""
    mock_ports = _get_mock_ports()
    mock_port_values = set(mock_ports.values())
    compose_ports = _all_compose_host_ports()

    missing = compose_ports - mock_port_values
    if missing:
        # Build a readable message showing which compose services are uncovered
        detail_lines = []
        for path in (COMPOSE_CORE,):
            if not path.exists():
                continue
            for svc, ports in _parse_host_ports(path).items():
                for p in ports:
                    if p in missing:
                        detail_lines.append(f"  {svc}: port {p} ({path.name})")
        detail = "\n".join(sorted(detail_lines))
        pytest.fail(
            f"Compose ports not in MOCK_PORTS ({len(missing)}):\n{detail}\n\n"
            "Add them to tests/integration/conftest.py MOCK_PORTS."
        )


def test_no_stale_mock_ports():
    """Every port in MOCK_PORTS should map to a compose service (except known local-only)."""
    # Ports that intentionally have no compose service
    LOCAL_ONLY = {"can"}

    mock_ports = _get_mock_ports()
    compose_ports = _all_compose_host_ports()

    stale = {
        name: port
        for name, port in mock_ports.items()
        if port not in compose_ports and name not in LOCAL_ONLY
    }
    if stale:
        detail = "\n".join(f"  {name}: {port}" for name, port in sorted(stale.items()))
        pytest.fail(
            f"MOCK_PORTS entries with no matching compose service:\n{detail}\n\n"
            "Remove them or add to LOCAL_ONLY if intentional."
        )


def test_mock_ports_values_unique():
    """No two MOCK_PORTS keys should map to the same port (would mask one service)."""
    mock_ports = _get_mock_ports()
    seen: dict[int, str] = {}
    dupes = []
    for name, port in mock_ports.items():
        if port in seen:
            dupes.append(f"  port {port}: {seen[port]} vs {name}")
        seen[port] = name
    if dupes:
        pytest.fail("Duplicate ports in MOCK_PORTS:\n" + "\n".join(dupes))
