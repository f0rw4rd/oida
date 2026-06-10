"""
Shared pytest fixtures for OIDA integration testing

Marker-driven container management: protocol markers (e.g. @pytest.mark.hart)
drive which Docker Compose services start. pytest-docker handles lifecycle.

Key fixtures:
- docker_services: Session-scoped Docker service management (from pytest-docker)
- cli_runner: CLI subprocess execution helper
- mock_host: Returns localhost for mock services
"""

import os
import subprocess

import pytest
import socket
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .cli_runner import CLIRunner


# Configuration Constants
MOCK_HOST = "127.0.0.1"

# Docker compose file path
DOCKER_COMPOSE_PATH = Path(__file__).parent.parent.parent / "docker" / "mocks" / "compose.yml"

# Port configuration for all mock services
MOCK_PORTS: Dict[str, int] = {
    "modbus": 502,
    "opcua": 4840,
    "opcua_auth": 4841,
    "opcua_insecure": 4842,
    "opcua_gds": 4850,
    "ethernetip": 44818,
    "ethernetip_opener": 44819,
    "ethernetip_opener_udp": 2223,
    "ethernetip_conpot": 44823,
    "ads": 48898,
    "s7": 10102,
    "iec104": 2404,
    "iec104_custom": 2405,
    "iec104_conpot": 2409,
    "iec104_tls": 19998,
    "mms": 102,
    "mms_goose": 10106,
    "mms_control": 10107,
    "mms_auth": 10108,
    "mms_conpot": 10109,
    "knx": 3671,
    "mqtt": 1883,
    "mqtt_auth": 1884,
    "mqtt_sparkplug": 1885,
    "mqtt_busy": 1886,
    "mqtt_tls": 8883,
    "mqtt_mtls": 8884,
    "mqtt_busy_tls": 8885,
    "mqtt_busy_mtls": 8886,
    # Medical protocols
    "dicom": 11112,
    "dicom_strict": 11113,
    "hl7": 2577,
    "hl7_python": 2575,
    "hl7_tls": 2576,
    "fhir": 8081,
    "dicom_orthanc": 4242,
    "dicom_orthanc_web": 8042,
    "hl7_mirth_web": 8443,
    "hl7_mirth_http": 8080,
    "hl7_mirth_1": 6661,
    "hl7_mirth_2": 6662,
    "hl7_mirth_3": 6663,
    # DNP3
    "dnp3": 20000,
    "dnp3_complex": 20001,
    "dnp3_tls": 20002,
    "dnp3_addr1": 20003,
    "dnp3_addr10": 20004,
    "dnp3_addr100": 20005,
    "dnp3_enhanced": 20010,
    "dnp3_filetransfer": 20020,
    # HTTP/2
    "http2_nghttp2_h2c": 8280,
    "http2_nghttp2_tls": 8281,
    "http2_python_h2c": 9080,
    "http2_python_tls": 9443,
    # BACnet
    "bacnet": 47808,
    "bacnet_conpot": 47812,
    # CoAP (UDP — uses check_udp_port_open via UDP_PROTOCOLS)
    "coap": 5683,
    "coap_libcoap": 5685,
    "coap_dtls": 5684,
    "coap_dtls_cert": 5686,
    # HART-IP
    "hart": 5094,
    "hart_tls": 5095,
    "hart_secondary_tcp": 5096,
    "hart_secondary_udp": 5097,
    "hart_tertiary_tcp": 5098,
    "hart_tertiary_udp": 5099,
    # SNMP
    "snmp": 10161,
    "snmp_v3only": 10164,
    "snmp_switch": 10162,
    # Modbus variants
    "modbus_sunspec": 5502,
    "modbus_conpot": 5503,
    "modbus_tls": 802,
    "modbus_rtu_tcp": 5030,
    # S7comm variants
    "s7comm_softplc": 10110,
    "s7comm_softplc_web": 8082,
    # ASTM
    "astm": 1394,
    "astm_hematology": 1395,
    "astm_data": 1396,
    # OCPP
    "ocpp_ws": 9000,
    "ocpp_wss": 9001,
    # VNC / FTP / SMTP / HTTP (state machine testing)
    "vnc": 5900,
    "ftp": 2121,
    "smtp": 2530,
    "http_mock": 8083,
}

# ---------------------------------------------------------------------------
# Protocol marker → compose service names
# ---------------------------------------------------------------------------
PROTOCOL_SERVICES: Dict[str, List[str]] = {
    "modbus": [
        "modbus-mock",
        "modbus-conpot",
        "modbus-tls",
        "modbus-rtu-tcp",
        "modbus-sunspec",
    ],
    "opcua": ["opcua-mock", "opcua-advanced", "opcua-gds", "opcua-insecure"],
    "ethernetip": ["ethernetip-mock", "ethernetip-opener"],
    "ads": ["ads-mock"],
    "bacnet": ["bacnet-mock", "bacnet-conpot"],
    "iec104": ["iec104-lib60870", "iec104-custom-types", "iec104-conpot", "iec104-tls"],
    "mms": ["mms-libiec61850", "mms-goose", "mms-control", "mms-authentication"],
    "s7comm": ["s7comm-snap7"],
    "knx": ["knx-calimero", "knx-devices"],
    "mqtt": [
        "mqtt-insecure",
        "mqtt-auth",
        "mqtt-sparkplug",
        "mqtt-busy",
        "mqtt-tls",
        "mqtt-busy-tls",
    ],
    "hart": ["hart-mock", "hart-tls", "hart-secondary", "hart-tertiary"],
    "snmp": ["snmp-mock", "snmp-switch", "snmp-v3only"],
    "dnp3": [
        "dnp3-basic",
        "dnp3-complex",
        "dnp3-tls",
        "dnp3-addr1",
        "dnp3-addr10",
        "dnp3-addr100",
        "dnp3-enhanced",
        "dnp3-filetransfer",
    ],
    "astm": ["astm-mock", "astm-hematology", "astm-data"],
    "ocpp": ["ocpp-insecure"],
    "dicom": ["dicom-mock", "dicom-strict"],
    "hl7": ["hl7-node-mock", "hl7-mock"],
    "fhir": ["fhir-mock"],
    "http2": ["http2-nghttp2", "http2-python"],
    "vnc": ["vnc-mock"],
    "ftp": ["ftp-mock"],
    "smtp": ["smtp-mock"],
    "http": ["http-mock"],
    "coap": ["coap-mock", "coap-libcoap", "coap-dtls", "coap-dtls-cert"],
    "ethercat": ["ethercat-slave-veth"],
    "profinet": ["profinet-device"],
    "goose": ["goose-l2-publisher"],
}

# ---------------------------------------------------------------------------
# Compose service → primary TCP port for health-check probing
# ---------------------------------------------------------------------------
SERVICE_HEALTH_PORT: Dict[str, int] = {
    "modbus-mock": 502,
    "modbus-conpot": 5503,
    "ads-mock": 48898,
    "mms-libiec61850": 102,
    "mms-goose": 10106,
    "mms-control": 10107,
    "mms-authentication": 10108,
    "iec104-lib60870": 2404,
    "iec104-custom-types": 2405,
    "iec104-conpot": 2409,
    "iec104-tls": 19998,
    "s7comm-snap7": 10102,
    "knx-calimero": 3671,
    "mqtt-insecure": 1883,
    "mqtt-auth": 1884,
    "mqtt-sparkplug": 1885,
    "mqtt-busy": 1886,
    "mqtt-tls": 8883,
    "mqtt-busy-tls": 8885,
    "opcua-mock": 4840,
    "opcua-advanced": 4841,
    "opcua-gds": 4850,
    "opcua-insecure": 4842,
    "dnp3-basic": 20000,
    "dnp3-complex": 20001,
    "dnp3-tls": 20002,
    "dnp3-addr1": 20003,
    "dnp3-addr10": 20004,
    "dnp3-addr100": 20005,
    "dnp3-enhanced": 20010,
    "dnp3-filetransfer": 20020,
    "ethernetip-mock": 44818,
    "ethernetip-opener": 44819,
    "hart-mock": 5094,
    "hart-tls": 5095,
    "hart-secondary": 5097,
    "hart-tertiary": 5099,
    "snmp-mock": 10161,
    # snmp-switch: UDP-only (10162), skipped here — tests use _check_snmp_reachable()
    "modbus-sunspec": 5502,
    "modbus-tls": 802,
    "modbus-rtu-tcp": 5030,
    "coap-mock": 5683,  # UDP — uses check_udp_port_open()
    "coap-libcoap": 5685,  # UDP — libcoap C server
    "coap-dtls": 5683,  # UDP — libcoap DTLS (plain port; DTLS on 5684)
    "coap-dtls-cert": 5686,  # UDP — libcoap DTLS cert (DTLS on 5686)
    "http2-nghttp2": 8281,
    "http2-python": 9080,
    "astm-mock": 1394,
    "astm-hematology": 1395,
    "astm-data": 1396,
    "ocpp-insecure": 9000,
    "hl7-mock": 2575,
    "hl7-node-mock": 2577,
    "vnc-mock": 5900,
    "ftp-mock": 2121,
    "smtp-mock": 2530,
    "http-mock": 8083,
    "dicom-mock": 11112,
    "dicom-strict": 11113,
    "fhir-mock": 8081,
    "bacnet-mock": 47808,
    "bacnet-conpot": 47812,
}

# Timeout configurations
SERVICE_STARTUP_TIMEOUT = 120
DEFAULT_CLI_TIMEOUT = 30


def check_port_open(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a TCP port is open"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        return False


def check_udp_port_open(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a UDP port is responding (sends a CoAP-style ping and waits for any reply).

    Works for CoAP (sends a minimal CoAP empty confirmable message) and
    other UDP services that reply to any datagram.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # CoAP empty confirmable message (4 bytes): version=1, type=CON, token_len=0, code=0.00
        coap_ping = b"\x40\x00\x00\x01"
        sock.sendto(coap_ping, (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            return len(data) > 0
        except socket.timeout:
            return False
        finally:
            sock.close()
    except (socket.error, OSError):
        return False


# Protocols that use UDP instead of TCP for their primary port
UDP_PROTOCOLS: Set[str] = {"coap", "bacnet"}


def ensure_mock(protocol_name: str) -> None:
    """Ensure a protocol's mock service is reachable.

    Called by BaseProtocolIntegrationTest's autouse fixture. The actual
    container lifecycle is handled by the marker-driven Docker setup, so
    this is a lightweight check that skips the test class if the primary
    mock port isn't open.

    Uses UDP probing for protocols in UDP_PROTOCOLS, TCP otherwise.
    """
    port = MOCK_PORTS.get(protocol_name)
    if not port:
        return

    if protocol_name in UDP_PROTOCOLS:
        reachable = check_udp_port_open(MOCK_HOST, port, timeout=2)
    else:
        reachable = check_port_open(MOCK_HOST, port, timeout=2)

    if not reachable:
        pytest.skip(
            f"{protocol_name} mock not available on port {port} "
            f"(run 'make mock-start' or use pytest markers)"
        )


# ---------------------------------------------------------------------------
# Layer 2 (non-TCP) services — health checked via Docker inspect, not TCP
# ---------------------------------------------------------------------------

# Services that use raw L2 sockets instead of TCP — no port to probe.
# Health is determined by checking the container's Docker healthcheck status.
L2_SERVICES: Set[str] = {
    "ethercat-slave-veth",
    "ethercat-slave",
    "profinet-device",
    "goose-l2-publisher",
}

# Services that use UDP instead of TCP — use check_udp_port_open().
UDP_SERVICES: Set[str] = {
    "coap-mock",
    "coap-libcoap",
    "coap-dtls",
    "coap-dtls-cert",
}

# Docker compose project name (must match docker_compose_project_name fixture)
_COMPOSE_PROJECT = "oida-test"


def check_l2_container_healthy(
    container_name: str = "ethercat-slave-veth",
) -> bool:
    """Check if an L2 mock container is running and healthy via docker inspect.

    Works for any container that has a Docker HEALTHCHECK defined — EtherCAT,
    PROFINET DCP, GOOSE, etc.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        status = result.stdout.strip()
        return result.returncode == 0 and status == "healthy"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# Backward-compatible alias
check_ethercat_container_healthy = check_l2_container_healthy


def get_docker_bridge_interface(
    network_name: str = "ics-network",
    project_name: str = _COMPOSE_PROJECT,
) -> Optional[str]:
    """Discover the host-side bridge interface for a Docker network.

    Docker creates a bridge interface named ``br-<short_id>`` for each
    user-defined bridge network.  The network may be namespaced under the
    compose project (e.g. ``oida-test_ics-network`` or ``mocks_ics-network``).

    Returns the bridge interface name (e.g. ``br-7b4761a968f7``) or None.
    """
    # Try project-prefixed names (both test and dev), then bare name
    candidates = [
        f"{project_name}_{network_name}",
        f"mocks_{network_name}",
        network_name,
    ]
    for name in candidates:
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", name, "--format", "{{.Id}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                net_id = result.stdout.strip()[:12]
                bridge_name = f"br-{net_id}"
                # Verify the interface actually exists on the host
                if os.path.exists(f"/sys/class/net/{bridge_name}"):
                    return bridge_name
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return None


def check_raw_socket_capability() -> Tuple[bool, Optional[str]]:
    """Check if the current process has CAP_NET_RAW or root privileges.

    Returns (has_capability, error_message).
    """
    if os.geteuid() == 0:
        return True, None
    # Try creating a raw socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88A4))
        s.close()
        return True, None
    except (PermissionError, OSError):
        return False, (
            "Raw socket access denied — run as root or with CAP_NET_RAW "
            "(e.g. sudo pytest, or setcap cap_net_raw+ep on python)"
        )


def check_sudo_available() -> bool:
    """Check if passwordless sudo is available for the current user.

    Returns True if ``sudo -n true`` succeeds (passwordless sudo works).
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def get_raw_socket_strategy() -> Tuple[Optional[str], Optional[str]]:
    """Determine how to obtain raw socket access for L2 protocol tests.

    Returns (strategy, error_message) where strategy is one of:
      - "direct"  : current process has CAP_NET_RAW or is root — no sudo needed
      - "sudo"    : passwordless sudo available — prefix commands with sudo
      - None      : no raw socket access possible — skip tests
    """
    has_raw, _ = check_raw_socket_capability()
    if has_raw:
        return "direct", None
    if check_sudo_available():
        return "sudo", None
    return None, (
        "Raw socket access unavailable — need one of:\n"
        "  1. Run as root (sudo pytest)\n"
        "  2. Set CAP_NET_RAW on Python (sudo setcap cap_net_raw+ep $(which python))\n"
        "  3. Enable passwordless sudo for the current user"
    )


# ---------------------------------------------------------------------------
# Marker-driven container tracking (populated during collection)
# ---------------------------------------------------------------------------
_needed_services: Set[str] = set()
_preexisting_services: Set[str] = set()


def pytest_collection_modifyitems(items):
    """Scan collected tests for protocol markers and @pytest.mark.containers()
    to determine which compose services need to run."""
    for item in items:
        for marker in item.iter_markers():
            if marker.name in PROTOCOL_SERVICES:
                _needed_services.update(PROTOCOL_SERVICES[marker.name])
            elif marker.name == "containers":
                _needed_services.update(marker.args)


# ---------------------------------------------------------------------------
# Override pytest-docker fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def docker_compose_file():
    """Point pytest-docker at our compose file."""
    return str(DOCKER_COMPOSE_PATH)


@pytest.fixture(scope="session")
def docker_compose_project_name():
    """Stable project name so pre-existing containers are found."""
    return "oida-test"


@pytest.fixture(scope="session")
def docker_setup():
    """Start only the compose services required by collected test markers.
    Services already listening (e.g. from ``make mock-start``) are skipped.

    If some services are already running (pre-existing from ``make mock-start``)
    and additional services need to be started, we skip the compose up to avoid
    Docker network conflicts.  The per-test ``_check_required_containers``
    fixture will skip tests whose services are not available.
    """
    # Detect already-running services
    for svc in list(_needed_services):
        if svc in L2_SERVICES:
            # L2 services have no TCP port; check via docker inspect
            if check_l2_container_healthy(svc):
                _preexisting_services.add(svc)
        elif svc in UDP_SERVICES:
            port = SERVICE_HEALTH_PORT.get(svc)
            if port and check_udp_port_open(MOCK_HOST, port, timeout=1):
                _preexisting_services.add(svc)
        else:
            port = SERVICE_HEALTH_PORT.get(svc)
            if port and check_port_open(MOCK_HOST, port, timeout=1):
                _preexisting_services.add(svc)

    to_start = _needed_services - _preexisting_services
    if to_start:
        if _preexisting_services:
            # Some services already running from a previous compose session.
            # Starting new services would likely fail with a Docker network
            # overlap error.  Let per-test skip guards handle missing services.
            return []
        # Bring the services up ourselves (rather than delegating the command to
        # pytest-docker) so a build/start failure -- e.g. an upstream package that
        # has vanished from its index -- degrades to per-test skips via
        # _check_required_containers instead of erroring the entire session.
        cmd = [
            "docker",
            "compose",
            "-f",
            str(DOCKER_COMPOSE_PATH),
            "-p",
            "oida-test",
            "up",
            "-d",
            "--wait",
            *sorted(to_start),
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(
                f"[docker_setup] could not start {sorted(to_start)}: {e}; "
                "per-test guards will skip unavailable services"
            )
        return []
    return []  # Everything already running — no Docker commands


@pytest.fixture(scope="session")
def docker_cleanup():
    """Stop only the services we started (leave pre-existing ones alone)."""
    to_stop = _needed_services - _preexisting_services
    if to_stop:
        return ["stop " + " ".join(sorted(to_stop))]
    return []  # Don't touch pre-existing services


# ---------------------------------------------------------------------------
# Autouse per-test container availability guard
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _check_required_containers(request):
    """Skip tests whose @pytest.mark.containers(...) services aren't reachable."""
    marker = request.node.get_closest_marker("containers")
    if marker:
        for service in marker.args:
            if service in L2_SERVICES:
                if not check_l2_container_healthy(service):
                    # Determine the profile hint from the service name
                    profile = "ethercat"
                    if "profinet" in service:
                        profile = "profinet"
                    elif "goose" in service:
                        profile = "goose-l2"
                    pytest.skip(
                        f"L2 container '{service}' not healthy "
                        f"(start with: docker compose --profile {profile} up -d)"
                    )
            elif service in UDP_SERVICES:
                port = SERVICE_HEALTH_PORT.get(service)
                if port and not check_udp_port_open(MOCK_HOST, port, timeout=2):
                    pytest.skip(f"Container '{service}' not available (UDP port {port})")
            else:
                port = SERVICE_HEALTH_PORT.get(service)
                if port and not check_port_open(MOCK_HOST, port, timeout=2):
                    pytest.skip(f"Container '{service}' not available (port {port})")


# ---------------------------------------------------------------------------
# Common fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_service():
    """No-op fixture for backward compatibility.

    Service lifecycle is managed by the marker-driven docker_setup fixture.
    This fixture exists so tests that reference it continue to collect
    without fixture errors.
    """
    pass


@pytest.fixture
def cli_runner():
    """Fixture providing CLI runner instance"""
    return CLIRunner()


@pytest.fixture
def mock_host():
    """Returns the mock host address"""
    return MOCK_HOST


@pytest.fixture
def mock_ports():
    """Returns port configuration for all mock services"""
    return MOCK_PORTS


# ---------------------------------------------------------------------------
# Generic L2 Docker test helper
# ---------------------------------------------------------------------------


def skip_unless_l2_docker(
    container_name: str,
    profile_hint: str = "ethercat",
) -> Tuple[str, bool]:
    """Skip the calling test if a Docker L2 mock or raw sockets are unavailable.

    Works for any L2 protocol: EtherCAT, PROFINET DCP, GOOSE, etc.

    Args:
        container_name: Docker container name to health-check.
        profile_hint: Docker Compose profile name for the skip message.

    Returns:
        (bridge_interface, needs_sudo) tuple on success.

    Raises:
        pytest.skip: If requirements are not met.
    """
    if not check_l2_container_healthy(container_name):
        pytest.skip(
            f"L2 container '{container_name}' not available "
            f"(start with: docker compose --profile {profile_hint} up -d {container_name})"
        )
    strategy, err_msg = get_raw_socket_strategy()
    if strategy is None:
        pytest.skip(f"Raw socket not available: {err_msg}")
    bridge = get_docker_bridge_interface()
    if bridge is None:
        pytest.skip("Cannot discover Docker bridge interface for ics-network")
    needs_sudo = strategy == "sudo"
    return bridge, needs_sudo


# ---------------------------------------------------------------------------
# L2 / raw-socket fixtures (generic + protocol-specific delegates)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def has_raw_socket() -> Tuple[bool, Optional[str]]:
    """Return (True, None) if this process can open raw sockets."""
    return check_raw_socket_capability()


@pytest.fixture(scope="session")
def raw_socket_strategy() -> Tuple[Optional[str], Optional[str]]:
    """Return (strategy, error) for raw socket access.

    strategy is "direct", "sudo", or None.
    """
    return get_raw_socket_strategy()


@pytest.fixture(scope="session")
def l2_bridge_interface() -> Optional[str]:
    """Discover the host-side Docker bridge interface for ics-network.

    L2 protocol tests send raw frames to this bridge interface so they
    reach containers on the ics-network Docker bridge.

    Returns the bridge name (e.g. ``br-7b4761a968f7``) or None.
    """
    return get_docker_bridge_interface()


# Protocol-specific convenience fixtures that delegate to the generic helpers
@pytest.fixture(scope="session")
def ethercat_bridge_interface() -> Optional[str]:
    """Alias for l2_bridge_interface — kept for backward compatibility."""
    return get_docker_bridge_interface()


@pytest.fixture(scope="session")
def ethercat_mock_available() -> bool:
    """Return True if the EtherCAT Docker mock container is healthy."""
    return check_l2_container_healthy("ethercat-slave-veth")


@pytest.fixture(scope="session")
def profinet_mock_available() -> bool:
    """Return True if the PROFINET Docker mock container is healthy."""
    return check_l2_container_healthy("profinet-device")


@pytest.fixture(scope="session")
def goose_mock_available() -> bool:
    """Return True if the GOOSE L2 publisher container is healthy."""
    return check_l2_container_healthy("goose-l2-publisher")


# ---------------------------------------------------------------------------
# Pytest configuration — register custom markers
# ---------------------------------------------------------------------------


def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "slow: marks tests as slow running")
    config.addinivalue_line("markers", "auth: marks tests requiring authentication")
    config.addinivalue_line("markers", "fuzz: marks fuzzing tests")
    config.addinivalue_line("markers", "security: marks security analysis tests")
    config.addinivalue_line("markers", "modbus: Modbus protocol tests")
    config.addinivalue_line("markers", "opcua: OPC UA protocol tests")
    config.addinivalue_line("markers", "ethernetip: EtherNet/IP protocol tests")
    config.addinivalue_line("markers", "ads: Beckhoff ADS protocol tests")
    config.addinivalue_line("markers", "snap7: Siemens S7 protocol tests")
    config.addinivalue_line("markers", "s7comm: Siemens S7comm protocol tests")
    config.addinivalue_line("markers", "iec104: IEC 104 protocol tests")
    config.addinivalue_line("markers", "mms: MMS/IEC 61850 protocol tests")
    config.addinivalue_line("markers", "knx: KNX protocol tests")
    config.addinivalue_line("markers", "mqtt: MQTT protocol tests")
    config.addinivalue_line("markers", "dicom: DICOM protocol tests")
    config.addinivalue_line("markers", "hl7: HL7 protocol tests")
    config.addinivalue_line("markers", "cli: CLI integration tests")
    config.addinivalue_line("markers", "dnp3: DNP3 protocol tests")
    config.addinivalue_line("markers", "http2: HTTP/2 protocol tests")
    config.addinivalue_line("markers", "bacnet: BACnet protocol tests")
    config.addinivalue_line("markers", "mock_services: Mock service integration tests")
    config.addinivalue_line("markers", "ocpp: OCPP protocol tests")
    config.addinivalue_line("markers", "hart: HART protocol tests")
    config.addinivalue_line("markers", "snmp: SNMP protocol tests")
    config.addinivalue_line("markers", "astm: ASTM/LIS protocol tests")
    config.addinivalue_line("markers", "fhir: FHIR protocol tests")
    config.addinivalue_line("markers", "coap: CoAP protocol tests")
    config.addinivalue_line("markers", "can: CAN bus protocol tests")
    config.addinivalue_line("markers", "vnc: VNC protocol tests")
    config.addinivalue_line("markers", "ftp: FTP protocol tests")
    config.addinivalue_line("markers", "smtp: SMTP protocol tests")
    config.addinivalue_line("markers", "ethercat: EtherCAT protocol tests")
    config.addinivalue_line("markers", "profinet: PROFINET DCP protocol tests")
    config.addinivalue_line("markers", "goose: IEC 61850 GOOSE protocol tests")
    config.addinivalue_line(
        "markers", "containers: marks tests requiring specific Docker containers"
    )
