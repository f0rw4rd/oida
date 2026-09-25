"""
Integration tests wiring OIDA's bacnetsc scanner to the REAL bacnet-stack BSC
(Secure Connect) mock stacks over WSS/TLS.

Two postures (built from the same source, differing only in a compile-time
patch - see docker/mocks/services/bacnetsc/mock/realstack/Dockerfile):

  bacnetsc-realstack-secure  TCP 47830  STRICT: mutual-auth required + TLS 1.3
  bacnetsc-realstack-weak    TCP 47831  stock: accepts anon/rogue + TLS 1.2

The device-level tests prove the ENTIRE inherited BACnet application layer
(ReadProperty, --call, identify) rides over the SC datalink unchanged. The
TLS-posture tests prove OIDA's automatic background checks (a) FIRE against the
weak device (anonymous/rogue client accepted, TLS 1.2 downgrade) and (b) are
SILENT for the enforced controls on the secure device.

The mock mints its own PKI into a container volume on first boot; each test
copies the CA + client cert out of the running container with `docker cp`.
Tests skip cleanly when a mock is not reachable (bring them up with
`python services.py up bacnetsc`).
"""

import shutil
import subprocess
import sys

import pytest

from tests.service_gate import require_port, require_service

from tests.integration.conftest import MOCK_HOST

pytestmark = [pytest.mark.integration, pytest.mark.bacnetsc]

SECURE_PORT = 47830
WEAK_PORT = 47831
SECURE_CONTAINER = "bacnetsc-realstack-secure"
WEAK_CONTAINER = "bacnetsc-realstack-weak"
SECURE_DEVICE_ID = 44004
WEAK_DEVICE_ID = 44005


def _require(port: int, name: str) -> None:
    require_port(MOCK_HOST, port, f"{name} BACnet/SC mock")


def _copy_certs(container: str, tmp_path):
    """docker cp the minted CA + client cert/key out of the container."""
    if shutil.which("docker") is None:
        require_service("docker CLI not available to extract mock certs")
    out = {}
    for fname, key in (
        ("ca.pem", "ca"),
        ("client_cert.pem", "cert"),
        ("client_key.pem", "key"),
    ):
        dest = tmp_path / fname
        r = subprocess.run(
            ["docker", "cp", f"{container}:/certs/{fname}", str(dest)],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0 or not dest.exists():
            require_service(f"could not extract {fname} from {container}: {r.stderr.strip()}")
        out[key] = str(dest)
    return out


def _run_bacnetsc(uri, certs, *extra, timeout=90):
    """Run `oida bacnet --sc ...` as a subprocess; return (stdout+stderr, json?)."""
    cmd = [
        sys.executable,
        "-m",
        "oida.cli",
        "bacnet",
        "--sc",
        uri,
        "--ca",
        certs["ca"],
        "--cert",
        certs["cert"],
        "--key",
        certs["key"],
        "--timeout",
        "8",
        *extra,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr


# --- device / application-layer over SC ------------------------------------


def test_secure_device_read_over_sc(tmp_path):
    """A targeted ReadProperty rides the inherited mixin over the SC datalink."""
    _require(SECURE_PORT, SECURE_CONTAINER)
    certs = _copy_certs(SECURE_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{SECURE_PORT}",
        certs,
        "--device-id",
        str(SECURE_DEVICE_ID),
        "-r",
        f"device:{SECURE_DEVICE_ID}:object-name",
        "--no-tls-checks",
    )
    assert "Connected to BACnet/SC" in out, out
    assert "BACnetSC-Secure-Supervisor" in out, out


def test_secure_device_discovery_without_device_id(tmp_path):
    """Auto-discovery over SC with NO --device-id.

    Regression guard for H2: the inherited discovery path issues a directed
    Who-Is, and SCLinkLayer routes that outbound NPDU to the negotiated peer
    VMAC over the SC tunnel. The mock answers with an I-Am, so the device is
    discovered and its object-name read - proving --device-id is NOT required
    over SC (verified against bacnet-stack 1.4.4's BSC server).
    """
    _require(SECURE_PORT, SECURE_CONTAINER)
    certs = _copy_certs(SECURE_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{SECURE_PORT}",
        certs,
        # NO --device-id: force the directed-Who-Is discovery path over SC.
        "--no-tls-checks",
    )
    assert "Connected to BACnet/SC" in out, out
    assert f"Discovered device ID: {SECURE_DEVICE_ID} (via Who-Is)" in out, out
    assert "BACnetSC-Secure-Supervisor" in out, out


def test_secure_device_call_read_over_sc(tmp_path):
    """--call read (CallMixin) works over SC."""
    _require(SECURE_PORT, SECURE_CONTAINER)
    certs = _copy_certs(SECURE_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{SECURE_PORT}",
        certs,
        "--device-id",
        str(SECURE_DEVICE_ID),
        "--call",
        "read",
        "AI:1:present-value",
        "--no-tls-checks",
    )
    assert "[Call] readProperty AI:1:present-value" in out, out
    assert "AI:1:present-value =" in out, out


# --- TLS posture: WEAK device => findings FIRE -----------------------------


def test_weak_device_mutual_auth_findings_fire(tmp_path):
    _require(WEAK_PORT, WEAK_CONTAINER)
    certs = _copy_certs(WEAK_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{WEAK_PORT}",
        certs,
        "--device-id",
        str(WEAK_DEVICE_ID),
    )
    assert "mutual auth NOT enforced (anonymous client accepted)" in out, out


def test_weak_device_tls12_downgrade_finding_fires(tmp_path):
    _require(WEAK_PORT, WEAK_CONTAINER)
    certs = _copy_certs(WEAK_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{WEAK_PORT}",
        certs,
        "--device-id",
        str(WEAK_DEVICE_ID),
    )
    assert "accepts TLS 1.2 (downgrade)" in out, out


# --- TLS posture: SECURE device => enforced controls SILENT ----------------


def test_secure_device_no_anonymous_finding(tmp_path):
    """The STRICT device rejects the anonymous client, so the finding is silent."""
    _require(SECURE_PORT, SECURE_CONTAINER)
    certs = _copy_certs(SECURE_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{SECURE_PORT}",
        certs,
        "--device-id",
        str(SECURE_DEVICE_ID),
    )
    # Must still connect with the valid client cert...
    assert "Connected to BACnet/SC" in out, out
    # ...but the anonymous-accepted finding must NOT appear.
    assert "anonymous client accepted" not in out, out


def test_secure_device_no_tls12_downgrade_finding(tmp_path):
    """The STRICT device refuses TLS 1.2, so the downgrade finding is silent."""
    _require(SECURE_PORT, SECURE_CONTAINER)
    certs = _copy_certs(SECURE_CONTAINER, tmp_path)
    out = _run_bacnetsc(
        f"wss://{MOCK_HOST}:{SECURE_PORT}",
        certs,
        "--device-id",
        str(SECURE_DEVICE_ID),
    )
    assert "accepts TLS 1.2 (downgrade)" not in out, out
