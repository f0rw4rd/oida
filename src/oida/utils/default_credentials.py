# -*- coding: utf-8 -*-
"""
Centralized ICS default credentials database

Provides vendor-specific default passwords and credentials for:
- Siemens S7 PLCs
- DNP3 Secure Authentication
- HART Device Lock Codes
- OCPP EV Charger / CSMS credentials
- Other ICS protocols

Sources:
- Vendor security advisories (SSA-*, ICSA-*, VDE-*)
- ICS-CERT / CISA advisories
- IEEE reference implementations
- Vendor manuals (Schneider, Bender, Vestel, Phoenix Contact, etc.)
- Pwn2Own Automotive 2024/2025
- Common ICS configurations
"""

from typing import List, Optional, Tuple, Union

from oida.utils.ics_logger import get_module_logger

_logger = get_module_logger(__name__)

# =============================================================================
# Siemens S7 Default Passwords (max 8 characters)
# =============================================================================
SIEMENS_S7_DEFAULTS: List[str] = [
    # Priority 1: Empty/Null (most common misconfiguration)
    "",
    # Priority 2: Siemens product names
    "SIEMENS",
    "siemens",
    "S7-1200",
    "S7-1500",
    "s7-300",
    "s7-400",
    # Priority 3: Common ICS passwords
    "admin",
    "1234",
    "12345678",
    "password",
    "operator",
    "service",
    # Priority 4: Siemens tools
    "STEP7",
    "TIA",
    "portal",
    "Portal",
    # Priority 5: Common ICS roles
    "plc",
    "PLC",
    "hmi",
    "HMI",
    "scada",
    "SCADA",
    "engineer",
    # Priority 6: Numeric patterns
    "00000000",
    "11111111",
    "99999999",
    "123456",
    # Priority 7: Known weak passwords
    "default",
    "DEFAULT",
    "program",
    "PROGRAM",
    "web",
    "webadmin",
]

# =============================================================================
# DNP3 Secure Authentication Default Credentials
# Format: (user_id, update_key_bytes)
# =============================================================================
DNP3_SA_DEFAULTS: List[Tuple[int, bytes]] = [
    # IEEE 1815 Reference Implementation defaults
    (1, bytes(16)),  # All zeros
    (1, bytes([0xFF] * 16)),  # All ones
    (1, bytes.fromhex("0102030405060708090A0B0C0D0E0F10")),
    # Sequential patterns
    (1, bytes.fromhex("00112233445566778899AABBCCDDEEFF")),
    (1, bytes.fromhex("12345678901234567890123456789012")),
    # Common weak keys
    (1, bytes.fromhex("11111111111111111111111111111111")),
    (1, bytes.fromhex("22222222222222222222222222222222")),
    # Vendor-specific reference keys (SEL, GE, ABB, Schweitzer)
    (1, b"SELEngineering\x00\x00"),  # 16 bytes
    (2, b"GENERICSCADA0000"),  # 16 bytes
    (1, b"ABBSCADAKEY\x00\x00\x00\x00\x00"),  # 16 bytes
    # User IDs 1-3 with common patterns
    (2, bytes(16)),
    (3, bytes(16)),
    (2, bytes.fromhex("0102030405060708090A0B0C0D0E0F10")),
]

# =============================================================================
# Generic ICS Default Credentials (username:password)
# For protocols that use username/password authentication
# =============================================================================
GENERIC_ICS_DEFAULTS: List[Tuple[str, str]] = [
    # Empty/Anonymous
    ("", ""),
    ("anonymous", ""),
    ("guest", "guest"),
    # Common admin accounts
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("administrator", "administrator"),
    # ICS-specific roles
    ("operator", "operator"),
    ("engineer", "engineer"),
    ("technician", "technician"),
    ("maintenance", "maintenance"),
    ("service", "service"),
    # Vendor defaults
    ("siemens", "siemens"),
    ("rockwell", "rockwell"),
    ("schneider", "schneider"),
    ("abb", "abb"),
    ("honeywell", "honeywell"),
    ("emerson", "emerson"),
    # SCADA/HMI
    ("scada", "scada"),
    ("hmi", "hmi"),
    ("plc", "plc"),
]


def get_protocol_defaults(protocol: str) -> Union[List[str], List[Tuple]]:
    """Get default credentials for a specific protocol.

    Args:
        protocol: Protocol name (s7, snap7, dnp3_sa, snmp, generic, etc.)

    Returns:
        List of default credentials (format depends on protocol)
    """
    protocol_lower = protocol.lower()

    defaults = {
        "s7": SIEMENS_S7_DEFAULTS,
        "snap7": SIEMENS_S7_DEFAULTS,
        "siemens": SIEMENS_S7_DEFAULTS,
        "dnp3_sa": DNP3_SA_DEFAULTS,
        "dnp3": DNP3_SA_DEFAULTS,
        "hart": HART_LOCK_DEFAULTS,
        "hart_lock": HART_LOCK_DEFAULTS,
        "ocpp": OCPP_DEFAULTS,
        "ocpp_tags": OCPP_ID_TAGS,
        "snmp": SNMP_COMMUNITY_DEFAULTS,
        "snmpv3_users": SNMP_V3_USERNAMES,
        "generic": GENERIC_ICS_DEFAULTS,
        "ics": GENERIC_ICS_DEFAULTS,
    }

    # Return a defensive shallow copy so callers that mutate the result
    # (append/extend/sort) cannot corrupt the shared module-level lists or
    # leak entries across protocols that alias the same constant (e.g.
    # s7/snap7/siemens -> SIEMENS_S7_DEFAULTS). Elements are immutable
    # (str / tuples of int|bytes|str), so a shallow copy is sufficient.
    return list(defaults.get(protocol_lower, []))


# =============================================================================
# SNMP Community String Defaults
# Sources: ICS-CERT advisories, vendor documentation, common misconfigurations
# =============================================================================
SNMP_V3_USERNAMES: List[str] = [
    # Priority 1: Common default usernames
    "initial",
    "admin",
    "root",
    "snmp",
    "snmpuser",
    "public",
    "private",
    "default",
    "user",
    "guest",
    "operator",
    "engineer",
    "service",
    "maintenance",
    "monitor",
    "readonly",
    "readwrite",
    "backup",
    # Priority 2: ICS vendor defaults
    "siemens",
    "schneider",
    "rockwell",
    "abb",
    "moxa",
    "hirschmann",
    "phoenix",
    "wago",
]


SNMP_COMMUNITY_DEFAULTS: List[str] = [
    # RFC defaults
    "public",
    "private",
    # ICS/SCADA common
    "SCADA",
    "control",
    "manager",
    "monitor",
    "admin",
    "rw",
    "read",
    "write",
    "default",
    "system",
    "scada",
    "plc",
    "ics",
    "hmi",
    "automation",
    # ICS vendor defaults (ICS-CERT advisories)
    "siemens",
    "schneider",
    "rockwell",
    "moxa",
    "hirschmann",
    "scalance",
    "ruggedcom",
    "beckhoff",
    "advantech",
    "allen-bradley",
    "emerson",
    "honeywell",
    "yokogawa",
    # IT infrastructure (common in ICS networks)
    "cisco",
    "apc",
    "brocade",
    # Common generic
    "secret",
    "test",
    "password",
    "root",
    "operator",
    "snmptrap",
    "trap",
    "network",
    "ILMI",
    "community",
]


# =============================================================================
# HART Device Lock Default Codes (max 8 characters, packed to 6 bytes)
# =============================================================================
HART_LOCK_DEFAULTS: List[str] = [
    # Priority 1: Empty/Null (most common misconfiguration)
    "",
    # Priority 2: All zeros/ones
    "00000000",
    "11111111",
    "FFFFFFFF",
    # Priority 3: Sequential patterns
    "12345678",
    "87654321",
    "1234",
    "4321",
    # Priority 4: Common ICS passwords
    "PASSWORD",
    "DEFAULT",
    "ADMIN",
    "SERVICE",
    "HART",
    "HARTHART",
    # Priority 5: Vendor-specific (Emerson/Rosemount)
    "EMERSON",
    "ROSE",
    "ROSEMNT",
    "FISHER",
    # Priority 6: Vendor-specific (Siemens)
    "SIEMENS",
    "SITRANS",
    # Priority 7: Vendor-specific (Endress+Hauser)
    "EH",
    "ENDRESS",
    # Priority 8: Vendor-specific (Yokogawa)
    "YOKOGAWA",
    "YEW",
    "YOKO",
    # Priority 9: Vendor-specific (Honeywell)
    "HONEY",
    "HONEYWELL",
    "STT",
    # Priority 10: Vendor-specific (ABB)
    "ABB",
    # Priority 11: Vendor-specific (Krohne)
    "KROHNE",
    # Priority 12: Vendor-specific (Vega)
    "VEGA",
    # Priority 13: Generic ICS
    "LOCKCODE",
    "USER",
    "GUEST",
    "TEST",
    "DEMO",
    # Priority 14: Numeric patterns
    "0000",
    "1111",
    "2222",
    "9999",
    "0001",
    "1000",
    "123456",
    "654321",
]


# =============================================================================
# OCPP Default Credentials
# Format: (username/charge_point_id, password/authorization_key)
#
# OCPP SecurityProfile 1/2 uses HTTP Basic Auth where chargePointId = username
# and AuthorizationKey = password. Many chargers ship at SecurityProfile 0
# (no auth at all).
#
# Sources:
#   - SteVe (application-prod.properties): admin/1234
#   - SteVe RPi image: admin/keba12
#   - Open e-Mobility (SAP Labs ev-server): super.admin@ev.com/Super.admin00
#   - Schneider EVlink (CVE-2018-7800): admin/ADMIN, user/USER
#   - Alpitronic Hypercharger (CVE-2024-4622, ICSA-24-130-02): admin/admin123
#   - Phoenix Contact CHARX (VDE-2024-011): manufacturer/manufacturer
#   - Bender CC612/CC613 manual: operator/yellow_zone
#   - Vestel EVC04 manual: admin/admin; E.ON variant: admin/eon01
#   - Etrel INCH customization guide: root@etrel.com/toor
#   - Juice Charger me (Vector config doc): operator/JuiCeMeUP!
#   - Delta AC MAX manual: 1234567890123456 (app login)
#   - OCPP-CS (apostoldevel): ocpp/ocpp
# =============================================================================
OCPP_DEFAULTS: List[Tuple[str, str]] = [
    # ── SecurityProfile 0: no auth (very common out-of-box) ──
    ("", ""),
    # ── Common CP IDs with empty AuthorizationKey ──
    ("CP001", ""),
    ("CP_001", ""),
    ("CP_SCANNER_001", ""),
    ("ChargePoint", ""),
    ("CHARGER_001", ""),
    ("STEVE_01", ""),
    # ── SteVe CSMS defaults (application-prod.properties) ──
    ("admin", "1234"),
    # ── SteVe RPi image defaults ──
    ("admin", "keba12"),
    # ── Open e-Mobility (SAP Labs ev-server) ──
    ("super.admin@ev.com", "Super.admin00"),
    ("slf.admin@ev.com", "Slf.admin00"),
    # ── OCPP-CS (apostoldevel) webhook default ──
    ("ocpp", "ocpp"),
    # ── Generic admin defaults ──
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "admin123"),  # Alpitronic Hypercharger (CVE-2024-4622)
    # ── Charger vendor web interface defaults (also used as OCPP keys) ──
    ("operator", "yellow_zone"),  # Bender CC612/CC613
    ("operator", "JuiCeMeUP!"),  # Juice Charger me
    ("manufacturer", "manufacturer"),  # Phoenix Contact CHARX
    ("user", "USER"),  # Schneider EVlink
    ("admin", "ADMIN"),  # Schneider EVlink
    ("admin", "eon01"),  # Vestel EVC04 (E.ON)
    ("root@etrel.com", "toor"),  # Etrel INCH
    ("changeThis", "changeThis"),  # SteVe legacy/forks
    # ── Common ICS-style defaults ──
    ("charger", "charger"),
    ("operator", "operator"),
    ("service", "service"),
    # ── Common AuthorizationKey patterns ──
    ("CP001", "CP001"),
    ("CP001", "password"),
    ("CP001", "1234"),
    ("CP001", "12345678"),
    ("CP001", "0000000000000000"),
    ("CP001", "1111111111111111"),
    ("CP001", "1234567890123456"),  # Delta AC MAX default
    ("CP001", "DEADBEEFDEADBEEF"),
]

# Common OCPP IdTag values (RFID badges, card IDs)
OCPP_ID_TAGS: List[str] = [
    # Empty/wildcard
    "",
    # Common test/default tags
    "0000000000",
    "1234567890",
    "AABBCCDD",
    "DEADBEEF",
    # Common RFID UID formats (4-byte and 7-byte)
    "04000000000000",
    "00000000",
    "FFFFFFFF",
    "04DEADBEEF0000",
    # Vendor test badges / simulator defaults
    "TEST",
    "test",
    "ADMIN",
    "SERVICE",
    "MASTER",
    "DEFAULT",
    "OIDA_SEC_TEST_00000000",
    # Chinese EVSE auth codes (Beny and similar)
    "123456",
    # Sequential patterns
    "0001",
    "0002",
    "1111",
    "9999",
    # FreeCharging mode patterns
    "FREECHARGE",
    "FREE",
]


def parse_credential_input(value: Optional[str]) -> Tuple[List[str], bool]:
    """
    Parse credential input - NXC style auto-detection.

    If value can be opened as a file, reads lines from it.
    Otherwise treats as single credential.

    Args:
        value: Single value or path to a file

    Returns:
        tuple: (list of values, is_file)
    """
    if value is None:
        return [], False

    value = str(value).strip()
    if not value:
        return [], False

    # Try to open as file. Read bytes rather than text: real password lists are
    # frequently not valid UTF-8, and a text-mode read raises UnicodeDecodeError
    # (a ValueError, not an OSError) part-way through the file. That escaped this
    # handler and either aborted the scan or -- where a caller wrapped it -- made
    # the whole wordlist silently turn into a single literal credential.
    try:
        with open(value, "rb") as f:
            values = []
            for raw_line in f:
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    # latin-1 round-trips every byte, so no entry is dropped.
                    line = raw_line.decode("latin-1")
                line = line.strip()
                if line and not line.startswith("#"):
                    values.append(line)
            return values, True
    except (IOError, OSError) as e:
        _logger.debug(f"Failed to open credential file: {e}")
    except ValueError as e:
        # e.g. a credential containing a NUL byte: open() rejects the path.
        _logger.debug(f"Not usable as a credential file path: {e}")

    return [value], False


def load_credentials(
    username: str = "",
    password: str = "",
    defaults: list = None,
) -> list:
    """
    Load credentials from username/password args with auto file detection.

    Supports NXC-style auto-detection: if value is a file path, loads lines from it.
    Generates username x password combinations when both have multiple values.
    Falls back to defaults when no credentials provided.

    Args:
        username: Single username or path to username file
        password: Single password or path to password file
        defaults: List of (user, pass) tuples to use as fallback

    Returns:
        List of (username, password) tuples
    """
    usernames, _ = parse_credential_input(username)
    passwords, _ = parse_credential_input(password)

    # Generate combinations if we have values
    if usernames and passwords:
        return [(u, p) for u in usernames for p in passwords]

    # Single username with empty password
    if usernames:
        return [(u, "") for u in usernames]

    # Empty username with password(s)
    if passwords:
        return [("", p) for p in passwords]

    # Fall back to defaults
    return defaults or []
