"""BACnet service catalog — single source of truth for service capabilities.

Maps every BACnetServicesSupported bit to:
  * its canonical name (used to decode ``protocolServicesSupported``),
  * a risk tier (read / write / control / indication),
  * whether OIDA can invoke it via ``--call`` and which handler does so,
  * the ``--call`` token(s) and argument syntax.

``--services`` cross-references this catalog to show, per device-advertised
service, whether OIDA can act on it and how. ``--call`` uses it to dispatch.
The ordered ``SERVICE_NAMES`` list is also the bitstring-decode table, so the
detection and the invocation paths can never drift apart.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Risk tiers -----------------------------------------------------------------
RISK_READ = "read"  # non-mutating: discovery / reads
RISK_WRITE = "write"  # mutates device state -> requires --confirm
RISK_CONTROL = "control"  # disruptive (reboot / mute / DoS) -> --confirm + warn
RISK_INDICATION = "indication"  # device emits/receives; not invokable on a target


@dataclass(frozen=True)
class ServiceSpec:
    index: int  # BACnetServicesSupported bit position
    name: str  # canonical BACnet service name
    risk: str
    callable: bool  # OIDA can invoke it via --call
    handler: Optional[str] = None  # CallMixin method name
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    usage: str = ""  # --call argument syntax

    @property
    def mutating(self) -> bool:
        return self.risk in (RISK_WRITE, RISK_CONTROL)


# Ordered by bit index == protocolServicesSupported decode order.
# (Canonical BACnetServicesSupported enumeration, ASHRAE 135.)
SERVICES: List[ServiceSpec] = [
    ServiceSpec(
        0,
        "acknowledgeAlarm",
        RISK_WRITE,
        True,
        "_call_acknowledge_alarm",
        ("ackalarm",),
        "PROC:objType:inst:eventState",
    ),
    ServiceSpec(1, "confirmedCOVNotification", RISK_INDICATION, False),
    ServiceSpec(2, "confirmedEventNotification", RISK_INDICATION, False),
    ServiceSpec(
        3,
        "getAlarmSummary",
        RISK_READ,
        True,
        "_call_get_alarm_summary",
        ("alarmsummary",),
        "(no args)",
    ),
    ServiceSpec(4, "getEnrollmentSummary", RISK_READ, False),
    ServiceSpec(
        5,
        "subscribeCOV",
        RISK_WRITE,
        True,
        "_call_subscribe_cov",
        ("cov",),
        "objType:inst[:lifetime]",
    ),
    ServiceSpec(
        6,
        "atomicReadFile",
        RISK_READ,
        True,
        "_call_atomic_read_file",
        ("readfile",),
        "fileInst[:start[:count]]",
    ),
    ServiceSpec(
        7,
        "atomicWriteFile",
        RISK_WRITE,
        True,
        "_call_atomic_write_file",
        ("writefile", "upload"),
        "fileInst:localPath[:start]",
    ),
    ServiceSpec(
        8,
        "addListElement",
        RISK_WRITE,
        True,
        "_call_add_list_element",
        ("addlist",),
        "objType:inst:property:value",
    ),
    ServiceSpec(
        9,
        "removeListElement",
        RISK_WRITE,
        True,
        "_call_remove_list_element",
        ("rmlist",),
        "objType:inst:property:value",
    ),
    ServiceSpec(
        10, "createObject", RISK_WRITE, True, "_call_create_object", ("create",), "objType[:inst]"
    ),
    ServiceSpec(
        11, "deleteObject", RISK_WRITE, True, "_call_delete_object", ("delete",), "objType:inst"
    ),
    ServiceSpec(
        12,
        "readProperty",
        RISK_READ,
        True,
        "_call_read_property",
        ("read", "rp"),
        "objType:inst:property",
    ),
    ServiceSpec(13, "readPropertyConditional", RISK_READ, False),
    ServiceSpec(
        14,
        "readPropertyMultiple",
        RISK_READ,
        True,
        "_call_read_property_multiple",
        ("rpm",),
        "objType:inst:prop[,objType:inst:prop...]",
    ),
    ServiceSpec(
        15,
        "writeProperty",
        RISK_WRITE,
        True,
        "_call_write_property",
        ("write", "wp"),
        "objType:inst:property:value[:priority]",
    ),
    ServiceSpec(
        16,
        "writePropertyMultiple",
        RISK_WRITE,
        True,
        "_call_write_property_multiple",
        ("wpm",),
        "objType:inst:prop:val[,objType:inst:prop:val...]",
    ),
    ServiceSpec(
        17,
        "deviceCommunicationControl",
        RISK_CONTROL,
        True,
        "_call_dcc",
        ("dcc",),
        "enable|disable|disable-initiation[:minutes[:password]]",
    ),
    ServiceSpec(18, "confirmedPrivateTransfer", RISK_CONTROL, False),
    ServiceSpec(
        19,
        "confirmedTextMessage",
        RISK_WRITE,
        True,
        "_call_text_message",
        ("textmessage", "msg"),
        '"message text"[:class[:priority]]',
    ),
    ServiceSpec(
        20,
        "reinitializeDevice",
        RISK_CONTROL,
        True,
        "_call_reinitialize_device",
        ("reinit",),
        "coldstart|warmstart[:password]",
    ),
    ServiceSpec(21, "vtOpen", RISK_INDICATION, False),
    ServiceSpec(22, "vtClose", RISK_INDICATION, False),
    ServiceSpec(23, "vtData", RISK_INDICATION, False),
    ServiceSpec(24, "authenticate", RISK_INDICATION, False),
    ServiceSpec(25, "requestKey", RISK_INDICATION, False),
    ServiceSpec(26, "i-Am", RISK_INDICATION, False),
    ServiceSpec(27, "i-Have", RISK_INDICATION, False),
    ServiceSpec(28, "unconfirmedCOVNotification", RISK_INDICATION, False),
    ServiceSpec(29, "unconfirmedEventNotification", RISK_INDICATION, False),
    ServiceSpec(30, "unconfirmedPrivateTransfer", RISK_INDICATION, False),
    ServiceSpec(31, "unconfirmedTextMessage", RISK_INDICATION, False),
    ServiceSpec(
        32,
        "timeSynchronization",
        RISK_WRITE,
        True,
        "_call_time_sync",
        ("timesync",),
        "now|YYYY-MM-DDTHH:MM:SS",
    ),
    ServiceSpec(
        33, "who-Has", RISK_READ, True, "_call_who_has", ("whohas",), "objectName | objType:inst"
    ),
    ServiceSpec(34, "who-Is", RISK_READ, True, "_call_who_is", ("whois",), "(no args)"),
    ServiceSpec(
        35,
        "readRange",
        RISK_READ,
        True,
        "_call_read_range",
        ("readrange",),
        "objType:inst  (reads logBuffer)",
    ),
    ServiceSpec(
        36,
        "utcTimeSynchronization",
        RISK_WRITE,
        True,
        "_call_utc_time_sync",
        ("utctimesync",),
        "now|YYYY-MM-DDTHH:MM:SS",
    ),
    ServiceSpec(
        37,
        "lifeSafetyOperation",
        RISK_WRITE,
        True,
        "_call_life_safety_operation",
        ("lso",),
        "objType:inst:operation[:process]",
    ),
    ServiceSpec(38, "subscribeCOVProperty", RISK_WRITE, False),
    ServiceSpec(
        39,
        "getEventInformation",
        RISK_READ,
        True,
        "_call_get_event_information",
        ("eventinfo",),
        "(no args)",
    ),
    ServiceSpec(
        40,
        "writeGroup",
        RISK_CONTROL,
        True,
        "_call_write_group",
        ("wg",),
        "group:channel:value[:priority]",
    ),
    ServiceSpec(41, "subscribeCOVPropertyMultiple", RISK_WRITE, False),
    ServiceSpec(42, "confirmedCOVNotificationMultiple", RISK_INDICATION, False),
    ServiceSpec(43, "unconfirmedCOVNotificationMultiple", RISK_INDICATION, False),
]

# Bitstring-decode table: index -> name (drives protocolServicesSupported decode).
SERVICE_NAMES: List[str] = [s.name for s in SERVICES]

# Token -> spec (canonical name + aliases, case-insensitive) for --call lookup.
_BY_TOKEN: Dict[str, ServiceSpec] = {}
for _s in SERVICES:
    _BY_TOKEN[_s.name.lower()] = _s
    for _a in _s.aliases:
        _BY_TOKEN[_a.lower()] = _s


def lookup(token: str) -> Optional[ServiceSpec]:
    """Resolve a --call token (canonical name or alias) to a ServiceSpec."""
    if not token:
        return None
    return _BY_TOKEN.get(token.strip().lower())


def by_name(name: str) -> Optional[ServiceSpec]:
    """Resolve an exact canonical service name (as decoded from the bitstring)."""
    for s in SERVICES:
        if s.name == name:
            return s
    return None
