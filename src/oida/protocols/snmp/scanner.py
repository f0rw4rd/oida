"""
SNMP Protocol Scanner.

Standalone SNMP scanner following the NetworkScanner pattern.
Queries devices for MIB-2 system info, vendor-specific OIDs,
and host enumeration tables (ARP/MAC via ``-e arp`` / ``-e cam``).

Supports community string brute-force, raw OID queries (--walk/--get),
native .mib file loading, and compact SNMPv3 auth.

Uses pysnmp v7 (async API). Supports SNMPv1, v2c, v3.
"""

import asyncio
import os
import time
from typing import Any, Dict

from ...utils import (
    NetworkScanner,
    register_protocol,
    create_protocol_module,
)
from ...utils.lazy_import import lazy_import
from ...utils.export_utils import export_table, configure as configure_export

from .constants import (
    SNMP_OIDS,
    VENDOR_OIDS,
    ENUM_CATEGORIES,
)

from .mixins import (
    BruteForceMixin,
    VersionDetectionMixin,
    WriteAccessMixin,
    V3EnumerationMixin,
    RawQueryMixin,
    HostEnumerationMixin,
)
from oida.utils.common_types import Category

_pysnmp = lazy_import("pysnmp", "SNMP")

protocol_options = {
    "community": {
        "type": "string",
        "description": "SNMP community string",
        "required": False,
        "default": "public",
    },
    "snmp-version": {
        "type": "enum",
        "description": "SNMP version (auto, 1, 2c, 3)",
        "required": False,
        "default": "auto",
        "values": ["auto", "1", "2c", "3"],
    },
}


def _validate_snmp_key(key: str, key_label: str, min_len: int = 8) -> str:
    """Validate an SNMPv3 auth/priv key meets the RFC 3414 minimum length.

    The previous implementation NUL-padded short keys so pysnmp would accept
    them locally — but the localized key would never match the device's own
    computed key (which can't see those NULs), causing every authenticated
    request to fail with a misleading "no response" diagnostic. RFC 3414
    section 11.2 mandates passphrases of at least 8 octets — refuse early
    with a clear error rather than silently padding to nonsense.
    """
    if key and len(key) < min_len:
        raise ValueError(
            f"SNMPv3 {key_label} must be at least {min_len} characters per RFC 3414; "
            f"got {len(key)}."
        )
    return key


@register_protocol(
    name="SNMP Scanner",
    description="SNMP device discovery with vendor identification and table extraction",
    default_port=161,
    authors=["f0rw4rd"],
    references=[
        {"type": "rfc", "ref": "RFC 1157 (SNMPv1)"},
        {"type": "rfc", "ref": "RFC 3416 (SNMPv2c)"},
        {"type": "rfc", "ref": "RFC 3414 (SNMPv3 USM)"},
    ],
    protocol_options=protocol_options,
)
class SNMPScanner(
    BruteForceMixin,
    VersionDetectionMixin,
    WriteAccessMixin,
    V3EnumerationMixin,
    RawQueryMixin,
    HostEnumerationMixin,
    NetworkScanner,
):
    """SNMP scanner for network device discovery.

    Queries devices for basic MIB-2 system info and vendor-specific OIDs.
    ARP/MAC tables available via ``-e arp`` / ``-e cam``. Supports SNMPv1/v2c/v3.
    """

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        raw_version = args.get("snmp_version") or args.get("snmp-version", "auto")
        if raw_version == "auto":
            self.version = "2c"  # sensible fallback if detection is skipped
            self._version_auto = True
        else:
            self.version = raw_version
            self._version_auto = False

        # SNMPv3 fine-grained defaults
        self.username = args.get("snmp_user", "")
        self.auth_protocol = args.get("snmp_auth_protocol", "SHA")
        self.auth_pass = args.get("snmp_auth_pass", "")
        self.priv_protocol = args.get("snmp_priv_protocol", "AES128")
        self.priv_pass = args.get("snmp_priv_pass", "")
        self.security_level = args.get("snmp_security_level", "authPriv")

        # Unified -C/--auth parsing: colon-separated = v3, plain = community
        auth_value = args.get("auth") or args.get("community", "public")
        if ":" in auth_value:
            # V3 format: user:authpass[:privpass]
            parts = auth_value.split(":", 2)
            self._version_auto = False
            self.version = "3"
            self.username = parts[0]
            if len(parts) >= 2:
                self.auth_pass = parts[1]
                self.security_level = "authNoPriv"
            if len(parts) >= 3:
                self.priv_pass = parts[2]
                self.security_level = "authPriv"
            if len(parts) == 1:
                self.security_level = "noAuthNoPriv"
            self.community = "public"
            self.logger.debug(
                f"Auth parsed as v3: user={self.username}, level={self.security_level}"
            )
        else:
            # Auto-detect file: if auth_value is a readable file, load communities
            from ...utils.default_credentials import parse_credential_input

            values, is_file = parse_credential_input(auth_value)
            if is_file:
                self.community = ",".join(values)
                self.logger.debug(
                    f"Auth parsed as community file: {len(values)} entries from {auth_value}"
                )
            else:
                self.community = auth_value
                self.logger.debug(f"Auth parsed as v2c community: {self.community}")

        # Fine-grained -u/-a/-x override the unified -C value
        if args.get("snmp_user"):
            self.username = args["snmp_user"]
            self._version_auto = False
            self.version = "3"
            # Infer security level from provided credentials
            if not self.auth_pass:
                self.security_level = "noAuthNoPriv"
            elif not self.priv_pass:
                self.security_level = "authNoPriv"
            self.logger.debug(f"Fine-grained -u override: user={self.username}, forcing v3")

        # Brute-force parameters
        self.do_default_creds = args.get("default_creds", False)
        self.brute_rate = args.get("brute_rate", 0.2)
        self.confirm_brute = args.get("confirm_brute", False)

        # Write access testing
        self.test_write = args.get("test_write", False)

        # Host enumeration parameters
        enum_raw = args.get("enum")
        self.enum_categories = []
        if enum_raw is not None:
            if enum_raw == "all":
                self.enum_categories = list(ENUM_CATEGORIES.keys())
            else:
                self.enum_categories = [c.strip() for c in enum_raw.split(",") if c.strip()]
        self.enum_limit = args.get("enum_limit", 0)

        # SNMPv3 enumeration parameters
        _enum_v3_raw = args.get("enum_v3")
        self.enum_v3 = _enum_v3_raw is not None
        self.enum_v3_target_user = _enum_v3_raw if _enum_v3_raw else None
        self.enum_users = args.get("enum_users", False)

        # Raw SET / walk-write parameters
        self.set_oid = args.get("set_oid")  # [oid, type_char, value] or None
        self.walk_write = args.get("walk_write")  # OID string or None

        # Raw query parameters
        self.walk_oid = args.get("walk")
        if args.get("walk_all"):
            self.walk_oid = "list:all"
        self.get_oids = args.get("get_oids")
        self.use_bulk = args.get("bulk", False)

        # MIB source directories
        self.mib_sources = []
        mib_dirs = args.get("mib_dirs") or []
        for d in mib_dirs:
            abs_path = os.path.abspath(d)
            self.mib_sources.append(f"file:///{abs_path}")

    def get_protocol_name(self) -> str:
        return "SNMP"

    def get_default_port(self) -> int:
        return 161

    def check_dependencies(self) -> bool:
        return _pysnmp.is_available

    def connect(self) -> Any:
        """Create SNMP engine and session objects, test reachability."""
        from pysnmp.hlapi.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )

        engine = SnmpEngine()
        auth_data = self._get_auth_data()
        if auth_data is None:
            return None

        context = ContextData()

        # Test reachability with sysDescr GET
        self.logger.debug(
            f"Connecting to {self.host}:{self.port} (v={self.version}, timeout={self.timeout})"
        )
        _connect_t0 = time.monotonic()

        async def _test():
            transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=1
            )
            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(SNMP_OIDS["sysDescr"])),
            )
            if error_indication:
                self.logger.debug(f"SNMP reachability test failed: {error_indication}")
                return None
            if error_status:
                self.logger.debug(f"SNMP error status: {error_status}")
                return None
            return transport

        transport = asyncio.run(_test())
        if transport is None:
            return None

        _connect_ms = (time.monotonic() - _connect_t0) * 1000
        self.logger.debug(f"Connection test passed ({_connect_ms:.0f}ms)")
        return (engine, auth_data, transport, context)

    def disconnect(self, connection: Any) -> None:
        """Clean up SNMP engine."""
        pass  # pysnmp engine doesn't require explicit cleanup

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform SNMP discovery on the target."""
        from pysnmp.hlapi.asyncio import SnmpEngine, UdpTransportTarget

        _, auth_data, _, context = connection

        # Fresh engine + transport -- pysnmp engines don't survive across
        # multiple asyncio.run() calls (internal transport dispatcher state).
        async def _discover():
            engine = SnmpEngine()
            transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=1
            )
            return await self._async_discover(engine, auth_data, transport, context)

        result = asyncio.run(_discover())

        if result:
            # NXC-style reporting
            self.report_host_info(
                self.host,
                vendor=result.get("vendor", "Unknown"),
                name=result.get("sys_info", {}).get("sysName", ""),
                description=result.get("sys_info", {}).get("sysDescr", ""),
            )
            self.report_service_info(
                self.host,
                port=self.port,
                name="SNMP",
                proto="udp",
                version=self.version,
            )

            # Security analysis
            self._analyze_security(result)

        return result or {}

    def _display_banner(self, discovery: Dict[str, Any]) -> None:
        """Display compact one-line host banner after discovery."""
        if not discovery:
            return

        sys_info = discovery.get("sys_info", {})
        vendor = discovery.get("vendor", "Unknown")
        desc = sys_info.get("sysDescr", "")
        name = sys_info.get("sysName", "")

        parts = []
        if name:
            parts.append(name)
        if vendor and vendor != "Unknown":
            parts.append(vendor)
        if desc:
            short_desc = desc[:80] + ("..." if len(desc) > 80 else "")
            parts.append(short_desc)

        if parts:
            self.logger.success(" | ".join(parts))

        # Version info
        version_label = f"SNMPv{self.version}"
        if self.version in ("1", "2c"):
            version_label += f" community='{self.community}'"
        elif self.version == "3":
            version_label += f" user='{self.username}'"
        self.logger.display(f"    {version_label}")

    def run_scan(self) -> Dict[str, Any]:
        """Override run_scan to support brute, comma-separated -C, and raw queries."""
        if not self.check_dependencies():
            from ...utils import ics_logger as _log

            _log.log_error(f"Missing dependencies for {self.get_protocol_name()} scanner")
            return {"error": "missing_dependencies"}

        host, port = self.get_target_info()

        if not self.validate_target(host, port):
            return {"error": "invalid_target"}

        results: Dict[str, Any] = {}

        try:
            # Phase 0a: Auto-detect supported SNMP versions
            if self._version_auto and not self.enum_v3 and not self.enum_users:
                detection = self._detect_versions()
                results["version_detection"] = detection
                supported = detection.get("supported_versions", [])
                if supported:
                    best = detection["best_version"]
                    if best != self.version:
                        self.logger.info(
                            f"Auto-selected SNMPv{best} "
                            f"(supported: {', '.join('v' + v for v in supported)})"
                        )
                        self.version = best
                    else:
                        self.logger.info(
                            f"SNMPv{self.version} confirmed "
                            f"(supported: {', '.join('v' + v for v in supported)})"
                        )

                    # V3 auto-selected but no credentials provided
                    if best == "3" and not self.username:
                        self.logger.fail(
                            "SNMPv3 detected but no credentials provided -- "
                            "use -C user:authpass:privpass"
                        )
                        results["version_detection"] = detection
                        return results
                else:
                    self.logger.fail("No response (no SNMP version detected)")
                    return {"error": "no_snmp_response", "version_detection": detection}

            # Phase 0a: SNMPv3 user enumeration only (--enum-users)
            if self.enum_users:
                # --enum-users implies SNMPv3. With -V auto (the default) version is
                # still "2c" here, so force v3 before the guard -- otherwise the
                # default invocation wrongly fails "requires SNMPv3".
                if self._version_auto:
                    self.version = "3"
                if self.version in ("1", "2c"):
                    self.logger.fail("--enum-users requires SNMPv3 (use -V 3 or -V auto)")
                    return results
                if not self.confirm_brute:
                    self.logger.fail("--enum-users requires --confirm (active probing)")
                    return results
                self.version = "3"  # --enum-users implies SNMPv3
                from ...utils.default_credentials import SNMP_V3_USERNAMES, parse_credential_input

                if self.username:
                    usernames, _ = parse_credential_input(self.username)
                else:
                    usernames = list(SNMP_V3_USERNAMES)
                results["v3_user_enum"] = self._enum_v3_users(usernames)

                # Summary table
                valid = results["v3_user_enum"].get("valid_users", [])
                if valid:
                    output_dir = self.args.get("output-dir") or self.args.get("output")
                    full_width = self.args.get("full_width", False)
                    configure_export(
                        output_dir=output_dir, logger=self.logger, full_width=full_width
                    )
                    host_sfx = self.host.replace(".", "_")
                    headers = ["Username", "Security Level"]
                    rows = [[u["username"], u["level"]] for u in valid]
                    export_table(f"snmp_v3_users_{host_sfx}", headers, rows, title="SNMPv3 Users")

                return results

            # Phase 0b: SNMPv3 enumeration (if requested)
            if self.enum_v3:
                # -E/--enum-v3 implies SNMPv3. With -V auto (the default) the version
                # is still "2c" here because Phase 0a auto-detect is skipped for
                # enum_v3, so force v3 (mirrors --enum-users at the branch above).
                if self._version_auto:
                    self.version = "3"
                if self.version in ("1", "2c"):
                    self.logger.fail("-E/--enum-v3 requires SNMPv3 (use -V 3 or -V auto)")
                    return results
                if not self.confirm_brute:
                    self.logger.fail("-E/--enum-v3 requires --confirm (active probing)")
                    return results
                v3_results = self._enum_v3()
                results["v3_enumeration"] = v3_results
                # If credentials found, set them for subsequent connect/discover
                if v3_results.get("credentials"):
                    cred = v3_results["credentials"][0]
                    self.version = "3"
                    self.username = cred["username"]
                    self.auth_pass = cred.get("auth_pass", "")
                    self.auth_protocol = cred.get("auth_protocol", "SHA")
                    self.priv_pass = cred.get("priv_pass", "")
                    self.priv_protocol = cred.get("priv_protocol", "AES128")
                    self.security_level = cred.get("security_level", "noAuthNoPriv")
                    self.logger.info(
                        f"SNMP: using discovered v3 credentials "
                        f"(user={self.username}, level={self.security_level})"
                    )
                elif not v3_results.get("valid_users"):
                    # _enum_v3 already emitted a specific reason (no response vs.
                    # responded-but-no-users); don't pile on a vaguer line.
                    return results

            # Phase 1: Community brute-force (--default-creds)
            elif self.do_default_creds:
                if not self.confirm_brute:
                    self.logger.fail(
                        "Brute-force requires --confirm flag "
                        "(e.g. oida snmp <target> --default-creds --confirm)"
                    )
                    return results
                valid = self._brute_communities()
                results["brute"] = valid
                if valid:
                    self.community = valid[0]
                    self.logger.info(f"SNMP: using discovered community '{self.community}'")
                else:
                    self.logger.warning("SNMP: no valid communities found during brute")

            # Phase 1b: Comma-separated -C (lightweight multi-community test)
            elif "," in self.community:
                candidates = [c.strip() for c in self.community.split(",") if c.strip()]
                valid = self._test_communities(candidates)
                if valid:
                    self.community = valid[0]
                    self.logger.info(f"SNMP: using community '{self.community}'")
                    results["tested_communities"] = valid
                else:
                    self.logger.fail("None of the communities responded")
                    return {"error": "no_valid_community"}

            # Phase 2: Connect + automated discovery
            if self.version == "3":
                self.logger.info(
                    f"Connecting via SNMPv3 "
                    f"(user={self.username}, level={self.security_level}, "
                    f"auth={self.auth_protocol}, priv={self.priv_protocol})..."
                )
            else:
                self.logger.info(
                    f"Connecting via SNMPv{self.version} (community={self.community})..."
                )
            connection = self.connect()
            if not connection:
                self.logger.fail("No response from SNMP agent")
                results.setdefault("error", "connection_failed")
                return results

            self.logger.success(f"SNMP agent responding (SNMPv{self.version})")

            # Configure export system once for all subsequent phases
            output_dir = self.args.get("output-dir") or self.args.get("output")
            full_width = self.args.get("full_width", False)
            configure_export(output_dir=output_dir, logger=self.logger, full_width=full_width)

            discovery_results = self.discover(connection)
            results.update(discovery_results)

            # Display compact banner
            self._display_banner(discovery_results)

            # Phase 2b: Write access test (if requested)
            if self.test_write:
                if not self.confirm_brute:
                    self.logger.fail(
                        "--test-write requires --confirm flag "
                        "(e.g. oida snmp <target> --test-write --confirm)"
                    )
                    return results
                engine, auth_data, transport, context = connection
                write_result = self._check_write_access(engine, auth_data, transport, context)
                results["write_access"] = write_result

            # Phase 2d: Raw SET (if requested)
            if self.set_oid:
                if not self.confirm_brute:
                    self.logger.fail(
                        "--set requires --confirm flag "
                        "(e.g. oida snmp <target> --set OID TYPE VALUE --confirm)"
                    )
                    return results
                oid, type_char, value = self.set_oid
                set_result = self._raw_set(connection, oid, type_char, value)
                results["set"] = set_result

            # Phase 2c: Host enumeration (if requested)
            if self.enum_categories:
                enum_results = self._run_enumeration(connection)
                results["enumeration"] = enum_results

            # Phase 3: Raw queries (if requested)
            if self.walk_oid or self.get_oids:
                from pysnmp.hlapi.asyncio import SnmpEngine as _SE, UdpTransportTarget as _UT

                _, auth_data, _, context = connection

                async def _raw():
                    transport = await _UT.create(
                        (self.host, self.port), timeout=self.timeout, retries=1
                    )
                    return await self._async_raw_queries(
                        _SE(),
                        auth_data,
                        transport,
                        context,
                    )

                raw = asyncio.run(_raw())
                results["raw_queries"] = raw

            # Phase 3b: Walk-write (if requested)
            if self.walk_write:
                if not self.confirm_brute:
                    self.logger.fail(
                        "--walk-write requires --confirm flag "
                        "(e.g. oida snmp <target> --walk-write OID --confirm)"
                    )
                    return results
                from pysnmp.hlapi.asyncio import SnmpEngine as _SE2, UdpTransportTarget as _UT2

                _, auth_data, _, context = connection

                async def _walk_write():
                    transport = await _UT2.create(
                        (self.host, self.port), timeout=self.timeout, retries=1
                    )
                    return await self._async_walk_write(
                        _SE2(), auth_data, transport, context, self.walk_write
                    )

                ww_result = asyncio.run(_walk_write())
                results["walk_write"] = ww_result

            return results

        except Exception as e:
            from ...utils import ics_logger as _log

            _log.log_exc(f"Error during {self.get_protocol_name()} scan")
            results.setdefault("error", str(e))
            return results

        finally:
            self.export_results()

    # --- Auth Data ---

    def _get_auth_data(self) -> Any:
        """Build authentication data based on SNMP version."""
        from pysnmp.hlapi.asyncio import CommunityData

        if self.version == "3":
            if not self.username:
                self.logger.warning("SNMPv3 requires credentials -- use -C user:authpass:privpass")
                return None
            from pysnmp.hlapi.asyncio import UsmUserData

            try:
                auth_protocols, priv_protocols = self._get_usm_protocol_maps()
            except (ImportError, AttributeError) as e:
                self.logger.warning(
                    f"SNMPv3 crypto symbols unavailable: {e} -- install pysnmp with crypto extras"
                )
                return None

            auth_proto = auth_protocols.get(self.auth_protocol, auth_protocols["SHA"])
            priv_proto = priv_protocols.get(self.priv_protocol, priv_protocols["AES128"])

            self.logger.debug(
                f"v3 auth: user={self.username}, level={self.security_level}, "
                f"auth_proto={self.auth_protocol}, priv_proto={self.priv_protocol}"
            )
            if self.security_level == "noAuthNoPriv":
                return UsmUserData(self.username)
            try:
                if self.security_level == "authNoPriv":
                    return UsmUserData(
                        self.username,
                        authKey=_validate_snmp_key(self.auth_pass, "auth password"),
                        authProtocol=auth_proto,
                    )
                else:  # authPriv
                    return UsmUserData(
                        self.username,
                        authKey=_validate_snmp_key(self.auth_pass, "auth password"),
                        privKey=_validate_snmp_key(self.priv_pass, "priv password"),
                        authProtocol=auth_proto,
                        privProtocol=priv_proto,
                    )
            except ValueError as e:
                self.logger.fail(str(e))
                return None
        else:
            # v1/v2c: mpModel 0 = SNMPv1, 1 = SNMPv2c
            mp_model = 1 if self.version == "2c" else 0
            self.logger.debug(f"v1/v2c auth: community={self.community}, mpModel={mp_model}")
            return CommunityData(self.community, mpModel=mp_model)

    # --- Async Discovery ---

    async def _async_discover(self, engine, auth_data, transport, context) -> Dict:
        """Async implementation of single-target SNMP discovery."""
        from pysnmp.hlapi.asyncio import (
            ObjectIdentity,
            ObjectType,
            get_cmd,
        )

        # Get basic system info
        sys_info = {}
        for name, oid in SNMP_OIDS.items():
            try:
                error_indication, error_status, _, var_binds = await get_cmd(
                    engine,
                    auth_data,
                    transport,
                    context,
                    ObjectType(ObjectIdentity(oid)),
                )
                if error_indication or error_status:
                    continue
                for var_bind in var_binds:
                    value = var_bind[1].prettyPrint()
                    if value and value != "No Such Object currently exists at this OID":
                        sys_info[name] = value
            except Exception as e:
                self.logger.debug(f"SNMP: failed to get {name}: {e}")

        if not sys_info:
            return {}

        # Parse vendor from sysObjectID
        vendor = "Unknown"
        if "sysObjectID" in sys_info:
            oid = sys_info["sysObjectID"]
            if not oid.startswith("."):
                oid = "." + oid
            if ".1.3.6.1.4.1." in oid:
                parts = oid.split(".1.3.6.1.4.1.")[-1].split(".")
                if parts:
                    vendor = VENDOR_OIDS.get(parts[0], f"Enterprise:{parts[0]}")

        # Query vendor-specific OIDs
        vendor_info = await self._query_vendor_oids(vendor, engine, auth_data, transport, context)

        return {
            "host": self.host,
            "version": self.version,
            "sys_info": sys_info,
            "vendor": vendor,
            "vendor_info": vendor_info,
        }

    # --- Security Analysis ---

    def _analyze_security(self, result: Dict) -> None:
        """Analyze SNMP scan results for security findings."""
        if self.version == "1":
            self.logger.security_finding(
                "Legacy protocol",
                category=Category.AUTHENTICATION,
                detail="SNMPv1 supported (no message integrity)",
            )
        if self.version in ("1", "2c"):
            self.logger.security_finding(
                "No encryption",
                category=Category.ENCRYPTION,
                detail=f"SNMPv{self.version} sends community strings in cleartext",
            )

        if self.version in ("1", "2c") and self.community == "public":
            self.logger.security_finding(
                "Default credentials",
                category=Category.AUTHENTICATION,
                detail="Default community string 'public' accepted",
            )

        sys_info = result.get("sys_info", {})
        if not sys_info.get("sysContact") and not sys_info.get("sysLocation"):
            self.logger.warning("sysContact and sysLocation not configured")


def scan_targets(targets, **kwargs):
    """Multi-target scan for discovery integration.

    Args:
        targets: List of IP addresses to scan
        **kwargs: SNMP parameters (community, version, port, timeout, etc.)

    Returns:
        Dict mapping IP -> result dict
    """
    from ...utils import ics_logger as _log

    results = {}
    for target in targets:
        args = {
            "host": target,
            "port": kwargs.get("port", 161),
            "timeout": kwargs.get("timeout", 2),
            "community": kwargs.get("community", "public"),
            "snmp_version": kwargs.get("version", "2c"),
            "snmp_user": kwargs.get("username", ""),
            "snmp_auth_protocol": kwargs.get("auth_protocol", "SHA"),
            "snmp_auth_pass": kwargs.get("auth_pass", ""),
            "snmp_priv_protocol": kwargs.get("priv_protocol", "AES128"),
            "snmp_priv_pass": kwargs.get("priv_pass", ""),
            "snmp_security_level": kwargs.get("security_level", "authPriv"),
        }
        try:
            scanner = SNMPScanner(args)
            connection = scanner.connect()
            if connection:
                result = scanner.discover(connection)
                if result:
                    results[target] = result
                scanner.disconnect(connection)
        except Exception as e:
            _log.log_debug(f"SNMP scan failed for {target}: {e}")

    _log.log_info(f"SNMP found {len(results)} devices from {len(targets)} targets")
    return results


# Module-level exports
metadata, run = create_protocol_module(
    SNMPScanner, dependencies_check_func=lambda: not _pysnmp.is_available
)
