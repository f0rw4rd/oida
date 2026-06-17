"""
SNMP Write Access Mixin

Handles write access detection and SET operations:
- VACM table analysis
- Idempotent SET probe
- USM protocol maps (shared by _get_auth_data and _probe_v3)
- Raw SET operations
- Walk-write enumeration
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class WriteAccessMixin(_ScannerBase):
    """Mixin providing SNMP write access detection and SET operations."""

    def _check_write_access(self, engine, auth_data, transport, context) -> Dict:
        """Check if current credentials have write access.

        Strategy: VACM table walk first, SET probe as fallback.
        Returns dict with method used, result, and details.
        """
        from pysnmp.hlapi.asyncio import SnmpEngine, UdpTransportTarget

        self.logger.info("Testing write access...")

        # Fresh engine + transport -- pysnmp engines don't survive across
        # multiple asyncio.run() calls (internal transport dispatcher state).
        async def _write_check():
            fresh_engine = SnmpEngine()
            fresh_transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=1
            )
            return await self._async_check_write(fresh_engine, auth_data, fresh_transport, context)

        result = asyncio.run(_write_check())

        if result.get("writable"):
            self.logger.security_finding(
                "Writable access",
                f"WRITE ACCESS via {result['method']}: {result.get('detail', '')}",
            )
        else:
            self.logger.info(f"  Result: read-only ({result.get('detail', 'no write access')})")

        return result

    async def _async_check_write(self, engine, auth_data, transport, context) -> Dict:
        """Async write access check: VACM walk (v3 only) then SET probe fallback."""
        # 1. VACM is SNMPv3-only (RFC 3415) -- skip for v1/v2c
        if self.version == "3":
            vacm_result = await self._vacm_check(engine, auth_data, transport, context)
            if vacm_result["conclusive"]:
                return vacm_result

        # 2. Fallback: idempotent SET probe on sysContact.0
        return await self._set_probe(engine, auth_data, transport, context)

    async def _vacm_check(self, engine, auth_data, transport, context) -> Dict:
        """Walk VACM access table to detect write view configuration."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        from ..constants import VACM_OIDS

        write_view_oid = VACM_OIDS["vacmAccessWriteViewName"]
        read_view_oid = VACM_OIDS["vacmAccessReadViewName"]

        write_views = []
        read_views = []

        # Walk vacmAccessWriteViewName
        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(write_view_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    val = var_bind[1].prettyPrint()
                    write_views.append(val)
        except Exception as e:
            self.logger.debug(f"VACM write view walk error: {e}")

        # Walk vacmAccessReadViewName for context
        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(read_view_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    val = var_bind[1].prettyPrint()
                    read_views.append(val)
        except Exception as e:
            self.logger.debug(f"VACM read view walk error: {e}")

        if not write_views and not read_views:
            # VACM not supported or not accessible
            self.logger.info("  VACM: no entries (not supported or access denied)")
            return {"conclusive": False, "method": "vacm", "writable": False}

        # Filter write views: "none" and empty strings mean no write access
        non_empty_writes = [v for v in write_views if v and v not in ("''", "none")]

        if not non_empty_writes:
            # ALL write views are empty/none -- no group has write access
            self.logger.info("  VACM: all write views empty (read-only)")
            return {
                "conclusive": True,
                "method": "vacm",
                "writable": False,
                "detail": "all write views empty",
                "read_views": read_views,
            }

        # Some groups have write views configured, but the VACM table is
        # global -- it doesn't tell us if OUR credentials have write access.
        # Fall through to SET probe for a definitive answer.
        view_names = ", ".join(f"'{v}'" for v in non_empty_writes)
        self.logger.debug(f"  VACM: write view {view_names} configured for some group(s)")
        return {
            "conclusive": False,
            "method": "vacm",
            "writable": False,
            "detail": f"write view(s) exist: {view_names} (need SET probe to confirm)",
            "write_views": non_empty_writes,
            "read_views": read_views,
        }

    async def _set_probe(self, engine, auth_data, transport, context) -> Dict:
        """Idempotent SET probe: GET sysContact.0, SET same value back."""
        from pysnmp.hlapi.asyncio import (
            ObjectIdentity,
            ObjectType,
            OctetString,
            get_cmd,
            set_cmd,
        )

        from ..constants import SNMP_OIDS

        sys_contact_oid = SNMP_OIDS["sysContact"]

        # 1. GET current sysContact.0
        try:
            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(sys_contact_oid)),
            )
        except Exception as e:
            self.logger.debug(f"SET probe GET failed: {e}")
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": f"GET failed: {e}",
            }

        if error_indication or error_status:
            self.logger.info("  SET probe: cannot read sysContact.0 (skipped)")
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": f"GET error: {error_indication or error_status}",
            }

        current_value = var_binds[0][1]
        display_val = current_value.prettyPrint()

        # Refuse to write unless we read back a genuine OctetString. pysnmp v7
        # returns NoSuchObject/NoSuchInstance/EndOfMibView inline (not as
        # error_status); writing OctetString("") over those would CLEAR a
        # populated sysContact instead of restoring it.
        from pysnmp.proto import rfc1905

        if isinstance(
            current_value, (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)
        ):
            self.logger.info("  SET probe: sysContact.0 absent (skipped, cannot probe safely)")
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": "sysContact.0 absent",
            }
        if not isinstance(current_value, OctetString):
            self.logger.info(
                f"  SET probe: sysContact.0 is {type(current_value).__name__}, not OctetString (skipped)"
            )
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": f"unexpected type {type(current_value).__name__}",
            }
        original_octets = current_value.asOctets()

        # 2. SET sysContact.0 back to its current value. Preserve the original
        # ASN.1 object so the write is a true identity (re-wrapping a non-string
        # type as OctetString would corrupt the value on permissive agents).
        try:
            error_indication, error_status, _, _ = await set_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(
                    ObjectIdentity(sys_contact_oid),
                    OctetString(original_octets),
                ),
            )
        except Exception as e:
            self.logger.debug(f"SET probe SET failed: {e}")
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": f"SET exception: {e}",
            }

        if error_indication:
            self.logger.info(f"  SET probe: {error_indication}")
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": str(error_indication),
            }

        if error_status:
            status_val = int(error_status)
            # noSuchName(2), readOnly(4), noAccess(6), authorizationError(16),
            # notWritable(17) all mean "not writable" definitively. badValue(3) is
            # NOT in this set: it means the value/type was rejected, not that the
            # OID is read-only -- treat it as inconclusive so a type round-trip
            # problem surfaces instead of being mislabelled read-only.
            read_only_codes = {2, 4, 6, 16, 17}
            if status_val in read_only_codes:
                status_name = {
                    2: "noSuchName",
                    4: "readOnly",
                    6: "noAccess",
                    16: "authorizationError",
                    17: "notWritable",
                }.get(status_val, str(status_val))
                self.logger.info(f"  SET probe: sysContact.0 -> {status_name} (read-only)")
                return {
                    "conclusive": True,
                    "method": "set_probe",
                    "writable": False,
                    "detail": f"error_status={status_name}",
                }
            # Other error (incl. badValue) -- inconclusive
            self.logger.info(f"  SET probe: error_status={error_status}")
            return {
                "conclusive": False,
                "method": "set_probe",
                "writable": False,
                "detail": f"error_status={error_status}",
            }

        # 3. Read back and verify the value is unchanged. If the agent coerced or
        # altered it, restore the original and report the anomaly rather than
        # leaving the device in a modified state.
        try:
            rb_ind, rb_status, _, rb_binds = await get_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(sys_contact_oid)),
            )
            if not (rb_ind or rb_status) and rb_binds:
                rb_val = rb_binds[0][1]
                if isinstance(rb_val, OctetString) and rb_val.asOctets() != original_octets:
                    self.logger.warning("  SET probe: read-back differs from original -- restoring")
                    await set_cmd(
                        engine,
                        auth_data,
                        transport,
                        context,
                        ObjectType(ObjectIdentity(sys_contact_oid), OctetString(original_octets)),
                    )
                    return {
                        "conclusive": True,
                        "method": "set_probe",
                        "writable": True,
                        "detail": "writable but value changed on write-back (restored)",
                    }
        except Exception as e:
            self.logger.debug(f"SET probe read-back failed: {e}")

        # Success -- write access confirmed, value verified unchanged
        self.logger.info(f'  SET probe: sysContact.0 = "{display_val}" -> success')
        self.logger.info("WRITE ACCESS: confirmed via SET probe on sysContact.0")
        return {
            "conclusive": True,
            "method": "set_probe",
            "writable": True,
            "detail": f'sysContact.0 = "{display_val}"',
        }

    # --- USM Protocol Maps (shared by _get_auth_data and _probe_v3) ---

    @staticmethod
    def _get_usm_protocol_maps():
        """Return (auth_protocols, priv_protocols) dicts mapping name to pysnmp OID.

        Lazy-imports pysnmp USM symbols on first call.
        """
        from pysnmp.hlapi.asyncio import (
            usm3DESEDEPrivProtocol,
            usmAesCfb128Protocol,
            usmAesCfb192Protocol,
            usmAesCfb256Protocol,
            usmDESPrivProtocol,
            usmHMAC192SHA256AuthProtocol,
            usmHMAC256SHA384AuthProtocol,
            usmHMAC384SHA512AuthProtocol,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
        )

        auth_protocols = {
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol,
        }
        priv_protocols = {
            "DES": usmDESPrivProtocol,
            "3DES": usm3DESEDEPrivProtocol,
            "AES128": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol,
            "AES256": usmAesCfb256Protocol,
        }
        return auth_protocols, priv_protocols

    # --- Raw SET / Walk-Write ---

    # Type character -> pysnmp type mapping (snmpset(1) notation)
    _SET_TYPE_MAP = {
        "i": "Integer32",
        "s": "OctetString",
        "x": "OctetString",  # hexValue variant
        "o": "ObjectIdentifier",
        "a": "IpAddress",
    }

    def _raw_set(self, connection, oid: str, type_char: str, value: str) -> Dict:
        """Execute a single SNMP SET operation.

        Args:
            connection: (engine, auth_data, transport, context) tuple
            oid: Target OID string
            type_char: Type character (i, s, x, o, a)
            value: Value to set

        Returns:
            Dict with oid, type, value, success, error keys.
        """
        from pysnmp.hlapi.asyncio import (
            Integer32,
            IpAddress,
            ObjectIdentity,
            ObjectType,
            OctetString,
            SnmpEngine,
            UdpTransportTarget,
            set_cmd,
        )
        from pysnmp.hlapi.asyncio import ObjectIdentifier as OIDType

        type_char = type_char.lower()
        if type_char not in self._SET_TYPE_MAP:
            self.logger.fail(
                f"Unknown type '{type_char}' (valid: i=INTEGER, s=STRING, x=HEX, o=OID, a=IPADDR)"
            )
            return {
                "oid": oid,
                "type": type_char,
                "value": value,
                "success": False,
                "error": f"unknown type '{type_char}'",
            }

        _, auth_data, _, context = connection

        # Build typed value. Coercion (int(), hexValue=, IpAddress()) can raise on
        # malformed user input -- catch it here rather than letting it abort the
        # whole scan (the try around _do_set below does not cover this block).
        try:
            if type_char == "i":
                typed_value = Integer32(int(value))
            elif type_char == "s":
                typed_value = OctetString(value.encode("utf-8"))
            elif type_char == "x":
                hex_str = value[2:] if value.lower().startswith("0x") else value
                if len(hex_str) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in hex_str):
                    raise ValueError(f"invalid hex value '{value}'")
                typed_value = OctetString(hexValue=hex_str)
            elif type_char == "o":
                typed_value = OIDType(value)
            elif type_char == "a":
                typed_value = IpAddress(value)
            else:
                typed_value = OctetString(value.encode("utf-8"))
        except Exception as e:
            self.logger.fail(f"SET {oid}: invalid value for type '{type_char}': {e}")
            return {
                "oid": oid,
                "type": type_char,
                "value": value,
                "success": False,
                "error": f"invalid value: {e}",
            }

        async def _do_set():
            engine = SnmpEngine()
            transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=1
            )
            error_indication, error_status, _, _ = await set_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(oid), typed_value),
            )
            return error_indication, error_status

        try:
            error_indication, error_status = asyncio.run(_do_set())
        except Exception as e:
            self.logger.fail(f"SET {oid} failed: {e}")
            return {
                "oid": oid,
                "type": type_char,
                "value": value,
                "success": False,
                "error": str(e),
            }

        if error_indication:
            self.logger.fail(f"SET {oid}: {error_indication}")
            return {
                "oid": oid,
                "type": type_char,
                "value": value,
                "success": False,
                "error": str(error_indication),
            }

        if error_status:
            status_val = int(error_status)
            status_name = {
                4: "readOnly",
                6: "noAccess",
                16: "authorizationError",
                17: "notWritable",
            }.get(status_val, str(error_status))
            self.logger.fail(f"SET {oid}: {status_name}")
            return {
                "oid": oid,
                "type": type_char,
                "value": value,
                "success": False,
                "error": status_name,
            }

        self.logger.success(f"SET {oid} = {value} ({self._SET_TYPE_MAP[type_char]})")
        return {"oid": oid, "type": type_char, "value": value, "success": True, "error": None}

    async def _async_walk_write(self, engine, auth_data, transport, context, oid: str) -> Dict:
        """Walk a subtree, then test idempotent SET on each walked OID.

        For each entry: GET current value, SET same value back (idempotent).
        Returns summary with per-OID results.
        """
        from pysnmp.hlapi.asyncio import (
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
            set_cmd,
        )
        from pysnmp.proto import rfc1905

        from ....utils.export_utils import export_table

        # Walk the subtree
        self.logger.info(f"Walk-write: walking {oid}...")
        entries = await self._raw_walk(engine, auth_data, transport, context, oid)

        if not entries:
            self.logger.info(f"Walk-write: no entries under {oid}")
            return {
                "oid": oid,
                "total": 0,
                "writable_count": 0,
                "read_only_count": 0,
                "error_count": 0,
                "details": [],
            }

        total = len(entries)
        self.logger.info(f"Walk-write: testing SET on {total} OIDs...")
        details = []
        writable = 0
        read_only = 0
        errors = 0
        current = 0

        for entry in entries:
            current += 1
            entry_oid = entry["oid"]

            # GET current value (fresh engine/transport for each to avoid state issues)
            try:
                fresh_engine = SnmpEngine()
                fresh_transport = await UdpTransportTarget.create(
                    (self.host, self.port), timeout=self.timeout, retries=1
                )
                err_ind, err_st, _, var_binds = await get_cmd(
                    fresh_engine,
                    auth_data,
                    fresh_transport,
                    context,
                    ObjectType(ObjectIdentity(entry_oid)),
                )
            except Exception as e:
                self.logger.debug(f"Walk-write GET {entry_oid}: {e}")
                errors += 1
                self.logger.progress(current, total, writable, errors)
                continue

            if err_ind or err_st:
                errors += 1
                self.logger.progress(current, total, writable, errors)
                continue

            current_value = var_binds[0][1]

            # SET same value back (idempotent)
            try:
                set_engine = SnmpEngine()
                set_transport = await UdpTransportTarget.create(
                    (self.host, self.port), timeout=self.timeout, retries=1
                )
                # Reuse the exact ASN.1 object read back from the GET so the SET is
                # a true identity write. Re-wrapping as OctetString would coerce
                # INTEGER/Counter/Gauge/IpAddress scalars and silently corrupt them
                # on permissive agents.
                if isinstance(
                    current_value,
                    (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView),
                ):
                    errors += 1
                    self.logger.progress(current, total, writable, errors)
                    continue
                set_value = current_value
                err_ind, err_st, _, _ = await set_cmd(
                    set_engine,
                    auth_data,
                    set_transport,
                    context,
                    ObjectType(ObjectIdentity(entry_oid), set_value),
                )
            except Exception as e:
                self.logger.debug(f"Walk-write SET {entry_oid}: {e}")
                errors += 1
                self.logger.progress(current, total, writable, errors)
                continue

            if err_ind:
                errors += 1
                self.logger.progress(current, total, writable, errors)
                continue

            if err_st:
                status_val = int(err_st)
                ro_codes = {4, 6, 16, 17}
                if status_val in ro_codes:
                    read_only += 1
                else:
                    errors += 1
                self.logger.progress(current, total, writable, errors)
                continue

            # SET succeeded -- this OID is writable
            details.append({"oid": entry_oid, "writable": True, "error": None})
            writable += 1
            self.logger.progress(current, total, writable, errors)

        self.logger.progress(total, total, writable, errors, end="\n")
        self.logger.info(f"Walk-write {oid}: {writable}/{total} OIDs writable")
        self.logger.debug(
            f"Walk-write {oid} breakdown: {writable} writable, "
            f"{read_only} read-only, {errors} errors"
        )

        if writable > 0:
            self.logger.security_finding(
                "Writable OIDs found",
                f"Walk-write {oid}: {writable}/{total} OIDs are writable",
            )

        # Export table -- only writable OIDs (details already filtered)
        if details:
            host_sfx = self.host.replace(".", "_")
            headers = ["OID"]
            table_rows = [[d["oid"]] for d in details]
            export_table(
                f"snmp_walk_write_{host_sfx}",
                headers,
                table_rows,
                title=f"Walk-Write {oid} -- writable",
            )

        return {
            "oid": oid,
            "total": total,
            "writable_count": writable,
            "read_only_count": read_only,
            "error_count": errors,
            "details": details,
        }
