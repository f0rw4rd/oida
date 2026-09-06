"""
SNMP Version Detection Mixin

Handles SNMP version auto-detection:
- Parallel v1/v2c/v3 probing
- SNMPv3 engine ID decoding (RFC 3411)
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from typing import TYPE_CHECKING, Any, Dict

from oida.utils.common_types import Category

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class VersionDetectionMixin(_ScannerBase):
    """Mixin providing SNMP version auto-detection."""

    def _detect_versions(self) -> Dict[str, Any]:
        """Probe target for supported SNMP versions (v1, v2c, v3).

        Sends parallel sysDescr GETs with v1 and v2c community data,
        plus a v3 noAuthNoPriv probe to detect engine support.
        Returns dict with 'supported_versions' list and best version to use.
        """
        from pysnmp.hlapi.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            get_cmd,
            usmHMACSHAAuthProtocol,
        )

        from ..constants import SNMP_OIDS

        # Mutable container for v3 observer to capture engine ID
        v3_engine_data: Dict[str, Any] = {}

        def _v3_observer(engine, execpoint, ctx, cbCtx=None):
            eid = ctx.get("securityEngineId")
            if eid and len(eid) > 0:
                v3_engine_data["engine_id"] = bytes(eid)
                v3_engine_data["engine_boots"] = ctx.get("snmpEngineBoots", 0)

        async def _probe_version(mp_model=None, v3=False):
            """Probe a single SNMP version. Returns (version_str, supported, detail)."""
            engine = SnmpEngine()
            transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=0
            )
            context = ContextData()

            if v3:
                # Register observer to capture peer engine ID from USM response
                engine.observer.register_observer(_v3_observer, "rfc3414.processIncomingMsg")
                # Use a dummy non-empty username with auth credentials;
                # pysnmp v7+ rejects empty usernames (min length 1-32).
                # A real v3 engine will reply with UnknownUserName, confirming support.
                auth_data = UsmUserData(
                    "__oida_probe__",
                    authKey="00000000",
                    authProtocol=usmHMACSHAAuthProtocol,
                )
                version_str = "3"
            else:
                auth_data = CommunityData(self.community, mpModel=mp_model)
                version_str = "2c" if mp_model == 1 else "1"

            try:
                error_indication, error_status, _, var_binds = await get_cmd(
                    engine,
                    auth_data,
                    transport,
                    context,
                    ObjectType(ObjectIdentity(SNMP_OIDS["sysDescr"])),
                )
            except Exception as e:
                self.logger.debug(f"Version probe v{version_str} exception: {e}")
                return (version_str, False, None)

            if v3:
                # For v3: even error responses from v3-capable devices indicate support
                if error_indication is None:
                    return ("3", True, "noAuthNoPriv accepted")
                err_str = str(error_indication)
                err_cls = type(error_indication).__name__
                # An error from the USM engine means v3 IS supported (creds just
                # wrong). Match the exception CLASS for the ambiguous tokens
                # (WrongDigest/authenticationFailure could otherwise substring-match
                # an unrelated message); keep a few specific phrases for the
                # message-only variants.
                v3_supported_classes = {
                    "UnknownUserName",
                    "UnsupportedSecurityLevel",
                    "WrongDigest",
                    "AuthenticationFailure",
                }
                v3_supported_phrases = (
                    "Unknown USM user",
                    "unknownSecurityName",
                    "unsupportedSecurityLevel",
                )
                if err_cls in v3_supported_classes or any(
                    phrase in err_str for phrase in v3_supported_phrases
                ):
                    return ("3", True, f"v3 engine detected ({err_cls})")
                # Timeout or other transport error means v3 not supported
                return ("3", False, None)

            # v1/v2c: success means supported
            if error_indication:
                return (version_str, False, None)
            if error_status:
                return (version_str, False, None)
            # Check we got a real value
            for var_bind in var_binds:
                val = var_bind[1].prettyPrint()
                if val and val != "No Such Object currently exists at this OID":
                    return (version_str, True, val[:100])
            return (version_str, False, None)

        async def _detect_all():
            return await asyncio.gather(
                _probe_version(mp_model=0),  # v1
                _probe_version(mp_model=1),  # v2c
                _probe_version(v3=True),  # v3
                return_exceptions=True,
            )

        self.logger.debug("Version detection: probing v1/v2c/v3 in parallel")
        _vdet_t0 = time.monotonic()
        try:
            results = asyncio.run(_detect_all())
        except Exception as e:
            self.logger.debug(f"Version detection error: {e}")
            return {"supported_versions": [], "best_version": self.version}

        supported = []
        for r in results:
            if isinstance(r, Exception):
                continue
            version_str, is_supported, detail = r
            if is_supported:
                supported.append(version_str)
                self.logger.debug(f"SNMPv{version_str}: supported ({detail})")
            else:
                self.logger.debug(f"SNMPv{version_str}: not supported")

        _vdet_ms = (time.monotonic() - _vdet_t0) * 1000
        self.logger.debug(f"Version detection completed in {_vdet_ms:.0f}ms")

        # Security finding for v1
        if "1" in supported:
            self.logger.security_finding(
                "Legacy protocol",
                category=Category.PROTOCOL_EXPOSURE,
                detail="SNMPv1 supported (no message integrity)",
            )

        # Best version selection: prefer v2c (GETBULK) > v3 > v1
        if "2c" in supported:
            best = "2c"
        elif "3" in supported:
            best = "3"
        elif "1" in supported:
            best = "1"
        else:
            best = self.version

        result: Dict[str, Any] = {
            "supported_versions": sorted(supported),
            "best_version": best,
        }

        # Decode SNMPv3 engine ID if captured from the v3 probe
        if v3_engine_data.get("engine_id"):
            engine_info = self._decode_engine_id(v3_engine_data["engine_id"])
            engine_info["engine_boots"] = v3_engine_data.get("engine_boots", 0)

            parts = [f"engineID: {engine_info['hex']}"]
            if engine_info.get("enterprise_name"):
                parts.append(engine_info["enterprise_name"])
            if engine_info.get("decoded"):
                parts.append(engine_info["decoded"])
            if engine_info["engine_boots"]:
                parts.append(f"boots={engine_info['engine_boots']}")
            self.logger.display(f"SNMPv3 {' | '.join(parts)}")

        return result

    @staticmethod
    def _decode_engine_id(raw: bytes) -> Dict[str, Any]:
        """Decode SNMPv3 engine ID per RFC 3411 section 5.

        Format:
          Bytes 0-3: enterprise number (big-endian), high bit set
          Byte 4: format indicator (1=IPv4, 2=IPv6, 3=MAC, 4=text, 5=octets)
          Bytes 5+: format-specific data
        """
        from ..constants import VENDOR_OIDS

        info: Dict[str, Any] = {"raw": raw, "hex": raw.hex()}

        if len(raw) < 5:
            info["decoded"] = raw.hex()
            return info

        # Enterprise number -- high bit is always set per RFC 3411
        enterprise = struct.unpack("!I", raw[:4])[0] & 0x7FFFFFFF
        fmt = raw[4]
        payload = raw[5:]

        info["enterprise"] = enterprise
        info["format"] = fmt

        # Map enterprise PEN to vendor name (reuse VENDOR_OIDS if available)
        pen_str = str(enterprise)
        info["enterprise_name"] = VENDOR_OIDS.get(pen_str, f"PEN {enterprise}")

        if fmt == 1 and len(payload) >= 4:
            # IPv4 address
            info["decoded"] = socket.inet_ntoa(payload[:4])
            info["format_name"] = "IPv4"
        elif fmt == 2 and len(payload) >= 16:
            # IPv6 address
            info["decoded"] = socket.inet_ntop(socket.AF_INET6, payload[:16])
            info["format_name"] = "IPv6"
        elif fmt == 3 and len(payload) >= 6:
            # MAC address
            info["decoded"] = ":".join(f"{b:02x}" for b in payload[:6])
            info["format_name"] = "MAC"
        elif fmt == 4:
            # Text
            info["decoded"] = payload.decode("utf-8", errors="replace")
            info["format_name"] = "text"
        elif fmt == 5:
            # Octets
            info["decoded"] = payload.hex()
            info["format_name"] = "octets"
        else:
            # Enterprise-specific or unknown
            info["decoded"] = payload.hex()
            info["format_name"] = f"enterprise-specific({fmt})"

        return info
