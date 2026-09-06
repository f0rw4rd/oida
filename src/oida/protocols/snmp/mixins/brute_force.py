"""
SNMP Brute-Force Mixin

Handles community string brute-forcing and multi-community testing:
- Built-in ICS community string brute-force
- Lightweight multi-community testing
- Single community validation
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class BruteForceMixin(_ScannerBase):
    """Mixin providing SNMP community string brute-force operations."""

    def _brute_communities(self) -> List[str]:
        """Test built-in ICS community strings, return first valid."""
        from ....utils.login_scanner import load_passwords

        # Fail-closed: brute-force is an active operation. The orchestrator gates
        # this on --confirm, but enforce it here too so no other caller can
        # brute-force without confirmation.
        if not getattr(self, "confirm_brute", False):
            self.logger.fail("Community brute-force requires --confirm")
            return []

        communities = load_passwords(None, "snmp")

        self.logger.info(f"SNMP: testing {len(communities)} community strings against {self.host}")
        valid = []

        for community in communities:
            if self._test_community(community):
                self.logger.info(f"SNMP: valid community found: '{community}'")
                valid.append(community)
                break
            else:
                self.logger.debug(f"Community '{community}': rejected")
            if self.brute_rate > 0:
                time.sleep(self.brute_rate)

        if valid:
            self.logger.info(f"SNMP: {len(valid)} valid community string(s) found")
        return valid

    def _test_communities(self, candidates: List[str]) -> List[str]:
        """Lightweight test of a small list of community strings."""
        valid = []
        for community in candidates:
            if self._test_community(community):
                valid.append(community)
            if self.brute_rate > 0:
                time.sleep(self.brute_rate)
        return valid

    def _test_community(self, community: str) -> bool:
        """Test a single community string with sysDescr GET."""
        from pysnmp.hlapi.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )

        from ..constants import SNMP_OIDS

        async def _probe():
            engine = SnmpEngine()
            mp_model = 1 if self.version == "2c" else 0
            auth_data = CommunityData(community, mpModel=mp_model)
            transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=1
            )
            context = ContextData()

            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(SNMP_OIDS["sysDescr"])),
            )
            if error_indication or error_status:
                return False
            # Check we actually got a response value
            for var_bind in var_binds:
                val = var_bind[1].prettyPrint()
                if val and val != "No Such Object currently exists at this OID":
                    return True
            return False

        try:
            return asyncio.run(_probe())
        except Exception as e:
            self.logger.debug(f"Community test exception for '{community}': {e}")
            return False
