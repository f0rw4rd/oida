"""
SNMP Raw Query Mixin

Handles raw SNMP walk/get operations and MIB-aware OID resolution:
- MIB-aware OID creation (numeric and symbolic)
- OID name resolution with caching
- Raw walk operations (standard and bulk)
- Raw GET operations
- Async raw query orchestration
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class RawQueryMixin(_ScannerBase):
    """Mixin providing raw SNMP walk/get operations and MIB resolution."""

    def _make_oid(self, oid_str: str):
        """Create ObjectIdentity from numeric or symbolic OID string.

        Applies --mib-dir sources for symbolic lookups.
        """
        from pysnmp.hlapi.asyncio import ObjectIdentity

        # Numeric OID: starts with . or is all digits/dots
        if oid_str.startswith(".") or all(c in "0123456789." for c in oid_str):
            return ObjectIdentity(oid_str)

        # Symbolic: MIB::object or MIB::object.index
        if "::" in oid_str:
            mib, rest = oid_str.split("::", 1)
            # Parse trailing index: e.g. ifDescr.1
            parts = rest.split(".", 1)
            obj_name = parts[0]
            if len(parts) > 1:
                try:
                    index = int(parts[1])
                    oid = ObjectIdentity(mib, obj_name, index)
                except ValueError:
                    oid = ObjectIdentity(mib, obj_name)
            else:
                oid = ObjectIdentity(mib, obj_name)

            for src in self.mib_sources:
                oid = oid.add_asn1_mib_source(src)
            return oid

        # Bare name -- try as-is, with custom MIB sources
        oid = ObjectIdentity(oid_str)
        for src in self.mib_sources:
            oid = oid.add_asn1_mib_source(src)
        return oid

    def _get_mib_view(self, engine):
        """Get or create a cached MibViewController for OID resolution."""
        if not hasattr(self, "_mib_view"):
            from pysnmp.smi.view import MibViewController

            self._mib_view = MibViewController(engine.get_mib_builder())
            self._oid_name_cache = {}
        return self._mib_view

    def _resolve_oid_name(self, engine, oid_str: str) -> str:
        """Resolve numeric OID to friendly MIB name, or return empty string."""
        cache = getattr(self, "_oid_name_cache", None)
        if cache is not None and oid_str in cache:
            return cache[oid_str]
        try:
            from pysnmp.hlapi.asyncio import ObjectIdentity

            mib_view = self._get_mib_view(engine)
            oid = ObjectIdentity(oid_str)
            for src in self.mib_sources:
                oid = oid.add_asn1_mib_source(src)
            oid.resolve_with_mib(mib_view)
            name = oid.prettyPrint()
            # Skip if it just echoes back the numeric form
            if not name or name == oid_str or name.startswith("1.3."):
                name = ""
        except Exception as e:
            self.logger.debug(f"OID name resolution failed for {oid_str}: {e}")
            name = ""
        if cache is not None:
            cache[oid_str] = name
        return name

    # --- Raw Queries ---

    async def _async_raw_queries(self, engine, auth_data, transport, context) -> Dict:
        """Execute --walk and/or --get queries."""
        from ..constants import WALK_LISTS
        from ....utils.export_utils import export_table

        results: Dict[str, Any] = {}

        if self.walk_oid:
            # Resolve list: prefix to OID list, or use single OID
            if self.walk_oid.startswith("list:"):
                list_name = self.walk_oid[5:] or "all"
                oid_list = WALK_LISTS.get(list_name.lower())
                if not oid_list:
                    self.logger.fail(f"Unknown walk list '{list_name}' (use --walk-list)")
                    return results
                walk_label = f"list:{list_name}"
            else:
                oid_list = [self.walk_oid]
                walk_label = self.walk_oid

            self.logger.debug(f"Walking OID {walk_label} (bulk={self.use_bulk})")
            _walk_t0 = time.monotonic()
            walk_results = []
            for oid_prefix in oid_list:
                entries = await self._raw_walk(engine, auth_data, transport, context, oid_prefix)
                walk_results.extend(entries)

            _walk_ms = (time.monotonic() - _walk_t0) * 1000
            results["walk"] = {"oid": walk_label, "entries": walk_results}
            self.logger.debug(f"Walk {walk_label}: {len(walk_results)} entries in {_walk_ms:.0f}ms")
            self.logger.info(f"SNMP walk {walk_label}: {len(walk_results)} entries")
            for entry in walk_results:
                self.logger.debug(f"  {entry['oid']} = {entry['type']}: {entry['value']}")
            if walk_results:
                host_sfx = self.host.replace(".", "_")
                headers = ["OID", "Value"]
                table_rows = [[e.get("name") or e["oid"], e["value"]] for e in walk_results]
                export_table(
                    f"snmp_walk_{host_sfx}", headers, table_rows, title=f"Walk {walk_label}"
                )

        if self.get_oids:
            oid_list = [o.strip() for o in self.get_oids.split(",") if o.strip()]
            self.logger.debug(f"GET {len(oid_list)} OIDs")
            _get_t0 = time.monotonic()
            get_results = await self._raw_get(engine, auth_data, transport, context, oid_list)
            _get_ms = (time.monotonic() - _get_t0) * 1000
            results["get"] = get_results
            self.logger.debug(f"GET: {len(get_results)} results in {_get_ms:.0f}ms")
            self.logger.info(f"SNMP get: {len(get_results)} results")
            for entry in get_results:
                self.logger.debug(f"  {entry['oid']} = {entry['type']}: {entry['value']}")
            if get_results:
                host_sfx = self.host.replace(".", "_")
                headers = ["OID", "Type", "Value"]
                table_rows = [
                    [e.get("name") or e["oid"], e["type"], e["value"]] for e in get_results
                ]
                export_table(f"snmp_get_{host_sfx}", headers, table_rows, title="GET Results")

        return results

    async def _raw_walk(self, engine, auth_data, transport, context, oid_str: str) -> List[Dict]:
        """Walk an OID subtree, returning list of {oid, name, type, value}."""
        from pysnmp.hlapi.asyncio import ObjectType, bulk_walk_cmd, walk_cmd

        oid = self._make_oid(oid_str)
        entries = []
        max_entries = 10000

        if self.use_bulk and self.version in ("2c", "3"):
            walker = bulk_walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                0,
                25,  # nonRepeaters, maxRepetitions
                ObjectType(oid),
                lexicographicMode=False,
            )
        else:
            walker = walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(oid),
                lexicographicMode=False,
            )

        try:
            async for error_indication, error_status, _, var_binds in walker:
                if error_indication:
                    self.logger.debug(f"Walk error: {error_indication}")
                    break
                if error_status:
                    self.logger.debug(f"Walk status error: {error_status}")
                    break

                for var_bind in var_binds:
                    oid_val = str(var_bind[0])
                    entries.append(
                        {
                            "oid": oid_val,
                            "name": self._resolve_oid_name(engine, oid_val),
                            "type": var_bind[1].__class__.__name__,
                            "value": var_bind[1].prettyPrint(),
                        }
                    )

                if len(entries) >= max_entries:
                    self.logger.debug(
                        f"Walk truncated at {len(entries)} entries (max={max_entries})"
                    )
                    self.logger.warning(f"Walk truncated at {max_entries} entries")
                    break
        except Exception as e:
            self.logger.debug(f"Walk exception: {e}")

        return entries

    async def _raw_get(
        self, engine, auth_data, transport, context, oid_list: List[str]
    ) -> List[Dict]:
        """GET one or more OIDs, returning list of {oid, name, type, value}."""
        from pysnmp.hlapi.asyncio import ObjectType, get_cmd

        obj_types = [ObjectType(self._make_oid(o)) for o in oid_list]
        results: List[Dict[str, Any]] = []

        try:
            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                auth_data,
                transport,
                context,
                *obj_types,
            )
            if error_indication:
                self.logger.debug(f"GET error: {error_indication}")
                return results
            if error_status:
                self.logger.debug(f"GET status error: {error_status}")
                return results

            for var_bind in var_binds:
                oid_val = str(var_bind[0])
                results.append(
                    {
                        "oid": oid_val,
                        "name": self._resolve_oid_name(engine, oid_val),
                        "type": var_bind[1].__class__.__name__,
                        "value": var_bind[1].prettyPrint(),
                    }
                )
        except Exception as e:
            self.logger.debug(f"GET exception: {e}")

        return results
