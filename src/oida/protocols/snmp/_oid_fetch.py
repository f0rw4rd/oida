"""
Shared SNMP GET helper.

Both the discovery path (``scanner._async_discover``) and the host-enumeration
path (``mixins.host_enumeration._query_vendor_oids``) need to resolve a small
map of ``name -> oid`` via individual SNMP GETs, skipping OIDs that don't
resolve. This is the shared implementation.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping


async def fetch_oid_values(
    engine: Any,
    auth_data: Any,
    transport: Any,
    context: Any,
    oid_map: Mapping[str, str],
    logger: Any,
    error_template: str,
) -> Dict[str, str]:
    """Resolve each ``name: oid`` pair in ``oid_map`` via an individual SNMP GET.

    Returns a ``name -> value`` dict, silently skipping OIDs that error out or
    don't exist on the target. ``error_template`` is a ``str.format`` template
    with ``{name}`` and ``{e}`` placeholders, used for the per-OID debug log on
    exception (callers use different wording for discovery vs. vendor OIDs).
    """
    from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, get_cmd

    results: Dict[str, str] = {}
    for name, oid in oid_map.items():
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
                    results[name] = value
        except Exception as e:
            logger.debug(error_template.format(name=name, e=e))

    return results
