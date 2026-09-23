"""
SNMP Host Enumeration Mixin

Handles host enumeration operations via SNMP:
- Network table walks (ARP, CAM/MAC, interfaces, TCP, UDP, routes)
- Host resource queries (processes, software, storage)
- Windows-specific enumeration (users, shares, services)
- Credential hunting (OID trees, process arguments)
- IPv6 address discovery
- NET-SNMP extend script detection
- Vendor-specific OID queries
- Security analysis of enumeration results
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any, Dict, List


if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class HostEnumerationMixin(_ScannerBase):
    """Mixin providing SNMP host enumeration operations."""

    def _run_enumeration(self, connection) -> Dict:
        """Orchestrate host enumeration based on --enum categories."""
        from pysnmp.hlapi.asyncio import SnmpEngine, UdpTransportTarget

        from oida.protocols.snmp.constants import ENUM_CATEGORIES

        _, auth_data, _, context = connection

        results = {}
        category_handlers = {
            "interfaces": self._enum_interfaces,
            "tcp": self._enum_tcp_connections,
            "udp": self._enum_udp_listeners,
            "routes": self._enum_routes,
            "processes": self._enum_processes,
            "software": self._enum_software,
            "storage": self._enum_storage,
            "users": self._enum_users,
            "shares": self._enum_windows_shares,
            "traps": self._enum_trap_config,
            "creds": self._enum_credentials,
            "system": self._enum_system_details,
            "services": self._enum_windows_services,
            "filesystems": self._enum_filesystems,
            "ipv6": self._enum_ipv6,
            "extend": self._enum_extend,
            "arp": self._enum_arp,
            "cam": self._enum_cam,
        }

        for category in self.enum_categories:
            if category not in category_handlers:
                self.logger.warning(f"Unknown enum category: {category}")
                continue

            desc = ENUM_CATEGORIES.get(category, category)
            self.logger.info(f"Enumerating {desc}...")

            _enum_t0 = time.monotonic()
            try:
                # Fresh engine per category -- pysnmp engines are single-use
                async def _run_category(handler=category_handlers[category]):
                    engine = SnmpEngine()
                    transport = await UdpTransportTarget.create(
                        (self.host, self.port), timeout=self.timeout, retries=1
                    )
                    return await handler(engine, auth_data, transport, context)

                data = asyncio.run(_run_category())
                results[category] = data
                _enum_ms = (time.monotonic() - _enum_t0) * 1000
                _n_entries = len(data) if isinstance(data, (list, dict)) else 0
                self.logger.debug(f"Enumerated {desc}: {_n_entries} entries in {_enum_ms:.0f}ms")
            except Exception as e:
                self.logger.debug(f"Enum {category} failed: {e}")
                results[category] = {"error": str(e)}

        # Security analysis on enumeration results
        self._analyze_enum_security(results)

        return results

    async def _walk_table(
        self,
        engine,
        auth_data,
        transport,
        context,
        columns: Dict[str, str],
    ) -> Dict[str, Dict]:
        """Walk multi-column SNMP table, correlate rows by OID index suffix.

        Args:
            columns: {"col_name": "base_oid", ...}

        Returns:
            {index_suffix: {col_name: value, ...}, ...}
        """
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd
        from pysnmp.proto import rfc1905

        rows: Dict[str, Dict] = {}
        # enum_limit caps the number of distinct rows (index suffixes) for the
        # WHOLE table, not per column -- otherwise a wide table multiplies the cap
        # by the column count and the row dict grows unbounded across columns.
        limit = self.enum_limit if self.enum_limit > 0 else 2000
        sentinels = (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)

        for col_name, base_oid in columns.items():
            base_norm = base_oid.lstrip(".")
            scope = base_norm + "."
            try:
                async for error_indication, error_status, _, var_binds in walk_cmd(
                    engine,
                    auth_data,
                    transport,
                    context,
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False,
                ):
                    if error_indication or error_status:
                        break

                    for var_bind in var_binds:
                        oid_str = str(var_bind[0])
                        # Extract index suffix: everything strictly under the base
                        # OID. An OID outside base_norm + "." is a sibling subtree
                        # (e.g. ...1.2 vs ...1.20) -- skip it rather than invent a
                        # single-arc index that would merge unrelated rows.
                        if oid_str.startswith(scope):
                            suffix = oid_str[len(scope) :]
                        elif oid_str == base_norm:
                            suffix = "0"
                        else:
                            continue

                        val = var_bind[1]
                        if isinstance(val, sentinels):
                            continue  # sparse cell: no value at this index

                        if suffix not in rows:
                            if len(rows) >= limit:
                                # Table-wide row cap reached. Every OID from here
                                # on in this column's walk is necessarily a new
                                # suffix (already-known suffixes were captured
                                # before the cap filled), so there's nothing left
                                # to fill for this column -- break to stop network
                                # work instead of walking the rest of the table.
                                break
                            rows[suffix] = {}
                        rows[suffix][col_name] = val.prettyPrint()

                    if len(rows) >= limit:
                        break

            except Exception as e:
                self.logger.debug(f"Walk {col_name} ({base_oid}) error: {e}")

        return rows

    async def _get_arp_table(self, engine, auth_data, transport, context) -> List[Dict]:
        """Walk the ARP table (ipNetToMediaTable)."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        entries = []
        arp_oid = ".1.3.6.1.2.1.4.22.1.2"
        arp_oid_norm = arp_oid.lstrip(".")

        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(arp_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid = str(var_bind[0])
                    if not oid.startswith(arp_oid_norm):
                        continue

                    parts = oid.split(".")
                    if len(parts) >= 4:
                        ip = ".".join(parts[-4:])
                        mac_raw = var_bind[1]

                        if hasattr(mac_raw, "prettyPrint"):
                            mac_hex = mac_raw.prettyPrint()
                            if mac_hex.startswith("0x"):
                                mac_hex = mac_hex[2:]
                                mac = ":".join(
                                    mac_hex[i : i + 2] for i in range(0, len(mac_hex), 2)
                                )
                            else:
                                mac = mac_hex
                        else:
                            mac = str(mac_raw)

                        if ip and mac and mac != "00:00:00:00:00:00":
                            entries.append({"ip": ip, "mac": mac.lower()})

                if len(entries) >= 1000:
                    break

        except Exception as e:
            self.logger.debug(f"Error walking ARP table: {e}")

        self.logger.debug(f"SNMP ARP table: {len(entries)} entries")
        return entries

    async def _get_mac_table(self, engine, auth_data, transport, context) -> List[Dict]:
        """Walk the MAC/CAM table with port mappings.

        Walks both standard bridge MIB and 802.1Q VLAN-aware tables.
        """
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd, get_cmd

        entries: Dict[str, Dict[str, Any]] = {}
        mac_oid = ".1.3.6.1.2.1.17.4.3.1.1"
        port_oid = ".1.3.6.1.2.1.17.4.3.1.2"
        status_oid = ".1.3.6.1.2.1.17.4.3.1.3"
        mac_oid_norm = mac_oid.lstrip(".")
        status_map = {1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}

        try:
            # First pass: get all MACs
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(mac_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid = str(var_bind[0])
                    if not oid.startswith(mac_oid_norm):
                        continue

                    parts = oid.split(".")
                    if len(parts) >= 6:
                        mac_suffix = ".".join(parts[-6:])
                        mac = ":".join(f"{int(p):02x}" for p in parts[-6:])
                        if mac != "00:00:00:00:00:00":
                            entries[mac_suffix] = {"mac": mac.lower()}

                if len(entries) >= 5000:
                    break

            # Second pass: get port numbers
            for mac_suffix in list(entries.keys()):
                try:
                    port_full_oid = f"{port_oid}.{mac_suffix}"
                    error_indication, error_status, _, var_binds = await get_cmd(
                        engine,
                        auth_data,
                        transport,
                        context,
                        ObjectType(ObjectIdentity(port_full_oid)),
                    )
                    if not error_indication and not error_status and var_binds:
                        port_num = var_binds[0][1]
                        if hasattr(port_num, "prettyPrint"):
                            entries[mac_suffix]["port"] = int(port_num.prettyPrint())
                        else:
                            entries[mac_suffix]["port"] = int(port_num)
                except Exception as e:
                    self.logger.debug(f"SNMP: failed to get port for {mac_suffix}: {e}")

            # Third pass: get status
            for mac_suffix in list(entries.keys()):
                try:
                    status_full_oid = f"{status_oid}.{mac_suffix}"
                    error_indication, error_status, _, var_binds = await get_cmd(
                        engine,
                        auth_data,
                        transport,
                        context,
                        ObjectType(ObjectIdentity(status_full_oid)),
                    )
                    if not error_indication and not error_status and var_binds:
                        status_val = var_binds[0][1]
                        if hasattr(status_val, "prettyPrint"):
                            status_int = int(status_val.prettyPrint())
                        else:
                            status_int = int(status_val)
                        entries[mac_suffix]["status"] = status_map.get(
                            status_int, f"unknown({status_int})"
                        )
                except Exception as e:
                    self.logger.debug(f"SNMP: failed to get status for {mac_suffix}: {e}")

        except Exception as e:
            self.logger.debug(f"Error walking MAC/CAM table: {e}")

        # Fallback to 802.1Q VLAN-aware table
        if not entries:
            entries = await self._get_dot1q_fdb_table(engine, auth_data, transport, context)

        result = list(entries.values()) if isinstance(entries, dict) else entries
        self.logger.debug(f"SNMP CAM table: {len(result)} entries")
        return result

    async def _get_dot1q_fdb_table(self, engine, auth_data, transport, context) -> Dict:
        """Walk 802.1Q VLAN-aware forwarding database (dot1qTpFdbTable)."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        entries = {}
        fdb_port_oid = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
        fdb_oid_norm = fdb_port_oid.lstrip(".")

        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(fdb_port_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid = str(var_bind[0])
                    if not oid.startswith(fdb_oid_norm):
                        continue

                    parts = oid.split(".")
                    if len(parts) >= 7:
                        vlan = parts[-7]
                        mac_parts = parts[-6:]
                        mac = ":".join(f"{int(p):02x}" for p in mac_parts)
                        port = var_bind[1]

                        if hasattr(port, "prettyPrint"):
                            port_num = int(port.prettyPrint())
                        else:
                            port_num = int(port)

                        key = f"{vlan}.{'.'.join(mac_parts)}"
                        entries[key] = {
                            "mac": mac.lower(),
                            "vlan": int(vlan),
                            "port": port_num,
                        }

                if len(entries) >= 5000:
                    break

        except Exception as e:
            self.logger.debug(f"Error walking dot1qTpFdbTable: {e}")

        return entries

    async def _query_vendor_oids(
        self, vendor: str, engine, auth_data, transport, context
    ) -> Dict[str, str]:
        """Query vendor-specific OIDs for extra device information."""
        from oida.protocols.snmp.constants import VENDOR_SPECIFIC_OIDS
        from oida.protocols.snmp._oid_fetch import fetch_oid_values

        if vendor not in VENDOR_SPECIFIC_OIDS:
            return {}

        results = await fetch_oid_values(
            engine,
            auth_data,
            transport,
            context,
            VENDOR_SPECIFIC_OIDS[vendor],
            self.logger,
            "SNMP: vendor OID {name} query failed: {e}",
        )

        if results:
            self.logger.debug(f"SNMP vendor-specific ({vendor}): {results}")
        return results

    # --- Enum Category Handlers ---

    async def _enum_interfaces(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate network interfaces (ifTable)."""
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS, IF_OPER_STATUS
        from oida.utils.export_utils import export_table

        columns = {
            "descr": NETWORK_ENUM_OIDS["ifDescr"],
            "type": NETWORK_ENUM_OIDS["ifType"],
            "speed": NETWORK_ENUM_OIDS["ifSpeed"],
            "mac": NETWORK_ENUM_OIDS["ifPhysAddress"],
            "status": NETWORK_ENUM_OIDS["ifOperStatus"],
            "in_octets": NETWORK_ENUM_OIDS["ifInOctets"],
            "out_octets": NETWORK_ENUM_OIDS["ifOutOctets"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        interfaces = []
        up_count = 0
        for idx, data in sorted(rows.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
            status_int = int(data.get("status", "0")) if data.get("status", "").isdigit() else 0
            status = IF_OPER_STATUS.get(status_int, f"unknown({status_int})")
            is_up = status == "up"
            if is_up:
                up_count += 1

            speed_val = int(data.get("speed", "0")) if data.get("speed", "").isdigit() else 0
            if speed_val >= 1_000_000_000:
                speed_str = f"{speed_val // 1_000_000_000}Gbps"
            elif speed_val >= 1_000_000:
                speed_str = f"{speed_val // 1_000_000}Mbps"
            elif speed_val > 0:
                speed_str = f"{speed_val // 1000}Kbps"
            else:
                speed_str = ""

            mac_raw = data.get("mac", "")
            if mac_raw.startswith("0x"):
                mac_hex = mac_raw[2:]
                mac = ":".join(mac_hex[i : i + 2] for i in range(0, len(mac_hex), 2))
            else:
                mac = mac_raw

            iface = {
                "index": idx,
                "descr": data.get("descr", ""),
                "type": data.get("type", ""),
                "speed": speed_val,
                "speed_str": speed_str,
                "mac": mac.lower() if mac else "",
                "status": status,
                "in_octets": data.get("in_octets", "0"),
                "out_octets": data.get("out_octets", "0"),
            }
            interfaces.append(iface)

        # Walk ipAddrTable and correlate IPs to interfaces by ifIndex
        ip_columns = {
            "addr": NETWORK_ENUM_OIDS["ipAdEntAddr"],
            "ifindex": NETWORK_ENUM_OIDS["ipAdEntIfIndex"],
            "mask": NETWORK_ENUM_OIDS["ipAdEntNetMask"],
        }
        ip_rows = await self._walk_table(engine, auth_data, transport, context, ip_columns)

        ip_by_ifindex = {}
        discovered_targets = []
        for suffix, ip_data in ip_rows.items():
            ifidx = ip_data.get("ifindex", "")
            addr = ip_data.get("addr", suffix)
            mask = ip_data.get("mask", "")
            if ifidx:
                ip_by_ifindex.setdefault(ifidx, []).append(
                    {
                        "addr": addr,
                        "mask": mask,
                    }
                )
            # Collect non-loopback IPs as discovered targets
            if addr and not addr.startswith("127.") and addr != "0.0.0.0":  # nosec B104
                discovered_targets.append(addr)

        for iface in interfaces:
            iface["ip_addresses"] = ip_by_ifindex.get(iface["index"], [])

        if discovered_targets:
            self.logger.info(
                f"  IP addresses: {', '.join(discovered_targets[:10])}"
                + (f" (+{len(discovered_targets) - 10})" if len(discovered_targets) > 10 else "")
            )

        # Log summary
        speed_parts = []
        for i in interfaces:
            if i["status"] == "up" and i["speed_str"]:
                speed_parts.append(f"{i['descr'] or 'if' + i['index']} {i['speed_str']}")

        summary = f"{len(interfaces)} interfaces ({up_count} up)"
        if speed_parts:
            summary += ": " + ", ".join(speed_parts[:5])
            if len(speed_parts) > 5:
                summary += f", ... (+{len(speed_parts) - 5})"
        self.logger.info(f"  {summary}")

        if interfaces:
            host_sfx = self.host.replace(".", "_")
            headers = ["Index", "Name", "Status", "Speed", "Type", "MAC", "IPs"]
            table_rows = []
            for i in interfaces:
                ips = ", ".join(a["addr"] for a in i.get("ip_addresses", []))
                table_rows.append(
                    [
                        i["index"],
                        i["descr"],
                        i["status"],
                        i["speed_str"],
                        i.get("type", ""),
                        i["mac"],
                        ips,
                    ]
                )
            export_table(f"snmp_interfaces_{host_sfx}", headers, table_rows, title="Interfaces")

        return {
            "interfaces": interfaces,
            "count": len(interfaces),
            "up": up_count,
            "discovered_targets": discovered_targets,
        }

    async def _enum_tcp_connections(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate TCP connections (tcpConnTable)."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS, TCP_STATES
        from oida.utils.export_utils import export_table

        base_oid = NETWORK_ENUM_OIDS["tcpConnState"]
        base_norm = base_oid.lstrip(".")
        connections = []
        listeners = []
        limit = self.enum_limit if self.enum_limit > 0 else 2000

        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    state_val = (
                        int(var_bind[1].prettyPrint()) if var_bind[1].prettyPrint().isdigit() else 0
                    )
                    state = TCP_STATES.get(state_val, f"unknown({state_val})")

                    suffix = (
                        oid_str[len(base_norm) + 1 :] if oid_str.startswith(base_norm + ".") else ""
                    )
                    parts = suffix.split(".")
                    if len(parts) >= 10:
                        local_addr = ".".join(parts[0:4])
                        local_port = int(parts[4])
                        remote_addr = ".".join(parts[5:9])
                        remote_port = int(parts[9])

                        conn = {
                            "local_addr": local_addr,
                            "local_port": local_port,
                            "remote_addr": remote_addr,
                            "remote_port": remote_port,
                            "state": state,
                        }
                        connections.append(conn)

                        if state == "listen":
                            listeners.append(local_port)

                    if len(connections) >= limit:
                        break

                if len(connections) >= limit:
                    break

        except Exception as e:
            self.logger.debug(f"TCP enum error: {e}")

        # Log summary
        listen_ports = sorted(set(listeners))
        listen_str = " ".join(f":{p}" for p in listen_ports[:10])
        summary = f"{len(connections)} connections ({len(listen_ports)} listening)"
        if listen_str:
            summary += ": " + listen_str
            if len(listen_ports) > 10:
                summary += f" (+{len(listen_ports) - 10})"
        self.logger.info(f"  {summary}")

        if connections:
            host_sfx = self.host.replace(".", "_")
            headers = ["Local Addr", "Local Port", "Remote Addr", "Remote Port", "State"]
            table_rows = [
                [c["local_addr"], c["local_port"], c["remote_addr"], c["remote_port"], c["state"]]
                for c in connections
            ]
            export_table(f"snmp_tcp_{host_sfx}", headers, table_rows, title="TCP Connections")

        return {
            "connections": connections,
            "count": len(connections),
            "listeners": listen_ports,
        }

    async def _enum_udp_listeners(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate UDP listeners (udpTable)."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS
        from oida.utils.export_utils import export_table

        base_oid = NETWORK_ENUM_OIDS["udpLocalAddress"]
        base_norm = base_oid.lstrip(".")
        listeners: List[Dict[str, Any]] = []
        limit = self.enum_limit if self.enum_limit > 0 else 2000

        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    suffix = (
                        oid_str[len(base_norm) + 1 :] if oid_str.startswith(base_norm + ".") else ""
                    )
                    parts = suffix.split(".")
                    if len(parts) >= 5:
                        local_addr = ".".join(parts[0:4])
                        local_port = int(parts[4])
                        listeners.append(
                            {
                                "local_addr": local_addr,
                                "local_port": local_port,
                            }
                        )

                    if len(listeners) >= limit:
                        break

                if len(listeners) >= limit:
                    break

        except Exception as e:
            self.logger.debug(f"UDP enum error: {e}")

        ports = sorted(set(int(entry["local_port"]) for entry in listeners))
        port_str = " ".join(f":{p}" for p in ports[:10])
        summary = f"{len(listeners)} listeners"
        if port_str:
            summary += ": " + port_str
            if len(ports) > 10:
                summary += f" (+{len(ports) - 10})"
        self.logger.info(f"  {summary}")

        if listeners:
            host_sfx = self.host.replace(".", "_")
            headers = ["Local Addr", "Local Port"]
            table_rows = [[e["local_addr"], e["local_port"]] for e in listeners]
            export_table(f"snmp_udp_{host_sfx}", headers, table_rows, title="UDP Listeners")

        return {"listeners": listeners, "count": len(listeners), "ports": ports}

    async def _enum_routes(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate IP routing table (ipRouteTable)."""
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS, IP_ROUTE_TYPES
        from oida.utils.export_utils import export_table

        columns = {
            "dest": NETWORK_ENUM_OIDS["ipRouteDest"],
            "next_hop": NETWORK_ENUM_OIDS["ipRouteNextHop"],
            "mask": NETWORK_ENUM_OIDS["ipRouteMask"],
            "if_index": NETWORK_ENUM_OIDS["ipRouteIfIndex"],
            "type": NETWORK_ENUM_OIDS["ipRouteType"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        routes = []
        for _, data in rows.items():
            type_int = int(data.get("type", "0")) if data.get("type", "").isdigit() else 0
            routes.append(
                {
                    "dest": data.get("dest", ""),
                    "mask": data.get("mask", ""),
                    "next_hop": data.get("next_hop", ""),
                    "if_index": data.get("if_index", ""),
                    "type": IP_ROUTE_TYPES.get(type_int, f"unknown({type_int})"),
                }
            )

        summary = f"{len(routes)} routes"
        if routes:
            direct = sum(1 for r in routes if r["type"] == "direct")
            indirect = sum(1 for r in routes if r["type"] == "indirect")
            summary += f" ({direct} direct, {indirect} indirect)"
        self.logger.info(f"  {summary}")

        if routes:
            host_sfx = self.host.replace(".", "_")
            headers = ["Destination", "Mask", "Next Hop", "Interface", "Type"]
            table_rows = [
                [r["dest"], r["mask"], r["next_hop"], r["if_index"], r["type"]] for r in routes
            ]
            export_table(f"snmp_routes_{host_sfx}", headers, table_rows, title="IP Routes")

        return {"routes": routes, "count": len(routes)}

    async def _enum_arp(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate ARP table (ipNetToMediaTable) with full table display."""
        from oida.utils.export_utils import export_table

        entries = await self._get_arp_table(engine, auth_data, transport, context)
        self.logger.info(f"  {len(entries)} ARP entries")
        if entries:
            host_sfx = self.host.replace(".", "_")
            export_table(
                f"snmp_arp_{host_sfx}",
                ["IP Address", "MAC Address"],
                [[e["ip"], e["mac"]] for e in entries],
                title="ARP Table",
            )
        return {"entries": entries, "count": len(entries)}

    async def _enum_cam(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate CAM/MAC forwarding table with full table display."""
        from oida.utils.export_utils import export_table

        entries = await self._get_mac_table(engine, auth_data, transport, context)
        self.logger.info(f"  {len(entries)} CAM entries")
        if entries:
            host_sfx = self.host.replace(".", "_")
            export_table(
                f"snmp_cam_{host_sfx}",
                ["MAC Address", "Port", "VLAN", "Status"],
                [
                    [e["mac"], e.get("port", ""), e.get("vlan", ""), e.get("status", "")]
                    for e in entries
                ],
                title="CAM Table",
            )
        return {"entries": entries, "count": len(entries)}

    async def _enum_processes(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate running processes (hrSWRunTable)."""
        from oida.protocols.snmp.constants import (
            HOST_RESOURCE_OIDS,
            HR_SW_RUN_TYPE,
            HR_SW_RUN_STATUS,
        )
        from oida.utils.export_utils import export_table

        columns = {
            "name": HOST_RESOURCE_OIDS["hrSWRunName"],
            "path": HOST_RESOURCE_OIDS["hrSWRunPath"],
            "params": HOST_RESOURCE_OIDS["hrSWRunParameters"],
            "type": HOST_RESOURCE_OIDS["hrSWRunType"],
            "status": HOST_RESOURCE_OIDS["hrSWRunStatus"],
            "cpu": HOST_RESOURCE_OIDS["hrSWRunPerfCPU"],
            "mem": HOST_RESOURCE_OIDS["hrSWRunPerfMem"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        processes = []
        for idx, data in rows.items():
            type_int = int(data.get("type", "0")) if data.get("type", "").isdigit() else 0
            status_int = int(data.get("status", "0")) if data.get("status", "").isdigit() else 0
            cpu_str = data.get("cpu", "")
            mem_str = data.get("mem", "")
            processes.append(
                {
                    "pid": idx,
                    "name": data.get("name", ""),
                    "path": data.get("path", ""),
                    "params": data.get("params", ""),
                    "type": HR_SW_RUN_TYPE.get(type_int, f"unknown({type_int})"),
                    "status": HR_SW_RUN_STATUS.get(status_int, f"unknown({status_int})"),
                    "cpu_cs": int(cpu_str) if cpu_str.isdigit() else 0,
                    "mem_kb": int(mem_str) if mem_str.isdigit() else 0,
                }
            )

        names = sorted(set(p["name"] for p in processes if p["name"]))
        name_str = ", ".join(names[:8])
        summary = f"{len(processes)} processes"
        if name_str:
            summary += ": " + name_str
            if len(names) > 8:
                summary += f", ... (+{len(names) - 8})"
        self.logger.info(f"  {summary}")

        if processes:
            host_sfx = self.host.replace(".", "_")
            headers = ["PID", "Name", "Path", "Parameters", "Type", "Status"]
            table_rows = [
                [p["pid"], p["name"], p["path"], p["params"], p["type"], p["status"]]
                for p in processes
            ]
            export_table(f"snmp_processes_{host_sfx}", headers, table_rows, title="Processes")

        return {"processes": processes, "count": len(processes)}

    async def _enum_software(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate installed software (hrSWInstalledTable)."""
        from oida.protocols.snmp.constants import HOST_RESOURCE_OIDS, HR_SW_RUN_TYPE
        from oida.utils.export_utils import export_table

        columns = {
            "name": HOST_RESOURCE_OIDS["hrSWInstalledName"],
            "type": HOST_RESOURCE_OIDS["hrSWInstalledType"],
            "date": HOST_RESOURCE_OIDS["hrSWInstalledDate"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        software = []
        for idx, data in rows.items():
            type_int = int(data.get("type", "0")) if data.get("type", "").isdigit() else 0
            software.append(
                {
                    "index": idx,
                    "name": data.get("name", ""),
                    "type": HR_SW_RUN_TYPE.get(type_int, f"unknown({type_int})"),
                    "date": data.get("date", ""),
                }
            )

        names = [s["name"] for s in software if s["name"]]
        summary = f"{len(software)} packages"
        if names:
            summary += ": " + ", ".join(names[:5])
            if len(names) > 5:
                summary += f", ... (+{len(names) - 5})"
        self.logger.info(f"  {summary}")

        if software:
            host_sfx = self.host.replace(".", "_")
            headers = ["Name", "Type", "Date"]
            table_rows = [[s["name"], s["type"], s["date"]] for s in software]
            export_table(
                f"snmp_software_{host_sfx}", headers, table_rows, title="Installed Software"
            )

        return {"software": software, "count": len(software)}

    async def _enum_storage(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate storage (hrStorageTable)."""
        from oida.protocols.snmp.constants import HOST_RESOURCE_OIDS, HR_STORAGE_TYPES
        from oida.utils.export_utils import export_table

        columns = {
            "descr": HOST_RESOURCE_OIDS["hrStorageDescr"],
            "type": HOST_RESOURCE_OIDS["hrStorageType"],
            "units": HOST_RESOURCE_OIDS["hrStorageAllocationUnits"],
            "size": HOST_RESOURCE_OIDS["hrStorageSize"],
            "used": HOST_RESOURCE_OIDS["hrStorageUsed"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        storage = []
        for idx, data in rows.items():
            units = int(data.get("units", "0")) if data.get("units", "").isdigit() else 0
            size = int(data.get("size", "0")) if data.get("size", "").isdigit() else 0
            used = int(data.get("used", "0")) if data.get("used", "").isdigit() else 0

            total_bytes = size * units
            used_bytes = used * units
            pct = (used / size * 100) if size > 0 else 0

            # pysnmp prettyPrint yields the OID without a leading dot, but the
            # HR_STORAGE_TYPES keys have one — normalize so the lookup hits
            # (otherwise RAM/FixedDisk/etc. never decode and show the raw OID).
            type_oid = data.get("type", "")
            type_key = "." + type_oid.lstrip(".") if type_oid else type_oid
            type_name = HR_STORAGE_TYPES.get(type_key, type_oid)

            storage.append(
                {
                    "index": idx,
                    "descr": data.get("descr", ""),
                    "type": type_name,
                    "total_bytes": total_bytes,
                    "used_bytes": used_bytes,
                    "pct_used": round(pct, 1),
                }
            )

        parts = []
        for s in storage:
            if s["total_bytes"] > 0:
                total_gb = s["total_bytes"] / (1024**3)
                if total_gb >= 1:
                    parts.append(f"{s['descr']} {total_gb:.1f}GB ({s['pct_used']}%)")
                else:
                    total_mb = s["total_bytes"] / (1024**2)
                    parts.append(f"{s['descr']} {total_mb:.0f}MB ({s['pct_used']}%)")

        summary = f"{len(storage)} storage entries"
        if parts:
            summary += ": " + ", ".join(parts[:4])
            if len(parts) > 4:
                summary += f", ... (+{len(parts) - 4})"
        self.logger.info(f"  {summary}")

        if storage:
            host_sfx = self.host.replace(".", "_")
            headers = ["Description", "Type", "Total", "Used", "% Used"]
            table_rows = []
            for s in storage:
                total = s["total_bytes"]
                used = s["used_bytes"]
                if total >= 1024**3:
                    total_str = f"{total / 1024**3:.1f} GB"
                    used_str = f"{used / 1024**3:.1f} GB"
                elif total >= 1024**2:
                    total_str = f"{total / 1024**2:.0f} MB"
                    used_str = f"{used / 1024**2:.0f} MB"
                elif total > 0:
                    total_str = f"{total / 1024:.0f} KB"
                    used_str = f"{used / 1024:.0f} KB"
                else:
                    total_str = "0"
                    used_str = "0"
                table_rows.append([s["descr"], s["type"], total_str, used_str, f"{s['pct_used']}%"])
            export_table(f"snmp_storage_{host_sfx}", headers, table_rows, title="Storage")

        return {"storage": storage, "count": len(storage)}

    async def _enum_users(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate Windows user accounts (LanManager svUserTable)."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        from oida.protocols.snmp.constants import WINDOWS_OIDS
        from oida.utils.export_utils import export_table

        base_oid = WINDOWS_OIDS["svUserName"]
        users: List[str] = []
        limit = self.enum_limit if self.enum_limit > 0 else 2000

        try:
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    val = var_bind[1].prettyPrint()
                    if val and val != "No Such Object currently exists at this OID":
                        users.append(val)
                    if len(users) >= limit:
                        break
                if len(users) >= limit:
                    break
        except Exception as e:
            self.logger.debug(f"Windows users enum error: {e}")

        summary = f"{len(users)} users"
        if users:
            summary += ": " + ", ".join(users[:8])
            if len(users) > 8:
                summary += f", ... (+{len(users) - 8})"
        self.logger.info(f"  {summary}")

        if users:
            host_sfx = self.host.replace(".", "_")
            headers = ["Username"]
            table_rows = [[u] for u in users]
            export_table(f"snmp_users_{host_sfx}", headers, table_rows, title="Windows Users")

        return {"users": users, "count": len(users)}

    async def _enum_windows_shares(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate Windows shares (LanManager svShareTable)."""
        from oida.protocols.snmp.constants import WINDOWS_OIDS
        from oida.utils.export_utils import export_table

        columns = {
            "name": WINDOWS_OIDS["svShareName"],
            "path": WINDOWS_OIDS["svSharePath"],
            "comment": WINDOWS_OIDS["svShareComment"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        shares = []
        for _, data in rows.items():
            shares.append(
                {
                    "name": data.get("name", ""),
                    "path": data.get("path", ""),
                    "comment": data.get("comment", ""),
                }
            )

        names = [s["name"] for s in shares if s["name"]]
        summary = f"{len(shares)} shares"
        if names:
            summary += ": " + ", ".join(names[:8])
        self.logger.info(f"  {summary}")

        if shares:
            host_sfx = self.host.replace(".", "_")
            headers = ["Name", "Path", "Comment"]
            table_rows = [[s["name"], s["path"], s["comment"]] for s in shares]
            export_table(f"snmp_shares_{host_sfx}", headers, table_rows, title="Windows Shares")

        return {"shares": shares, "count": len(shares)}

    async def _enum_trap_config(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate trap destinations and community strings."""
        from oida.protocols.snmp.constants import TRAP_CONFIG_OIDS
        from oida.utils.export_utils import export_table

        columns = {
            "addr": TRAP_CONFIG_OIDS["snmpTargetAddrTAddress"],
            "params": TRAP_CONFIG_OIDS["snmpTargetAddrParams"],
            "security_name": TRAP_CONFIG_OIDS["snmpTargetParamsSecurityName"],
            "community": TRAP_CONFIG_OIDS["snmpCommunityName"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        trap_targets = []
        discovered_communities = set()
        for idx, data in rows.items():
            community = data.get("community", "")
            if community:
                discovered_communities.add(community)

            security_name = data.get("security_name", "")
            if security_name:
                discovered_communities.add(security_name)

            if data.get("addr") or community or security_name:
                trap_targets.append(
                    {
                        "index": idx,
                        "address": data.get("addr", ""),
                        "params": data.get("params", ""),
                        "security_name": security_name,
                        "community": community,
                    }
                )

        discovered = list(discovered_communities)
        summary = f"{len(trap_targets)} trap targets"
        if discovered:
            summary += f", {len(discovered)} community string(s): " + ", ".join(
                f"'{c}'" for c in discovered[:5]
            )
        self.logger.info(f"  {summary}")

        if trap_targets:
            host_sfx = self.host.replace(".", "_")
            headers = ["Address", "Params", "Security Name", "Community"]
            table_rows = [
                [t["address"], t["params"], t["security_name"], t["community"]]
                for t in trap_targets
            ]
            export_table(f"snmp_traps_{host_sfx}", headers, table_rows, title="Trap Targets")

        return {
            "targets": trap_targets,
            "count": len(trap_targets),
            "discovered_communities": discovered,
        }

    async def _enum_credentials(self, engine, auth_data, transport, context) -> Dict:
        """Walk credential-related OID trees for credential hunting."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        from oida.protocols.snmp.constants import (
            CREDENTIAL_OIDS,
            HOST_RESOURCE_OIDS,
            CRED_PATTERNS,
            CRED_PATTERNS_CONTEXT,
        )
        from oida.utils.export_utils import export_table

        findings = {}
        limit = self.enum_limit if self.enum_limit > 0 else 500

        for name, base_oid in CREDENTIAL_OIDS.items():
            results = []
            try:
                async for error_indication, error_status, _, var_binds in walk_cmd(
                    engine,
                    auth_data,
                    transport,
                    context,
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False,
                ):
                    if error_indication or error_status:
                        break

                    for var_bind in var_binds:
                        val = var_bind[1].prettyPrint()
                        if val and val != "No Such Object currently exists at this OID":
                            results.append(
                                {
                                    "oid": str(var_bind[0]),
                                    "value": val,
                                }
                            )

                    if len(results) >= limit:
                        break

            except Exception as e:
                self.logger.debug(f"Cred walk {name} error: {e}")

            if results:
                findings[name] = results

        # Correlate H3C user tables
        h3c_users = []
        for prefix, names in [
            ("h3c", ("h3cUserName", "h3cUserPassword", "h3cUserLevel")),
            ("hh3c", ("hh3cUserName", "hh3cUserPassword", "hh3cUserLevel")),
        ]:
            name_entries = {r["oid"].split(".")[-1]: r["value"] for r in findings.get(names[0], [])}
            pass_entries = {r["oid"].split(".")[-1]: r["value"] for r in findings.get(names[1], [])}
            level_entries = {
                r["oid"].split(".")[-1]: r["value"] for r in findings.get(names[2], [])
            }

            for idx in name_entries:
                username = name_entries.get(idx, "")
                password = pass_entries.get(idx, "")
                level = level_entries.get(idx, "")
                if username:
                    h3c_users.append(
                        {
                            "table": prefix,
                            "index": idx,
                            "username": username,
                            "password": password,
                            "level": level,
                        }
                    )
                    self.logger.security_finding(
                        "Credential disclosure",
                        category="INFO_DISCLOSURE",
                        detail=f"H3C credential found: {username} / {password or '(empty)'}",
                    )
                    self.logger.info(
                        f"    H3C credential: {username}"
                        f" / {password or '(empty)'}"
                        f" (level={level or '?'})"
                    )

        # Correlate Brocade ADX
        brocade_users = []
        brocade_name_entries = {
            r["oid"].split(".")[-1]: r["value"] for r in findings.get("brocadeAdxAdminUser", [])
        }
        brocade_pass_entries = {
            r["oid"].split(".")[-1]: r["value"] for r in findings.get("brocadeAdxAdminPassword", [])
        }
        for idx in brocade_name_entries:
            username = brocade_name_entries.get(idx, "")
            password = brocade_pass_entries.get(idx, "")
            if username:
                brocade_users.append({"index": idx, "username": username, "password": password})
                self.logger.security_finding(
                    "Credential disclosure",
                    category="INFO_DISCLOSURE",
                    detail=f"Brocade credential found: {username} / {password or '(hash)'}",
                )

        # Log and report findings
        total = sum(len(v) for v in findings.values())
        if total > 0:
            parts = []
            for name, results in findings.items():
                values = [r["value"] for r in results[:3]]
                parts.append(f"{name}: {', '.join(values)}")

            summary = f"{total} credential-related entries found"
            self.logger.info(f"  {summary}")
            for part in parts:
                self.logger.info(f"    {part}")

            # Report as security findings (skip correlated entries)
            h3c_names = {
                "h3cUserName",
                "h3cUserPassword",
                "h3cUserLevel",
                "hh3cUserName",
                "hh3cUserPassword",
                "hh3cUserLevel",
                "brocadeAdxAdminUser",
                "brocadeAdxAdminPassword",
            }
            for name, results in findings.items():
                if name in h3c_names:
                    continue
                is_password = "password" in name.lower()
                for result in results:
                    if is_password:
                        self.logger.security_finding(
                            "Credential disclosure",
                            category="INFO_DISCLOSURE",
                            detail=f"Credential OID '{name}': password='{result['value']}'",
                        )
                    elif "community" in name.lower() or "Community" in name:
                        self.logger.security_finding(
                            "Credential disclosure",
                            category="INFO_DISCLOSURE",
                            detail=f"Community string in OID '{name}': '{result['value']}'",
                        )
        else:
            self.logger.info("  No credential-related data found")

        # Process argument credential scanning
        process_creds = []
        compiled_generic = [re.compile(p, re.IGNORECASE) for p in CRED_PATTERNS]
        compiled_context = [
            (re.compile(name_pat, re.IGNORECASE), [re.compile(p, re.IGNORECASE) for p in pats])
            for name_pat, pats in CRED_PATTERNS_CONTEXT.items()
        ]
        proc_columns = {
            "name": HOST_RESOURCE_OIDS["hrSWRunName"],
            "params": HOST_RESOURCE_OIDS["hrSWRunParameters"],
        }
        try:
            proc_rows = await self._walk_table(engine, auth_data, transport, context, proc_columns)
            for idx, data in proc_rows.items():
                params = data.get("params", "")
                proc_name = data.get("name", "")
                if not params:
                    continue
                name_bare = re.sub(r"\.exe$", "", proc_name, flags=re.IGNORECASE)

                matched_fragment = None
                for pattern in compiled_generic:
                    match = pattern.search(params)
                    if match:
                        matched_fragment = match.group(0)
                        break

                if not matched_fragment:
                    for name_re, arg_patterns in compiled_context:
                        if name_re.search(name_bare):
                            for pattern in arg_patterns:
                                match = pattern.search(params)
                                if match:
                                    matched_fragment = match.group(0)
                                    break
                            if matched_fragment:
                                break

                if matched_fragment:
                    process_creds.append(
                        {
                            "pid": idx,
                            "process": proc_name,
                            "match": matched_fragment,
                            "params": params,
                        }
                    )
                    self.logger.security_finding(
                        "Credential disclosure",
                        category="INFO_DISCLOSURE",
                        detail=f"Credential in process args: '{proc_name}' (PID {idx})"
                        f" -- {matched_fragment}",
                    )
        except Exception as e:
            self.logger.debug(f"Process credential scan error: {e}")

        if process_creds:
            self.logger.warning(
                f"  {len(process_creds)} processes with credentials in command line"
            )
            total += len(process_creds)

        if findings or process_creds:
            host_sfx = self.host.replace(".", "_")
            headers = ["Category", "Value", "OID"]
            table_rows = []
            for name, results in findings.items():
                for r in results:
                    table_rows.append([name, r["value"], r["oid"]])
            for pc in process_creds:
                table_rows.append([f"process:{pc['process']}", pc["match"], f"PID {pc['pid']}"])
            export_table(
                f"snmp_credentials_{host_sfx}", headers, table_rows, title="Credential Findings"
            )

        return {
            "findings": findings,
            "total": total,
            "h3c_users": h3c_users,
            "brocade_users": brocade_users,
            "process_credentials": process_creds,
        }

    async def _enum_system_details(self, engine, auth_data, transport, context) -> Dict:
        """GET extended system scalars."""
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, get_cmd

        from oida.protocols.snmp.constants import SNMP_OIDS, WINDOWS_OIDS
        from oida.utils.export_utils import export_table

        scalar_oids = {
            "hrSystemDate": SNMP_OIDS["hrSystemDate"],
            "ipForwarding": SNMP_OIDS["ipForwarding"],
            "ipDefaultTTL": SNMP_OIDS["ipDefaultTTL"],
            "tcpInSegs": SNMP_OIDS["tcpInSegs"],
            "tcpOutSegs": SNMP_OIDS["tcpOutSegs"],
            "tcpRetransSegs": SNMP_OIDS["tcpRetransSegs"],
            "domPrimaryDomain": WINDOWS_OIDS["domPrimaryDomain"],
        }

        details = {}
        for name, oid in scalar_oids.items():
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
                    val = var_bind[1]
                    val_str = val.prettyPrint()
                    if val_str and val_str != "No Such Object currently exists at this OID":
                        if name == "hrSystemDate" and val_str.startswith("0x"):
                            raw = bytes.fromhex(val_str[2:])
                            if len(raw) >= 8:
                                year = int.from_bytes(raw[0:2], "big")
                                month, day = raw[2], raw[3]
                                hour, minute, sec = raw[4], raw[5], raw[6]
                                val_str = (
                                    f"{year}-{month:02d}-{day:02d} "
                                    f"{hour:02d}:{minute:02d}:{sec:02d}"
                                )
                        details[name] = val_str
            except Exception as e:
                self.logger.debug(f"System detail {name} failed: {e}")

        parts = []
        if "hrSystemDate" in details:
            parts.append(f"date={details['hrSystemDate']}")
        if "ipForwarding" in details:
            fwd = "yes" if details["ipForwarding"] == "1" else "no"
            parts.append(f"forwarding={fwd}")
        if "ipDefaultTTL" in details:
            parts.append(f"TTL={details['ipDefaultTTL']}")
        if "domPrimaryDomain" in details:
            parts.append(f"domain={details['domPrimaryDomain']}")

        tcp_stats = {}
        for k in ("tcpInSegs", "tcpOutSegs", "tcpRetransSegs"):
            if k in details:
                tcp_stats[k] = details[k]
        if tcp_stats:
            parts.append(
                f"TCP in/out/retrans={tcp_stats.get('tcpInSegs', '?')}"
                f"/{tcp_stats.get('tcpOutSegs', '?')}"
                f"/{tcp_stats.get('tcpRetransSegs', '?')}"
            )

        self.logger.info(f"  {', '.join(parts) if parts else 'no system details available'}")

        if details:
            host_sfx = self.host.replace(".", "_")
            headers = ["Name", "Value"]
            table_rows = [[k, v] for k, v in details.items()]
            export_table(f"snmp_system_{host_sfx}", headers, table_rows, title="System Details")

        if details.get("ipForwarding") == "1":
            self.logger.security_finding(
                "IP forwarding enabled",
                detail="Device is routing between networks -- potential pivot point",
            )

        return {"details": details}

    async def _enum_windows_services(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate Windows services (LanManager svSvcTable)."""
        from oida.protocols.snmp.constants import WINDOWS_SERVICE_OIDS
        from oida.utils.export_utils import export_table

        svc_installed_states = {
            1: "uninstalled",
            2: "installPending",
            3: "uninstallPending",
            4: "installed",
        }
        svc_operating_states = {
            1: "active",
            2: "continue_pending",
            3: "pause_pending",
            4: "paused",
        }

        columns = {
            "name": WINDOWS_SERVICE_OIDS["svSvcName"],
            "installed": WINDOWS_SERVICE_OIDS["svSvcInstalledState"],
            "operating": WINDOWS_SERVICE_OIDS["svSvcOperatingState"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        services = []
        for _, data in rows.items():
            installed_int = (
                int(data.get("installed", "0")) if data.get("installed", "").isdigit() else 0
            )
            operating_int = (
                int(data.get("operating", "0")) if data.get("operating", "").isdigit() else 0
            )
            services.append(
                {
                    "name": data.get("name", ""),
                    "installed_state": svc_installed_states.get(
                        installed_int, f"unknown({installed_int})"
                    ),
                    "operating_state": svc_operating_states.get(
                        operating_int, f"unknown({operating_int})"
                    ),
                }
            )

        active = [s for s in services if s["operating_state"] == "active"]
        names = [s["name"] for s in active if s["name"]]
        summary = f"{len(services)} services ({len(active)} active)"
        if names:
            summary += ": " + ", ".join(names[:8])
            if len(names) > 8:
                summary += f", ... (+{len(names) - 8})"
        self.logger.info(f"  {summary}")

        if services:
            host_sfx = self.host.replace(".", "_")
            headers = ["Name", "Installed", "Operating"]
            table_rows = [[s["name"], s["installed_state"], s["operating_state"]] for s in services]
            export_table(f"snmp_services_{host_sfx}", headers, table_rows, title="Windows Services")

        return {"services": services, "count": len(services), "active": len(active)}

    async def _enum_filesystems(self, engine, auth_data, transport, context) -> Dict:
        """Enumerate mounted filesystems (hrFSTable)."""
        from oida.protocols.snmp.constants import FILESYSTEM_OIDS
        from oida.utils.export_utils import export_table

        fs_access_map = {1: "readWrite", 2: "readOnly"}

        columns = {
            "mount": FILESYSTEM_OIDS["hrFSMountPoint"],
            "remote": FILESYSTEM_OIDS["hrFSRemoteMountPoint"],
            "type": FILESYSTEM_OIDS["hrFSType"],
            "access": FILESYSTEM_OIDS["hrFSAccess"],
        }

        rows = await self._walk_table(engine, auth_data, transport, context, columns)

        filesystems = []
        for idx, data in rows.items():
            access_int = int(data.get("access", "0")) if data.get("access", "").isdigit() else 0
            access_str = fs_access_map.get(access_int, f"unknown({access_int})")
            fs = {
                "index": idx,
                "mount_point": data.get("mount", ""),
                "remote_mount": data.get("remote", ""),
                "type": data.get("type", ""),
                "access": access_str,
            }
            filesystems.append(fs)

            if fs["remote_mount"] and access_str == "readWrite":
                self.logger.security_finding(
                    "Insecure configuration",
                    detail=f"Writable remote mount: '{fs['remote_mount']}' at '{fs['mount_point']}'",
                )

        mounts = [f["mount_point"] for f in filesystems if f["mount_point"]]
        summary = f"{len(filesystems)} filesystems"
        if mounts:
            summary += ": " + ", ".join(mounts[:6])
            if len(mounts) > 6:
                summary += f", ... (+{len(mounts) - 6})"
        self.logger.info(f"  {summary}")

        if filesystems:
            host_sfx = self.host.replace(".", "_")
            headers = ["Mount Point", "Remote", "Type", "Access"]
            table_rows = [
                [f["mount_point"], f["remote_mount"], f["type"], f["access"]] for f in filesystems
            ]
            export_table(f"snmp_filesystems_{host_sfx}", headers, table_rows, title="Filesystems")

        return {"filesystems": filesystems, "count": len(filesystems)}

    async def _enum_ipv6(self, engine, auth_data, transport, context) -> Dict:
        """Discover IPv6 addresses from ipAddressTable (RFC 4293)."""
        from ipaddress import IPv6Address
        from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walk_cmd

        from oida.protocols.snmp.constants import IPV6_ENUM_OIDS
        from oida.utils.export_utils import export_table

        base_oid = IPV6_ENUM_OIDS["ipAddressIfIndex"]
        base_norm = base_oid.lstrip(".")
        limit = self.enum_limit if self.enum_limit > 0 else 500
        addresses = []

        try:
            count = 0
            async for error_indication, error_status, _, var_binds in walk_cmd(
                engine,
                auth_data,
                transport,
                context,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break

                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    if_index = var_bind[1].prettyPrint()

                    if oid_str.startswith(base_norm + "."):
                        suffix = oid_str[len(base_norm) + 1 :]
                    else:
                        continue

                    parts = suffix.split(".")
                    if len(parts) < 2:
                        continue

                    addr_type = int(parts[0])
                    addr_len = int(parts[1])
                    addr_bytes = parts[2 : 2 + addr_len]

                    if addr_type == 2 and addr_len == 16 and len(addr_bytes) == 16:
                        raw = bytes(int(b) for b in addr_bytes)
                        addr = IPv6Address(raw)
                        if addr.is_loopback:
                            scope = "loopback"
                        elif addr.is_link_local:
                            scope = "link-local"
                        elif addr.is_multicast:
                            scope = "multicast"
                        elif addr.is_global:
                            scope = "global"
                        else:
                            scope = "other"
                        addresses.append(
                            {"address": str(addr), "scope": scope, "if_index": if_index}
                        )
                        level = "warning" if scope == "global" else "info"
                        getattr(self.logger, level)(
                            f"  IPv6 [{scope}]: {addr} (ifIndex={if_index})"
                        )

                    count += 1
                    if count >= limit:
                        break
                if count >= limit:
                    break

        except Exception as e:
            self.logger.debug(f"IPv6 enumeration error: {e}")

        global_addrs = [a for a in addresses if a["scope"] == "global"]
        self.logger.info(f"  {len(addresses)} IPv6 addresses ({len(global_addrs)} global unicast)")

        if addresses:
            host_sfx = self.host.replace(".", "_")
            headers = ["Address", "Scope", "Interface Index"]
            table_rows = [[a["address"], a["scope"], a["if_index"]] for a in addresses]
            export_table(f"snmp_ipv6_{host_sfx}", headers, table_rows, title="IPv6 Addresses")

        return {"addresses": addresses, "count": len(addresses), "global": len(global_addrs)}

    async def _enum_extend(self, engine, auth_data, transport, context) -> Dict:
        """Detect NET-SNMP extend scripts (nsExtendObjects)."""
        from oida.protocols.snmp.constants import NETSNMP_EXTEND_OIDS
        from oida.utils.export_utils import export_table

        config_columns = {
            "command": NETSNMP_EXTEND_OIDS["nsExtendCommand"],
            "args": NETSNMP_EXTEND_OIDS["nsExtendArgs"],
            "exec_type": NETSNMP_EXTEND_OIDS["nsExtendExecType"],
            "storage": NETSNMP_EXTEND_OIDS["nsExtendStorage"],
            "status": NETSNMP_EXTEND_OIDS["nsExtendStatus"],
        }
        rows = await self._walk_table(engine, auth_data, transport, context, config_columns)

        output_columns = {
            "output": NETSNMP_EXTEND_OIDS["nsExtendOutput1Line"],
            "result": NETSNMP_EXTEND_OIDS["nsExtendResult"],
        }
        output_rows = await self._walk_table(engine, auth_data, transport, context, output_columns)

        for suffix, odata in output_rows.items():
            if suffix in rows:
                rows[suffix].update(odata)
            else:
                rows[suffix] = odata

        storage_map = {"2": "volatile (INJECTED)", "4": "permanent (config)"}
        exec_type_map = {"1": "exec", "2": "shell"}

        extends = []
        for suffix, data in rows.items():
            cmd = data.get("command", "")
            args = data.get("args", "")
            storage_raw = data.get("storage", "")
            storage_label = storage_map.get(storage_raw, f"type={storage_raw}")
            exec_raw = data.get("exec_type", "")
            exec_label = exec_type_map.get(exec_raw, f"type={exec_raw}")
            output = data.get("output", "")

            name = ""
            sparts = suffix.split(".")
            if sparts and sparts[0].isdigit():
                name_len = int(sparts[0])
                name_chars = sparts[1 : 1 + name_len]
                try:
                    name = "".join(chr(int(c)) for c in name_chars)
                except (ValueError, OverflowError):
                    name = suffix

            entry = {
                "name": name,
                "command": cmd,
                "args": args,
                "exec_type": exec_label,
                "storage": storage_label,
                "output": output,
            }
            extends.append(entry)

            if storage_raw == "2":
                self.logger.security_finding(
                    "RCE risk",
                    detail=f"Injected extend script '{name}': {cmd} {args}",
                )
            elif cmd:
                self.logger.info(f"  Extend script '{name}': {cmd} {args}")

        if extends:
            host_sfx = self.host.replace(".", "_")
            headers = ["Name", "Command", "Args", "ExecType", "Storage", "Output"]
            table_rows = [
                [e["name"], e["command"], e["args"], e["exec_type"], e["storage"], e["output"]]
                for e in extends
            ]
            export_table(
                f"snmp_extend_{host_sfx}", headers, table_rows, title="NET-SNMP Extend Scripts"
            )
        else:
            self.logger.info("  No NET-SNMP extend scripts found")

        return {"extends": extends, "count": len(extends)}

    def _analyze_enum_security(self, enum_results: Dict) -> None:
        """Analyze enumeration results for ICS-relevant security findings."""
        from oida.protocols.snmp.constants import ICS_PORTS

        tcp_data = enum_results.get("tcp", {})
        if isinstance(tcp_data, dict):
            for port in tcp_data.get("listeners", []):
                if port in ICS_PORTS:
                    proto_name = ICS_PORTS[port]
                    self.logger.security_finding(
                        "Insecure configuration",
                        detail=f"ICS service exposed: {proto_name} on TCP :{port}",
                    )

        users_data = enum_results.get("users", {})
        if isinstance(users_data, dict):
            risky_users = {"Guest", "guest", "DefaultAccount", "Administrator"}
            for user in users_data.get("users", []):
                if user in risky_users:
                    self.logger.security_finding(
                        "Insecure configuration",
                        detail=f"Default Windows account enabled: {user}",
                    )

        shares_data = enum_results.get("shares", {})
        if isinstance(shares_data, dict):
            admin_shares = {"C$", "ADMIN$", "IPC$", "D$", "E$"}
            for share in shares_data.get("shares", []):
                name = share.get("name", "")
                if name in admin_shares:
                    self.logger.security_finding(
                        "Insecure configuration",
                        detail=f"Administrative share exposed: {name} ({share.get('path', '')})",
                    )

        trap_data = enum_results.get("traps", {})
        if isinstance(trap_data, dict):
            for community in trap_data.get("discovered_communities", []):
                if community and community not in ("public", self.community):
                    self.logger.security_finding(
                        "Insecure configuration",
                        detail=f"Additional community string in trap config: '{community}'",
                    )

        extend_data = enum_results.get("extend", {})
        if isinstance(extend_data, dict) and extend_data.get("count", 0) > 0:
            self.logger.security_finding(
                "RCE risk",
                detail=f"{extend_data['count']} NET-SNMP extend scripts configured -- "
                "RCE possible if community string has write access",
            )

        ipv6_data = enum_results.get("ipv6", {})
        if isinstance(ipv6_data, dict) and ipv6_data.get("global", 0) > 0:
            self.logger.security_finding(
                "Hidden attack surface",
                detail=f"{ipv6_data['global']} global IPv6 addresses found -- "
                "services may be reachable on IPv6 only",
            )

        creds_data = enum_results.get("creds", {})
        if isinstance(creds_data, dict):
            proc_creds = creds_data.get("process_credentials", [])
            if proc_creds:
                self.logger.security_finding(
                    "Credential exposure",
                    detail=f"{len(proc_creds)} processes leaking credentials in command-line arguments",
                )
