"""EEPROM operations mixin for EtherCATScanner."""

from __future__ import annotations

import struct
from typing import Any, Dict, List, TYPE_CHECKING
from binascii import hexlify

from oida.utils import ProgressTracker
from oida.utils.export_utils import print_table
from oida.protocols.ethercat.constants import ESI_CATEGORY_TYPES
from oida.protocols.ethercat.eeprom import (
    calculate_sii_crc,
    parse_sii_header,
    parse_strings_category,
    parse_general_category,
    parse_syncmanager_category,
    parse_fmmu_category,
    parse_pdo_category,
    parse_dc_category,
)

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EepromOpsMixin(_ScannerBase):
    """Mixin providing EEPROM read/write/parse operations."""

    def _read_eeprom_data(self, master: Any) -> Dict[int, Any]:
        """Read EEPROM data from slaves"""
        self.logger.display("Reading EEPROM data...")
        eeprom_data = {}

        progress = ProgressTracker(len(master.slaves), logger=self.logger)

        targets = self._slave_filter()

        for i in range(len(master.slaves)):
            position = i + 1
            if position not in targets:
                progress.update()
                continue

            progress.update(msg=f"Reading EEPROM from slave {position}")

            try:
                # Parse the SII/ESI structure once, then derive every category
                # from the parsed result. pysoem's CdefSlave only exposes
                # man/id/rev/name/input/output — everything else (serial,
                # FMMU/SM counts, strings, PDO sizes) must come from the SII.
                sii = self._read_slave_sii(master, i)
                eeprom_data[i + 1] = {
                    "general": self._read_eeprom_general(master, i, sii),
                    "fmmu": self._read_eeprom_fmmu(sii),
                    "sync_manager": self._read_eeprom_sync_manager(sii),
                    "pdo": self._read_eeprom_pdo(master, i, sii),
                    "strings": self._read_eeprom_strings(master, i, sii),
                }

            except Exception as e:
                self.logger.debug(f"Error reading EEPROM from slave {i + 1}: {e}")
                eeprom_data[i + 1] = {"error": str(e)}

        return eeprom_data

    def _read_slave_sii(self, master: Any, slave_pos: int) -> Dict[str, Any]:
        """Read and parse the SII/ESI structure for one slave.

        Returns a dict with header + parsed categories (strings/general/fmmu/
        sync_managers/txpdo/rxpdo/dc). On read failure returns {}.
        """
        slave = master.slaves[slave_pos]
        raw = bytearray()
        try:
            for word_addr in range(0, 1024):
                try:
                    data = slave.eeprom_read(word_addr)
                    raw.extend(data[:2])
                except Exception:
                    break
        except Exception as e:
            self.logger.debug(f"SII read failed for slave {slave_pos + 1}: {e}")
            return {}

        if len(raw) < 128:
            return {}

        parsed: Dict[str, Any] = {
            "header": parse_sii_header(raw),
            "strings": [],
            "general": {},
            "fmmu": [],
            "sync_managers": [],
            "txpdo": [],
            "rxpdo": [],
        }

        strings = [""]  # 1-indexed
        offset = 0x80
        while offset + 4 <= len(raw):
            cat_type = struct.unpack_from("<H", raw, offset)[0]
            cat_size_bytes = struct.unpack_from("<H", raw, offset + 2)[0] * 2
            if cat_type in (0xFFFF, 0x7FFF, 0x0000):
                break
            cat_data = raw[offset + 4 : offset + 4 + cat_size_bytes]

            if cat_type == 10:  # STRINGS
                strings = parse_strings_category(cat_data)
                parsed["strings"] = strings[1:]
            elif cat_type == 30:  # GENERAL
                parsed["general"] = parse_general_category(cat_data, strings)
            elif cat_type == 40:  # FMMU
                parsed["fmmu"] = parse_fmmu_category(cat_data)
            elif cat_type == 41:  # SyncManager
                parsed["sync_managers"] = parse_syncmanager_category(cat_data)
            elif cat_type == 50:  # TxPDO
                parsed["txpdo"] = parse_pdo_category(cat_data, strings)
            elif cat_type == 51:  # RxPDO
                parsed["rxpdo"] = parse_pdo_category(cat_data, strings)

            offset += 4 + cat_size_bytes

        return parsed

    def _read_eeprom_general(
        self, master: Any, slave_pos: int, sii: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Read general EEPROM information (identity from pysoem, rest from SII)."""
        try:
            slave = master.slaves[slave_pos]
            header = sii.get("header", {})
            return {
                "vendor_id": slave.man,
                "product_code": slave.id,
                "revision_number": slave.rev,
                "serial_number": header.get("serial_number"),
                "fmmu_count": len(sii.get("fmmu", [])),
                "sync_manager_count": len(sii.get("sync_managers", [])),
            }
        except Exception as e:
            return {"error": str(e)}

    def _read_eeprom_fmmu(self, sii: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return FMMU configuration parsed from the SII FMMU category."""
        return sii.get("fmmu", [])

    def _read_eeprom_sync_manager(self, sii: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return SyncManager configuration parsed from the SII SM category."""
        return sii.get("sync_managers", [])

    def _read_eeprom_pdo(self, master: Any, slave_pos: int, sii: Dict[str, Any]) -> Dict[str, Any]:
        """Read PDO configuration (counts from SII, byte sizes from pysoem)."""
        try:
            slave = master.slaves[slave_pos]
            input_bytes = len(slave.input) if slave.input else 0
            output_bytes = len(slave.output) if slave.output else 0
            return {
                "rx_pdo_count": len(sii.get("rxpdo", [])),
                "tx_pdo_count": len(sii.get("txpdo", [])),
                "input_size": input_bytes,
                "output_size": output_bytes,
                "input_bits": input_bytes * 8,
                "output_bits": output_bytes * 8,
            }
        except Exception as e:
            return {"error": str(e)}

    def _read_eeprom_strings(
        self, master: Any, slave_pos: int, sii: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Read string data (device name from pysoem, group/order from SII)."""
        try:
            slave = master.slaves[slave_pos]
            general = sii.get("general", {})
            # pysoem may return slave.name as bytes or str depending on version
            # (see _discover_slaves); only decode when it is bytes, else an
            # AttributeError discards the whole strings block.
            name = slave.name
            if isinstance(name, bytes):
                device_name = name.decode("utf-8", errors="ignore")
            else:
                device_name = name or ""
            return {
                "device_name": device_name,
                "group_type": general.get("group", ""),
                "image_name": general.get("image", ""),
                "order": general.get("order", ""),
            }
        except Exception as e:
            return {"error": str(e)}

    def _dump_full_eeprom(self, master: Any) -> Dict[int, Any]:
        """Dump full EEPROM contents from all slaves (pysoem eeprom_read)"""
        self.logger.display("Dumping full EEPROM contents...")
        eeprom_raw = {}
        targets = self._slave_filter()

        for i in range(len(master.slaves)):
            position = i + 1
            if position not in targets:
                continue

            slave = master.slaves[i]
            self.logger.display(f"Reading EEPROM from slave {position}...")

            try:
                eeprom_data = []
                failed_addrs = []
                # Read EEPROM word addresses 0x00 to 0x7F (128 words).
                # Best-effort: a single flaky read shouldn't truncate the dump,
                # so continue past failures and record the failed addresses.
                for addr in range(0x00, 0x80):
                    try:
                        data = slave.eeprom_read(addr)
                        if data:
                            eeprom_data.append(
                                {"address": f"0x{addr:04X}", "data": hexlify(data).decode()}
                            )
                    except Exception as e:
                        self.logger.debug(f"EEPROM read error at 0x{addr:04X}: {e}")
                        failed_addrs.append(f"0x{addr:04X}")

                eeprom_raw[position] = {
                    "slave_position": position,
                    "data": eeprom_data,
                    "total_bytes": len(eeprom_data) * 4,
                    "failed_addresses": failed_addrs,
                }
                if failed_addrs:
                    self.logger.debug(
                        f"  Slave {position}: {len(failed_addrs)} EEPROM word(s) failed to read"
                    )
                self.logger.display(f"  Read {len(eeprom_data) * 4} bytes from slave {position}")

            except Exception as e:
                self.logger.debug(f"EEPROM dump failed for slave {position}: {e}")
                eeprom_raw[position] = {"error": str(e)}

        return eeprom_raw

    def _parse_eeprom_esi(self, master: Any) -> Dict[int, Any]:
        """Parse EEPROM ESI (EtherCAT Slave Information) per ETG.2010."""
        self.logger.display("Parsing EEPROM/ESI structure (ETG.2010)...")
        results = {}

        targets = self._slave_filter()

        for slave_idx in range(len(master.slaves)):
            position = slave_idx + 1
            if position not in targets:
                continue

            slave = master.slaves[slave_idx]
            self.logger.display(f"Parsing ESI for slave {position}...")

            try:
                # Read EEPROM - pysoem returns 4 bytes per word read, use first 2.
                # A single flaky read shouldn't truncate the image (which would
                # silently misparse), so pad the failed word with zeros to keep
                # byte alignment and only stop after several consecutive failures
                # (the genuine end-of-device signal).
                raw = bytearray()
                consecutive_failures = 0
                for word_addr in range(0, 1024):
                    try:
                        data = slave.eeprom_read(word_addr)
                        raw.extend(data[:2])
                        consecutive_failures = 0
                    except Exception as e:
                        self.logger.debug(f"ESI EEPROM read error at word 0x{word_addr:04X}: {e}")
                        consecutive_failures += 1
                        if consecutive_failures >= 4:
                            break
                        raw.extend(b"\x00\x00")

                if len(raw) < 128:
                    results[position] = {"error": "Insufficient EEPROM data"}
                    continue

                slave_result = {
                    "header": {},
                    "strings": [],
                    "general": {},
                    "fmmu": [],
                    "sync_managers": [],
                    "txpdo": [],
                    "rxpdo": [],
                    "dc": {},
                    "categories_found": [],
                }

                # Parse header (bytes 0x00-0x7F)
                slave_result["header"] = parse_sii_header(raw)

                # Parse categories starting at byte 0x80 (word 0x40)
                strings = [""]  # 1-indexed
                offset = 0x80
                while offset + 4 <= len(raw):
                    cat_type = struct.unpack_from("<H", raw, offset)[0]
                    cat_size_words = struct.unpack_from("<H", raw, offset + 2)[0]
                    cat_size_bytes = cat_size_words * 2

                    # End markers
                    if cat_type in (0xFFFF, 0x7FFF, 0x0000):
                        break

                    # Vendor-specific check
                    is_vendor = bool(cat_type & 0x8000)

                    cat_data = raw[offset + 4 : offset + 4 + cat_size_bytes]
                    cat_name = ESI_CATEGORY_TYPES.get(
                        cat_type, f"Vendor_{cat_type:04X}" if is_vendor else f"Unknown_{cat_type}"
                    )
                    slave_result["categories_found"].append(
                        {"type": cat_type, "name": cat_name, "size": cat_size_bytes}
                    )

                    if cat_type == 10:  # STRINGS
                        strings = parse_strings_category(cat_data)
                        slave_result["strings"] = strings[1:]  # Return without empty first element

                    elif cat_type == 30:  # GENERAL
                        slave_result["general"] = parse_general_category(cat_data, strings)

                    elif cat_type == 40:  # FMMU
                        slave_result["fmmu"] = parse_fmmu_category(cat_data)

                    elif cat_type == 41:  # SyncManager
                        slave_result["sync_managers"] = parse_syncmanager_category(cat_data)

                    elif cat_type == 50:  # TxPDO
                        slave_result["txpdo"] = parse_pdo_category(cat_data, strings)

                    elif cat_type == 51:  # RxPDO
                        slave_result["rxpdo"] = parse_pdo_category(cat_data, strings)

                    elif cat_type == 60:  # DC
                        slave_result["dc"] = parse_dc_category(cat_data, strings)

                    offset += 4 + cat_size_bytes

                results[position] = slave_result

                # Display results - Header info
                header = slave_result["header"]
                self.logger.display("")
                self.logger.success("  === EEPROM Header (ETG.2010) ===")

                # Identity table
                id_table = [
                    ["Vendor ID", f"0x{header['vendor_id']:08X}", str(header["vendor_id"])],
                    [
                        "Product Code",
                        f"0x{header['product_code']:08X}",
                        str(header["product_code"]),
                    ],
                    ["Revision", f"0x{header['revision']:08X}", ""],
                    [
                        "Serial Number",
                        f"0x{header['serial_number']:08X}",
                        str(header["serial_number"]),
                    ],
                    [
                        "Station Alias",
                        f"0x{header['station_alias']:04X}",
                        str(header["station_alias"]),
                    ],
                    [
                        "EEPROM Size",
                        f"{header['eeprom_size_kbit']} Kbit",
                        f"{header['eeprom_size_kbit'] * 128} bytes",
                    ],
                    ["SII Version", str(header["sii_version"]), ""],
                    ["CRC", f"0x{header['crc']:02X}", "OK" if header["crc_valid"] else "INVALID!"],
                ]
                print_table(
                    id_table,
                    ["Field", "Hex", "Decimal"],
                    title=f"Slave {position} Identity",
                    logger=self.logger,
                )

                # Mailbox configuration
                if header["std_rx_mbx_size"] > 0 or header["std_tx_mbx_size"] > 0:
                    mbx_table = [
                        [
                            "Standard RX",
                            f"0x{header['std_rx_mbx_offset']:04X}",
                            str(header["std_rx_mbx_size"]),
                        ],
                        [
                            "Standard TX",
                            f"0x{header['std_tx_mbx_offset']:04X}",
                            str(header["std_tx_mbx_size"]),
                        ],
                    ]
                    if header["bootstrap_rx_mbx_size"] > 0:
                        mbx_table.extend(
                            [
                                [
                                    "Bootstrap RX",
                                    f"0x{header['bootstrap_rx_mbx_offset']:04X}",
                                    str(header["bootstrap_rx_mbx_size"]),
                                ],
                                [
                                    "Bootstrap TX",
                                    f"0x{header['bootstrap_tx_mbx_offset']:04X}",
                                    str(header["bootstrap_tx_mbx_size"]),
                                ],
                            ]
                        )
                    print_table(
                        mbx_table,
                        ["Mailbox", "Offset", "Size"],
                        title="Mailbox Config",
                        logger=self.logger,
                    )

                # Mailbox protocols
                mbx_flags = header.get("mailbox_protocol_flags", {})
                active_mbx = [k for k, v in mbx_flags.items() if v]
                if active_mbx:
                    self.logger.display(f"  Mailbox Protocols: {', '.join(active_mbx)}")

                # Strings
                if slave_result["strings"]:
                    self.logger.display(f"  Strings: {slave_result['strings']}")

                # General category details
                general = slave_result.get("general", {})
                if general and "name" in general:
                    self.logger.display("")
                    self.logger.success("  === General Category ===")
                    self.logger.display(f"  Device Name: {general.get('name', '')}")
                    self.logger.display(f"  Group: {general.get('group', '')}")
                    self.logger.display(f"  Order: {general.get('order', '')}")

                    # CoE capabilities
                    coe_flags = general.get("coe_flags", {})
                    active_coe = [k for k, v in coe_flags.items() if v]
                    if active_coe:
                        self.logger.display(f"  CoE Capabilities: {', '.join(active_coe)}")

                    # Device flags
                    dev_flags = general.get("device_flags", {})
                    active_dev = [k for k, v in dev_flags.items() if v]
                    if active_dev:
                        self.logger.display(f"  Device Flags: {', '.join(active_dev)}")

                    # Current consumption
                    if general.get("current_on_ebus_ma", 0) != 0:
                        self.logger.display(f"  E-Bus Current: {general['current_on_ebus_ma']} mA")

                    # Port config
                    ports = general.get("ports", [])
                    if ports and any(p != "not_impl" for p in ports):
                        self.logger.display(f"  Ports: {ports}")

                # FMMU
                if slave_result["fmmu"]:
                    fmmu_str = ", ".join(
                        f"FMMU{f['fmmu']}={f['type']}"
                        for f in slave_result["fmmu"]
                        if f["type"] != "unused"
                    )
                    if fmmu_str:
                        self.logger.display(f"  FMMU: {fmmu_str}")

                # Sync Managers
                if slave_result["sync_managers"]:
                    self.logger.display("")
                    sm_table = []
                    for idx, sm in enumerate(slave_result["sync_managers"]):
                        ctrl = sm.get("control_flags", {})
                        flags = []
                        if ctrl.get("ecat_event"):
                            flags.append("event")
                        if ctrl.get("watchdog"):
                            flags.append("wdog")
                        sm_table.append(
                            [
                                f"SM{idx}",
                                sm["start"],
                                str(sm["length"]),
                                sm["control"],
                                sm["type"],
                                ctrl.get("direction", ""),
                                ",".join(flags) if flags else "-",
                            ]
                        )
                    print_table(
                        sm_table,
                        ["SM", "Start", "Len", "Ctrl", "Type", "Dir", "Flags"],
                        title=f"Slave {position} Sync Managers",
                        logger=self.logger,
                    )

                # PDO mappings
                for pdo_type, pdo_list in [
                    ("TxPDO (Inputs)", slave_result["txpdo"]),
                    ("RxPDO (Outputs)", slave_result["rxpdo"]),
                ]:
                    if pdo_list:
                        self.logger.display("")
                        self.logger.display(f"  {pdo_type}:")
                        for pdo in pdo_list:
                            flags = []
                            if pdo["flags"].get("fixed"):
                                flags.append("fixed")
                            if pdo["flags"].get("mandatory"):
                                flags.append("mandatory")
                            flag_str = f" [{','.join(flags)}]" if flags else ""
                            self.logger.display(
                                f"    {pdo['index']} {pdo['name']} -> SM{pdo['sm']}{flag_str}"
                            )
                            for entry in pdo["entries"]:
                                self.logger.display(
                                    f"      {entry['index']}:{entry['subindex']} {entry['name']} ({entry['data_type']}, {entry['bit_length']} bits)"
                                )

                # DC info
                dc = slave_result.get("dc", {})
                if dc and "cycle_time0_ns" in dc:
                    self.logger.display("")
                    self.logger.display(
                        f"  DC: {dc['assign_activate_mode']}, Cycle={dc['cycle_time0_ns']}ns"
                    )

                # Categories found summary
                self.logger.display("")
                cats = [c["name"] for c in slave_result.get("categories_found", [])]
                self.logger.display(f"  Categories: {', '.join(cats)}")

            except Exception as e:
                self.logger.debug(f"ESI parse error for slave {position}: {e}")
                results[position] = {"error": str(e)}

        return results

    def _execute_eeprom_write(self, master: Any) -> Dict[str, Any]:
        """Execute EEPROM write command with CRC update."""
        result = {"success": False, "command": self.eeprom_write_cmd}

        try:
            # Parse format: [SLAVE:]OFFSET:VALUE
            parts = self.eeprom_write_cmd.split(":")
            if len(parts) == 2:
                slave_pos = 0
                offset = int(parts[0], 0)
                value = int(parts[1], 0)
            elif len(parts) == 3:
                slave_pos = int(parts[0]) - 1
                offset = int(parts[1], 0)
                value = int(parts[2], 0)
            else:
                result["error"] = "Invalid format. Use OFFSET:VALUE or SLAVE:OFFSET:VALUE"
                self.logger.fail(result["error"])
                return result

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                result["error"] = f"Invalid slave position: {slave_pos + 1}"
                self.logger.fail(result["error"])
                return result

            slave = master.slaves[slave_pos]

            if offset < 0:
                result["error"] = f"Invalid offset: 0x{offset:X}"
                self.logger.fail(result["error"])
                return result

            # Determine data size based on value
            if value <= 0xFFFF:
                data = struct.pack("<H", value)
            else:
                data = struct.pack("<I", value)

            self.logger.warning(
                f"Writing EEPROM at 0x{offset:04X} = 0x{value:X} to slave {slave_pos + 1}..."
            )

            if not hasattr(slave, "eeprom_write"):
                result["error"] = "eeprom_write not available"
                self.logger.fail(result["error"])
                return result

            # EEPROM is word-addressed. An arbitrary byte offset (especially an
            # odd one) does not align to a word boundary, and the value may also
            # span more than one word. Read-modify-write the affected word(s) so
            # the bytes land at exactly [offset, offset + len(data)) without
            # clobbering the surrounding bytes of those words.
            start_word = offset // 2
            end_byte = offset + len(data)  # exclusive
            end_word = (end_byte - 1) // 2  # inclusive

            # Read the covering words into a byte buffer (2 bytes per word).
            buf = bytearray()
            for word_addr in range(start_word, end_word + 1):
                word = slave.eeprom_read(word_addr)
                buf.extend(word[:2])

            # Splice the value bytes into the correct intra-word position.
            splice_at = offset - start_word * 2
            buf[splice_at : splice_at + len(data)] = data

            # Write the merged word(s) back.
            for i, word_addr in enumerate(range(start_word, end_word + 1)):
                slave.eeprom_write(word_addr, bytes(buf[i * 2 : i * 2 + 2]))

            result["slave"] = slave_pos + 1
            result["offset"] = f"0x{offset:04X}"
            result["value"] = f"0x{value:X}"
            result["success"] = True
            self.logger.success("  EEPROM write successful")

            # If any modified byte falls in the header area (0x00-0x0D), the
            # header CRC at byte 0x0E must be refreshed. Key this off the actual
            # affected byte span, not just the start offset.
            if offset < 0x0E:
                self._update_eeprom_crc(slave)

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"EEPROM write failed: {e}")

        return result

    def _execute_set_alias(self, master: Any) -> Dict[str, Any]:
        """Set station alias (convenience function for EEPROM word 0x04)."""
        result = {"success": False, "command": self.set_alias_cmd}

        try:
            # Parse format: [SLAVE:]ALIAS
            parts = self.set_alias_cmd.split(":")
            if len(parts) == 1:
                slave_pos = 0
                alias = int(parts[0], 0)
            elif len(parts) == 2:
                slave_pos = int(parts[0]) - 1
                alias = int(parts[1], 0)
            else:
                result["error"] = "Invalid format. Use ALIAS or SLAVE:ALIAS"
                self.logger.fail(result["error"])
                return result

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                result["error"] = f"Invalid slave position: {slave_pos + 1}"
                self.logger.fail(result["error"])
                return result

            if alias > 0xFFFF:
                result["error"] = "Alias must be 16-bit value (0-65535)"
                self.logger.fail(result["error"])
                return result

            slave = master.slaves[slave_pos]

            self.logger.warning(
                f"Setting station alias to {alias} (0x{alias:04X}) for slave {slave_pos + 1}..."
            )

            # Station alias is at word address 0x04 (byte offset 0x08)
            if hasattr(slave, "eeprom_write"):
                data = struct.pack("<H", alias)
                slave.eeprom_write(0x04, data)

                # Update CRC since we modified header
                self._update_eeprom_crc(slave)

                result["slave"] = slave_pos + 1
                result["alias"] = alias
                result["success"] = True
                self.logger.success(f"  Station alias set to {alias}")
                self.logger.display("  Note: Power cycle required to apply new alias")
            else:
                result["error"] = "eeprom_write not available"
                self.logger.fail(result["error"])

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Set alias failed: {e}")

        return result

    def _update_eeprom_crc(self, slave: Any) -> bool:
        """Recalculate and write CRC for EEPROM header."""
        try:
            # Read first 14 bytes (words 0x00-0x06)
            header_data = bytearray()
            for word_addr in range(7):
                data = slave.eeprom_read(word_addr)
                header_data.extend(data[:2])

            # Calculate new CRC
            new_crc = calculate_sii_crc(bytes(header_data))

            # Write CRC at word 0x07 (byte 0x0E) - low byte is CRC, high byte is 0x00
            crc_data = struct.pack("<H", new_crc)
            slave.eeprom_write(0x07, crc_data)

            self.logger.display(f"  CRC updated to 0x{new_crc:02X}")
            return True

        except Exception as e:
            self.logger.warning(f"  CRC update failed: {e}")
            return False

    def _find_category_offset(self, slave: Any, category_type: int) -> int:
        """Find byte offset of a category in EEPROM. Returns -1 if not found."""
        offset = 0x80  # Categories start at byte 0x80

        for _ in range(100):  # Max iterations
            try:
                # Read category header (2 words = 4 bytes)
                word_addr = offset // 2
                data1 = slave.eeprom_read(word_addr)
                data2 = slave.eeprom_read(word_addr + 1)

                cat_type = struct.unpack("<H", data1[:2])[0]
                cat_size_words = struct.unpack("<H", data2[:2])[0]

                if cat_type in (0xFFFF, 0x7FFF, 0x0000):
                    break

                if cat_type == category_type:
                    return offset + 4  # Return offset of category DATA (after header)

                offset += 4 + cat_size_words * 2

            except Exception:
                break

        return -1

    def _execute_set_coe(self, master: Any) -> Dict[str, Any]:
        """Set CoE capabilities in General category."""
        result = {"success": False, "command": self.set_coe_cmd}

        # CoE flags mapping
        COE_FLAGS = {
            "sdo": 0x01,
            "sdo_info": 0x02,
            "pdo_assign": 0x04,
            "pdo_config": 0x08,
            "upload_at_startup": 0x10,
            "complete_access": 0x20,
        }

        try:
            # Parse format: [SLAVE:]FLAGS
            parts = self.set_coe_cmd.split(":")
            if len(parts) == 1:
                slave_pos = 0
                flags_str = parts[0]
            elif len(parts) == 2:
                slave_pos = int(parts[0]) - 1
                flags_str = parts[1]
            else:
                result["error"] = "Invalid format. Use FLAGS or SLAVE:FLAGS"
                self.logger.fail(result["error"])
                return result

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                result["error"] = f"Invalid slave position: {slave_pos + 1}"
                self.logger.fail(result["error"])
                return result

            # Parse flags - either hex value or comma-separated names
            if flags_str.startswith("0x") or flags_str.isdigit():
                coe_byte = int(flags_str, 0)
            else:
                coe_byte = 0
                for flag_name in flags_str.lower().split(","):
                    flag_name = flag_name.strip()
                    if flag_name in COE_FLAGS:
                        coe_byte |= COE_FLAGS[flag_name]
                    else:
                        result["error"] = (
                            f"Unknown flag: {flag_name}. Valid: {list(COE_FLAGS.keys())}"
                        )
                        self.logger.fail(result["error"])
                        return result

            slave = master.slaves[slave_pos]

            # Find General category (type 30)
            cat_offset = self._find_category_offset(slave, 30)
            if cat_offset < 0:
                result["error"] = "General category not found in EEPROM"
                self.logger.fail(result["error"])
                return result

            # CoE details is at offset 5 within General category
            coe_offset = cat_offset + 5
            word_addr = coe_offset // 2

            # Read current word, modify byte, write back
            current = slave.eeprom_read(word_addr)
            current_bytes = bytearray(current[:2])

            # CoE is at odd offset, so it's the high byte if offset is odd
            byte_pos = coe_offset % 2
            old_coe = current_bytes[byte_pos]
            current_bytes[byte_pos] = coe_byte

            # Decode flags for display
            old_flags = [k for k, v in COE_FLAGS.items() if old_coe & v]
            new_flags = [k for k, v in COE_FLAGS.items() if coe_byte & v]

            self.logger.warning(f"Setting CoE capabilities for slave {slave_pos + 1}...")
            self.logger.display(
                f"  Old: 0x{old_coe:02X} ({', '.join(old_flags) if old_flags else 'none'})"
            )
            self.logger.display(
                f"  New: 0x{coe_byte:02X} ({', '.join(new_flags) if new_flags else 'none'})"
            )

            if hasattr(slave, "eeprom_write"):
                slave.eeprom_write(word_addr, bytes(current_bytes))
                result["slave"] = slave_pos + 1
                result["old_coe"] = f"0x{old_coe:02X}"
                result["new_coe"] = f"0x{coe_byte:02X}"
                result["flags"] = new_flags
                result["success"] = True
                self.logger.success("  CoE capabilities updated")
                self.logger.display("  Note: Power cycle may be required")
            else:
                result["error"] = "eeprom_write not available"
                self.logger.fail(result["error"])

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Set CoE failed: {e}")

        return result

    def _execute_set_mailbox(self, master: Any) -> Dict[str, Any]:
        """Set mailbox protocols in EEPROM header."""
        result = {"success": False, "command": self.set_mailbox_cmd}

        # Mailbox protocol flags
        MBX_FLAGS = {
            "aoe": 0x01,
            "eoe": 0x02,
            "coe": 0x04,
            "foe": 0x08,
            "soe": 0x10,
            "voe": 0x20,
        }

        try:
            # Parse format: [SLAVE:]PROTOCOLS
            parts = self.set_mailbox_cmd.split(":")
            if len(parts) == 1:
                slave_pos = 0
                proto_str = parts[0]
            elif len(parts) == 2:
                slave_pos = int(parts[0]) - 1
                proto_str = parts[1]
            else:
                result["error"] = "Invalid format. Use PROTOCOLS or SLAVE:PROTOCOLS"
                self.logger.fail(result["error"])
                return result

            if slave_pos < 0 or slave_pos >= len(master.slaves):
                result["error"] = f"Invalid slave position: {slave_pos + 1}"
                self.logger.fail(result["error"])
                return result

            # Parse protocols - either hex value or comma-separated names
            if proto_str.startswith("0x") or proto_str.isdigit():
                mbx_word = int(proto_str, 0)
            else:
                mbx_word = 0
                for proto_name in proto_str.lower().split(","):
                    proto_name = proto_name.strip()
                    if proto_name in MBX_FLAGS:
                        mbx_word |= MBX_FLAGS[proto_name]
                    else:
                        result["error"] = (
                            f"Unknown protocol: {proto_name}. Valid: {list(MBX_FLAGS.keys())}"
                        )
                        self.logger.fail(result["error"])
                        return result

            slave = master.slaves[slave_pos]

            # Mailbox protocols at word 0x1C (byte offset 0x38)
            word_addr = 0x1C

            # Read current value
            current = slave.eeprom_read(word_addr)
            old_mbx = struct.unpack("<H", current[:2])[0]

            old_protos = [k.upper() for k, v in MBX_FLAGS.items() if old_mbx & v]
            new_protos = [k.upper() for k, v in MBX_FLAGS.items() if mbx_word & v]

            self.logger.warning(f"Setting mailbox protocols for slave {slave_pos + 1}...")
            self.logger.display(
                f"  Old: 0x{old_mbx:04X} ({', '.join(old_protos) if old_protos else 'none'})"
            )
            self.logger.display(
                f"  New: 0x{mbx_word:04X} ({', '.join(new_protos) if new_protos else 'none'})"
            )

            if hasattr(slave, "eeprom_write"):
                data = struct.pack("<H", mbx_word)
                slave.eeprom_write(word_addr, data)

                result["slave"] = slave_pos + 1
                result["old_mailbox"] = f"0x{old_mbx:04X}"
                result["new_mailbox"] = f"0x{mbx_word:04X}"
                result["protocols"] = new_protos
                result["success"] = True
                self.logger.success("  Mailbox protocols updated")
                self.logger.display("  Note: Power cycle required to apply changes")
            else:
                result["error"] = "eeprom_write not available"
                self.logger.fail(result["error"])

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Set mailbox failed: {e}")

        return result
