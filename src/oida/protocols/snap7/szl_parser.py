#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S7 SZL (System Status List) Parser

Parses binary SZL data into structured information.
"""

from typing import Dict, Any


class SZLParser:
    """Parse S7 SZL (System Status List) binary data into structured info"""

    @staticmethod
    def parse(szl_id: int, index: int, data: bytes) -> Dict[str, Any]:
        """Route to appropriate parser based on SZL ID"""
        parsers = {
            0x001C: SZLParser._parse_0x001c,
            0x0011: SZLParser._parse_0x0011,
            0x0132: SZLParser._parse_0x0132,
        }
        parser = parsers.get(szl_id)
        if parser:
            return parser(data, index)
        return {"raw": data.hex(), "parsed": False}

    @staticmethod
    def _parse_0x001c(data: bytes, index: int) -> Dict[str, Any]:
        """Parse module identification SZL (0x001C)

        SZL 0x001C contains comprehensive module identification in record format.
        Structure: Header (4 bytes) + Records
        - Header: record_len (2), partial_list_len (2)
        - Each record: index (2) + string/data (record_len-2)

        Common indices:
        - Index 1: Plant identification
        - Index 2: System name
        - Index 3: Module location
        - Index 4: Manufacturer
        - Index 5: Serial number
        - Index 6: Reserved
        - Index 7: Module type name (e.g., "S7 SoftPLC UA", "CPU 315-2 DP")
        - Index 9: Version info (may contain firmware version bytes)
        - Index 11: OEM info
        """
        result = {"szl_id": "0x001C", "index": index, "parsed": False}
        try:
            if len(data) < 4:
                return result

            # Parse header (little-endian)
            record_len = int.from_bytes(data[0:2], "little")
            partial_list_len = int.from_bytes(data[2:4], "little")
            result["record_len"] = record_len
            result["partial_list_len"] = partial_list_len

            # Guard against malformed SZL: a record must be at least 3 bytes
            # (2-byte index + ≥1 byte payload). record_len=0 from a hostile
            # or buggy PLC would otherwise infinite-loop on `offset +=
            # record_len` below (DoS).
            if record_len < 3:
                result["parsed"] = False
                result["error"] = f"invalid record_len={record_len}"
                return result

            # String length per record = record_len - 2 (for index)
            str_len = record_len - 2 if record_len > 2 else 32

            # Parse records starting at offset 4
            offset = 4
            records = {}
            while offset + record_len <= len(data):
                rec_index = int.from_bytes(data[offset : offset + 2], "big")  # Index is big-endian
                if rec_index == 0:
                    break  # End of records
                str_start = offset + 2
                str_end = min(str_start + str_len, len(data))
                raw_value = data[str_start:str_end]
                # Try to decode as string, keep raw for non-printable
                value = raw_value.decode("ascii", errors="ignore").strip("\x00 \t\r\n")
                if value:
                    records[rec_index] = value.strip()
                elif any(b != 0 for b in raw_value):
                    # Has non-zero data but not printable - store as hex
                    records[rec_index] = raw_value.hex()
                offset += record_len

            # Map known indices to named fields (with extra strip for safety)
            if 1 in records:
                result["plant_identification"] = str(records[1]).strip()
            if 2 in records:
                result["system_name"] = str(records[2]).strip()
            if 3 in records:
                result["module_location"] = str(records[3]).strip()
            if 4 in records:
                result["manufacturer"] = str(records[4]).strip()
            if 5 in records:
                result["serial_number"] = str(records[5]).strip()
            if 7 in records:
                result["module_type"] = str(records[7]).strip()
            if 9 in records:
                # Index 9 may contain version info
                result["version_info"] = str(records[9]).strip()
            if 11 in records:
                result["oem_info"] = str(records[11]).strip()

            result["records"] = records
            result["parsed"] = bool(records)

        except Exception as e:
            result["error"] = str(e)
            result["parsed"] = False
        return result

    @staticmethod
    def _parse_0x0011(data: bytes, index: int) -> Dict[str, Any]:
        """Parse CPU characteristics SZL (0x0011)

        SZL 0x0011 contains module identification data as variable-length records.
        Structure: Header (4 bytes) + Records
        - Header: record_len (2), partial_list_len (2)
        - Each record: index (2) + string data (record_len-2)

        Common indices:
        - Index 1: Module type name (e.g., "IE_CP", "OPC Server")
        - Index 6: Hardware order code (e.g., "6ES7 611-4SB00-0YB7")
        - Index 7: Serial number or additional info
        """
        result = {"szl_id": "0x0011", "index": index, "parsed": False}
        try:
            if len(data) < 4:
                return result

            # Parse header (little-endian)
            record_len = int.from_bytes(data[0:2], "little")
            partial_list_len = int.from_bytes(data[2:4], "little")
            result["record_len"] = record_len
            result["partial_list_len"] = partial_list_len

            # Guard against malformed SZL: see _parse_0x001c — record_len=0
            # would infinite-loop on the `offset += record_len` advance (DoS).
            if record_len < 3:
                result["parsed"] = False
                result["error"] = f"invalid record_len={record_len}"
                return result

            # SZL 0x0011 format: 2-byte index + 20-byte string + 6-byte metadata
            # The string field is fixed at 20 bytes, not record_len - 2
            str_len = 20

            # Parse records starting at offset 4
            offset = 4
            records = {}
            while offset + record_len <= len(data):
                rec_index = int.from_bytes(data[offset : offset + 2], "big")  # Index is big-endian
                if rec_index == 0:
                    break  # End of records
                str_start = offset + 2
                str_end = min(str_start + str_len, len(data))
                value = (
                    data[str_start:str_end].decode("ascii", errors="ignore").strip("\x00 \t\r\n")
                )
                if value:
                    records[rec_index] = value.strip()  # Extra strip for safety
                offset += record_len

            # Map known indices to named fields
            if 1 in records:
                result["module_name"] = records[1].strip()
            if 6 in records:
                result["order_code"] = records[6].strip()
            if 7 in records:
                result["serial_number"] = records[7].strip()

            result["records"] = records
            result["parsed"] = bool(records)

        except Exception as e:
            result["error"] = str(e)
            result["parsed"] = False
        return result

    @staticmethod
    def _parse_0x0132(data: bytes, index: int) -> Dict[str, Any]:
        """Parse protection level SZL (0x0132 index 4)"""
        result = {"szl_id": "0x0132", "index": index}
        try:
            if index == 4 and len(data) >= 12:
                result["sch_schal"] = data[2]
                result["sch_par"] = data[4]
                result["sch_rel"] = data[6]
                result["bart_sch"] = data[8]
                result["anl_sch"] = data[10]
                result["protection_level"] = max(
                    result["sch_schal"], result["sch_par"], result["sch_rel"]
                )
            result["parsed"] = True
        except Exception as e:
            result["error"] = str(e)
            result["parsed"] = False
        return result
