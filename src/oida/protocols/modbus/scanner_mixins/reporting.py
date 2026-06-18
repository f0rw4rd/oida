"""
Modbus Scanner Reporting Mixin

Handles register decoding, monitoring, and result reporting:
- Register value decoding (single and multi-register types)
- Register monitoring (continuous polling)
- Scan result reporting and table building
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerReportingMixin(_ScannerBase):
    """Mixin providing decoding, monitoring, and reporting for ModbusScanner."""

    def _decode_register_values(
        self,
        registers: Dict[int, int],
        decode_type: str,
        byte_order: str = "big",
        word_order: str = "big",
    ) -> List[Dict[str, Any]]:
        """
        Decode register values using specified data type

        Args:
            registers: Dict of {address: value}
            decode_type: Type string (f32, i32, str, etc.)
            byte_order: Byte order (big/little)
            word_order: Word order for 32/64-bit (big/little)

        Returns:
            List of decoded values with metadata
        """
        from ..decoder import ModbusDecoder, REGISTERS_PER_TYPE

        decoder = ModbusDecoder(byte_order=byte_order, word_order=word_order)

        # Convert dict to sorted list
        sorted_addrs = sorted(registers.keys())
        reg_values = [registers[addr] for addr in sorted_addrs]

        decoded = decoder.decode(reg_values, decode_type)

        # Add address info
        regs_per_value = REGISTERS_PER_TYPE.get(decode_type, 1) or 1
        for i, item in enumerate(decoded):
            base_addr = (
                sorted_addrs[i * regs_per_value] if i * regs_per_value < len(sorted_addrs) else 0
            )
            item["address"] = base_addr

        return decoded

    def _monitor_registers(
        self,
        client: Any,
        addresses: List[int],
        register_type: str = "holding_registers",
        interval: float = 1.0,
        duration: Optional[int] = None,
        on_change: bool = False,
        decode_type: Optional[str] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Continuously monitor registers (generator function)

        Args:
            client: Modbus client
            addresses: List of register addresses to monitor
            register_type: Type of registers (holding_registers, input_registers, etc.)
            interval: Polling interval in seconds
            duration: Optional max duration in seconds
            on_change: Only yield when values change
            decode_type: Optional data type for decoding

        Yields:
            dict: Current values and any changes detected
        """
        from ..register_io import read_registers_batched

        previous_values = {}
        start_time = time.time()

        while True:
            # Check duration limit
            if duration and (time.time() - start_time) > duration:
                break

            changes = {}
            timestamp = datetime.now().isoformat()

            # Batch-read all monitored addresses (no individual fallback for speed).
            current_values = read_registers_batched(
                client,
                register_type,
                addresses,
                unit_id=self.unit_id,
                fallback_individual=False,
                logger=self.logger,
            )

            # Detect changes.
            for addr, value in current_values.items():
                if addr in previous_values and previous_values[addr] != value:
                    changes[addr] = {"old": previous_values[addr], "new": value}
                elif addr not in previous_values:
                    changes[addr] = {"old": None, "new": value}

            # Decode values if requested
            decoded_values = {}
            if decode_type:
                decoded = self._decode_register_values(current_values, decode_type)
                for item in decoded:
                    decoded_values[item.get("address", 0)] = item.get("value")

            # Prepare result
            result = {
                "timestamp": timestamp,
                "values": current_values,
                "decoded": decoded_values if decoded_values else None,
                "changes": changes,
                "elapsed_seconds": round(time.time() - start_time, 1),
            }

            # Yield based on on_change setting
            if not on_change or changes:
                yield result

            # Update previous values
            previous_values = current_values.copy()

            # Wait for next poll
            time.sleep(interval)

    def _report_findings(self, results: Dict[str, Any]):
        """Report scan findings"""
        from ..decoder import ModbusDecoder
        from ....utils.export_utils import export_table, configure as configure_export

        server_info = results.get("server_info", {})
        registers = results.get("registers", {})
        security = results.get("security_analysis", {})

        # Report host
        self.report_host_info(
            self.host,
            server_type="Modbus",
            connection_type=server_info.get("connection_type", "TCP"),
        )

        # Report service
        service_info = {
            "name": "modbus",
            "product": "Modbus Server",
            "version": server_info.get("server_id", "Unknown"),
        }
        self.report_service_info(self.host, port=self.port, **service_info)

        # Report security issues from security analysis
        for issue in security.get("issues", []):
            self.report_vulnerability(
                self.host, "modbus_security_issue", description=issue, severity="medium"
            )

        # Display register values if found
        total_regs = sum(len(regs) for regs in registers.values())
        if total_regs > 0:
            # Create decoder for decode-all mode
            decoder = ModbusDecoder() if self.decode_all else None

            # Configure export with logger but no output_dir (console only here)
            # File export is handled separately by the framework
            configure_export(output_dir=self.output_dir, logger=self.logger)

            for reg_type, regs in registers.items():
                if regs:
                    type_name = reg_type.replace("_", " ").title()
                    sorted_items = sorted(regs.items())

                    # Filter zero/null values if requested
                    if self.filter_zero:
                        sorted_items = [
                            (addr, info)
                            for addr, info in sorted_items
                            if info.get("value") not in (0, None, False)
                        ]
                        if not sorted_items:
                            continue  # Skip empty register types

                    # Build table data
                    if self.decode_all and decoder:
                        headers = ["Addr", "Value", "Hex", "i16", "Bits", "ASCII"]
                        rows = self._build_decode_all_rows(decoder, sorted_items)
                    elif self.decode_type:
                        headers, rows = self._build_decode_type_rows(sorted_items)
                    else:
                        headers = ["Addr", "Value", "Hex"]
                        rows = []
                        for addr, info in sorted_items:
                            val = info.get("value", "?")
                            if isinstance(val, int) and not isinstance(val, bool):
                                rows.append([addr, val, f"0x{val:04X}"])
                            else:
                                rows.append([addr, val, ""])

                    # Export table (console + optional file)
                    table_name = f"modbus_{reg_type}_{self.host.replace('.', '_')}"
                    export_table(table_name, headers, rows, title=f"[{type_name}]")

    def _build_decode_all_rows(
        self,
        decoder: Any,
        sorted_items: List,
    ) -> List[List[Any]]:
        """
        Build table rows with all possible decodings for register values.

        Args:
            decoder: ModbusDecoder instance
            sorted_items: List of (addr, info) tuples

        Returns:
            List of rows for export_table: [Addr, Value, Hex, i16, Bits, ASCII]
        """
        rows = []

        for addr, info in sorted_items:
            val = info.get("value", "?")

            if not isinstance(val, int) or isinstance(val, bool):
                rows.append([addr, val, "", "", "", ""])
                continue

            # Base columns
            hex_val = f"0x{val:04X}"

            # Decode i16 (only show if negative)
            i16_val = ""
            try:
                results = decoder.decode([val], "i16")
                if results and "error" not in results[0]:
                    decoded = results[0]["value"]
                    if decoded < 0:
                        i16_val = str(decoded)
            except Exception as e:
                self.logger.debug("build decode all rows failed: %s", e)
                pass

            # Decode bits
            bits_val = ""
            try:
                results = decoder.decode([val], "bits")
                if results and "error" not in results[0]:
                    bits_val = results[0]["value"]
            except Exception as e:
                self.logger.debug("build decode all rows failed: %s", e)
                pass

            # Decode ASCII (only if printable)
            ascii_val = ""
            try:
                results = decoder.decode([val], "str")
                if results and "error" not in results[0]:
                    decoded = results[0]["value"]
                    if decoded and all(32 <= ord(c) < 127 for c in decoded):
                        ascii_val = f'"{decoded}"'
            except Exception as e:
                self.logger.debug("build decode all rows failed: %s", e)
                pass

            rows.append([addr, val, hex_val, i16_val, bits_val, ascii_val])

        return rows

    def _build_decode_type_rows(
        self,
        sorted_items: List,
    ) -> tuple:
        """
        Build table rows with decoded values for a specific type (e.g., f32, i32).

        Multi-register types are grouped (e.g., f32 uses 2 consecutive registers).
        Use --decode-width to override register grouping or set string length.

        Args:
            sorted_items: List of (addr, info) tuples

        Returns:
            Tuple of (headers, rows) for export_table
        """
        from ..decoder import ModbusDecoder, REGISTERS_PER_TYPE, parse_endian

        decode_type = self.decode_type.lower()
        default_regs = REGISTERS_PER_TYPE.get(decode_type, 1) or 1

        # Use custom width if specified, otherwise use type default
        # For strings: width = number of characters (2 chars per register)
        # For others: width = number of registers to group
        if self.decode_width:
            if decode_type == "str":
                # String: width is char count, need width/2 registers (2 chars per reg)
                regs_needed = (self.decode_width + 1) // 2
                string_length = self.decode_width
            else:
                regs_needed = self.decode_width
                string_length = None
        else:
            regs_needed = default_regs
            string_length = None

        byte_order, word_order = parse_endian(self.endian)
        decoder = ModbusDecoder(byte_order=byte_order, word_order=word_order)

        # Determine column header suffix
        width_info = f", w={self.decode_width}" if self.decode_width else ""
        col_header = f"Decoded ({decode_type}{width_info})"

        if regs_needed == 1 and not self.decode_width:
            # Single-register types: show inline
            headers = ["Addr", "Value", "Hex", col_header]
            rows = []
            for addr, info in sorted_items:
                val = info.get("value", "?")
                if not isinstance(val, int) or isinstance(val, bool):
                    rows.append([addr, val, "", ""])
                    continue
                hex_val = f"0x{val:04X}"
                try:
                    results = decoder.decode([val], decode_type)
                    decoded = results[0]["value"] if results else "?"
                except Exception as e:
                    self.logger.debug("build decode type rows failed: %s", e)
                    decoded = "?"
                rows.append([addr, val, hex_val, decoded])
            return headers, rows

        # Multi-register types: group registers
        headers = ["Addr", "Registers", "Hex", col_header]
        rows = []

        # Build dict for quick lookup
        reg_dict = {addr: info.get("value", 0) for addr, info in sorted_items}
        addrs = sorted(reg_dict.keys())

        i = 0
        while i <= len(addrs) - regs_needed:
            base_addr = addrs[i]
            # Check if we have consecutive registers
            consecutive = True
            for j in range(1, regs_needed):
                if base_addr + j not in reg_dict:
                    consecutive = False
                    break

            if consecutive:
                # Collect register values
                reg_vals = [reg_dict[base_addr + j] for j in range(regs_needed)]
                hex_vals = " ".join(f"0x{v:04X}" for v in reg_vals)
                reg_str = ", ".join(str(v) for v in reg_vals)

                try:
                    if decode_type == "str" and string_length:
                        results = decoder.decode(reg_vals, decode_type, string_length=string_length)
                    else:
                        results = decoder.decode(reg_vals, decode_type)
                    decoded = results[0]["value"] if results else "?"
                    # Format floats nicely
                    if isinstance(decoded, float):
                        if abs(decoded) < 0.0001 or abs(decoded) > 1e10:
                            decoded = f"{decoded:.6e}"
                        else:
                            decoded = f"{decoded:.6f}"
                except Exception as e:
                    self.logger.debug("build decode type rows failed: %s", e)
                    decoded = f"err: {e}"

                addr_range = f"{base_addr}-{base_addr + regs_needed - 1}"
                rows.append([addr_range, reg_str, hex_vals, decoded])
                i += regs_needed
            else:
                # Skip to next address if not consecutive
                i += 1

        return headers, rows
