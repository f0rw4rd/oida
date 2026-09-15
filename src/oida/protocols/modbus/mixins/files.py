"""
Modbus Files Mixin

Handles file and advanced register operations:
- Read File Record (FC 20)
- Write File Record (FC 21)
- Mask Write Register (FC 22)
- Read/Write Multiple Registers (FC 23)
- Read FIFO Queue (FC 24)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FilesMixin(_ScannerBase):
    """Mixin providing Modbus file record and advanced operations."""

    def _handle_file_read(self, file_spec: str):
        """Handle file record read (FC 20)"""
        try:
            parts = file_spec.split(":")
            if len(parts) == 2:
                file_num, record_num = int(parts[0]), int(parts[1])
                record_length = 1
            elif len(parts) == 3:
                file_num, record_num, record_length = (int(p) for p in parts)
            else:
                raise ValueError("expected FILE:RECORD or FILE:RECORD:LEN")
        except ValueError:
            self.logger.fail(f"Invalid file spec: {file_spec} (use FILE:RECORD[:LEN])")
            return

        self.logger.display(f"Reading file {file_num} record {record_num}...")
        result = self.scanner._read_file_record(self.conn, file_num, record_num, record_length)
        if result:
            self.results["data"]["file_record"] = result
            self.logger.display(f"[File Record] File {file_num}, Record {record_num}:")
            self.logger.display(f"  Data: {result.get('data', [])}")
        else:
            self.logger.warning("[File Record] Read failed or not supported")

    def _handle_fifo(self, address: int):
        """Handle FIFO queue read (FC 24)"""
        self.logger.display(f"Reading FIFO queue at {address}...")
        result = self.scanner._read_fifo_queue(self.conn, address)
        if result:
            self.results["data"]["fifo"] = result
            self.logger.display(f"[FIFO Queue] Address {address}:")
            self.logger.display(f"  Count: {result.get('count', 0)}")
            self.logger.display(f"  Values: {result.get('values', [])}")
        else:
            self.logger.warning("[FIFO Queue] Read failed or not supported")

    def _handle_file_write(self, file_spec: str):
        """Handle file record write (FC 21)

        Args:
            file_spec: Format is FILE:REC:DATA where DATA is hex string
        """
        try:
            parts = file_spec.split(":")
            if len(parts) < 3:
                self.logger.fail(f"Invalid file spec: {file_spec} (use FILE:REC:HEXDATA)")
                return
            file_num = int(parts[0])
            record_num = int(parts[1])
            hex_data = parts[2]
            # Convert hex string to bytes
            data = bytes.fromhex(hex_data)
        except ValueError as e:
            self.logger.fail(f"Invalid file spec: {file_spec}: {e}")
            return

        # Check for confirmation
        if not self.require_confirm("--confirm", detail="File write requires --confirm flag"):
            self.logger.display(
                f"    Would write {len(data)} bytes to file {file_num} record {record_num}"
            )
            return

        self.logger.display(f"Writing {len(data)} bytes to file {file_num} record {record_num}...")
        result = self.scanner._write_file_record(self.conn, file_num, record_num, data)
        self.results["data"]["file_write"] = result

        if result.get("success"):
            self.logger.success(
                f"[File Write] {result.get('bytes_written', 0)} bytes written to "
                f"file {file_num} record {record_num}"
            )
        else:
            self.logger.fail(f"[File Write] Failed: {result.get('error', 'Unknown error')}")

    def _handle_mask_write(self, mask_spec: str):
        """Handle mask write register (FC 22)

        Args:
            mask_spec: Format is ADDR:AND_MASK:OR_MASK (hex or decimal)
        """
        try:
            parts = mask_spec.split(":")
            if len(parts) != 3:
                self.logger.fail(f"Invalid mask spec: {mask_spec} (use ADDR:AND:OR)")
                return

            # Parse values - support both hex (0x...) and decimal
            def parse_int(s):
                s = s.strip()
                if s.startswith("0x") or s.startswith("0X"):
                    return int(s, 16)
                return int(s)

            address = parse_int(parts[0])
            and_mask = parse_int(parts[1])
            or_mask = parse_int(parts[2])

            # Validate 16-bit values
            if not (0 <= and_mask <= 0xFFFF):
                raise ValueError(f"AND mask must be 0-65535, got {and_mask}")
            if not (0 <= or_mask <= 0xFFFF):
                raise ValueError(f"OR mask must be 0-65535, got {or_mask}")

        except ValueError as e:
            self.logger.fail(f"Invalid mask spec: {mask_spec}: {e}")
            return

        # Check for confirmation (mask write modifies data)
        if not self.require_confirm("--confirm", detail="Mask write requires --confirm flag"):
            self.logger.display(
                f"    Would apply mask write to register {address}: "
                f"AND=0x{and_mask:04X}, OR=0x{or_mask:04X}"
            )
            return

        self.logger.display(
            f"Mask write to register {address}: AND=0x{and_mask:04X}, OR=0x{or_mask:04X}..."
        )
        result = self.scanner._mask_write_register(self.conn, address, and_mask, or_mask)
        self.results["data"]["mask_write"] = result

        if result.get("success"):
            msg = f"[Mask Write] Register {address} updated"
            if "new_value" in result:
                msg += f" (new value: {result['new_value']} / 0x{result['new_value']:04X})"
            self.logger.success(msg)
        else:
            self.logger.fail(f"[Mask Write] Failed: {result.get('error', 'Unknown error')}")

    def _handle_atomic_rw(self, atomic_spec: str):
        """Handle atomic read/write multiple registers (FC 23)

        Args:
            atomic_spec: Format is READ_ADDR-COUNT:WRITE_ADDR=VAL1,VAL2,...
        """
        try:
            # Split into read and write parts
            parts = atomic_spec.split(":")
            if len(parts) != 2:
                self.logger.fail(
                    f"Invalid atomic spec: {atomic_spec} (use READ_ADDR-COUNT:WRITE_ADDR=VAL1,VAL2)"
                )
                return

            read_part = parts[0]
            write_part = parts[1]

            # Parse read part: ADDR-COUNT
            if "-" in read_part:
                read_parts = read_part.split("-")
                read_addr = int(read_parts[0])
                read_count = int(read_parts[1])
            else:
                read_addr = int(read_part)
                read_count = 1

            # Parse write part: ADDR=VAL1,VAL2,...
            if "=" not in write_part:
                self.logger.fail(f"Invalid write part: {write_part} (use WRITE_ADDR=VAL1,VAL2)")
                return

            write_addr_str, values_str = write_part.split("=", 1)
            write_addr = int(write_addr_str)
            write_data = [int(v.strip()) for v in values_str.split(",")]

        except ValueError as e:
            self.logger.fail(f"Invalid atomic spec: {atomic_spec}: {e}")
            return

        # Check for confirmation (atomic write modifies data)
        if not self.require_confirm(
            "--confirm", detail="Atomic read/write requires --confirm flag"
        ):
            self.logger.display(
                f"    Would read {read_count} registers from {read_addr} and "
                f"write {len(write_data)} values to {write_addr}"
            )
            return

        self.logger.display(
            f"Atomic read/write: reading {read_count} from {read_addr}, "
            f"writing {len(write_data)} values to {write_addr}..."
        )
        result = self.scanner._atomic_read_write(
            self.conn, read_addr, read_count, write_addr, write_data
        )
        self.results["data"]["atomic_rw"] = result

        if result.get("success"):
            self.logger.success("[Atomic Read/Write] Operation successful")
            if result.get("read_values"):
                self.logger.display(f"  Read values: {result['read_values']}")
            self.logger.display(f"  Written values: {result['values_written']}")
        else:
            self.logger.fail(f"[Atomic Read/Write] Failed: {result.get('error', 'Unknown error')}")
