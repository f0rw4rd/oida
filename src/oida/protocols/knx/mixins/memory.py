"""
KNX Memory Mixin

Handles memory dump/write operations, group value writes, and device restart.
"""

import asyncio
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from xknx import XKNX

from ..constants import _xknx_cls  # noqa: E402
from ....utils.protocol_helpers import DataFormatter


class MemoryMixin:
    """Mixin providing memory operations."""

    async def _chunked_memory_read(
        self,
        knx: "XKNX",
        address: str,
        start: int,
        length: int,
        read_cls,
        response_cls,
        max_chunk: int,
        label: str = "Memory",
    ) -> Dict[str, Any]:
        """Generic chunked memory reader shared by all memory dump variants.

        Args:
            knx: XKNX instance.
            address: KNX individual address string.
            start: Start memory address.
            length: Number of bytes to read.
            read_cls: xknx request class (e.g. MemoryRead).
            response_cls: xknx response class (e.g. MemoryResponse).
            max_chunk: Maximum bytes per request.
            label: Human-readable label for log messages.

        Returns:
            Dict with address, start, length, data, hex_dump, error.
        """
        self.logger.debug(f"{label} dump: device={address}, start={hex(start)}, len={length}")
        result = {
            "address": address,
            "start": hex(start),
            "length": length,
            "data": None,
            "hex_dump": None,
            "error": None,
        }

        try:
            self.logger.display(
                f"Dumping {label.lower()} from {address}: {hex(start)} ({length} bytes)"
            )
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                data = bytearray()

                for offset in range(0, length, max_chunk):
                    chunk_size = min(max_chunk, length - offset)
                    try:
                        resp = await p2p.request(
                            read_cls(address=start + offset, count=chunk_size),
                            response_cls,
                        )
                        if resp and resp.payload and resp.payload.data:
                            data.extend(resp.payload.data)
                            self.logger.debug(f"  Read {chunk_size} bytes at {hex(start + offset)}")
                        else:
                            self.logger.warning(f"  No data at {hex(start + offset)}")
                            break
                    except Exception as e:
                        self.logger.debug(f"  Error at {hex(start + offset)}: {e}")
                        break

                result["data"] = bytes(data).hex()
                result["hex_dump"] = DataFormatter.format_hex_dump(bytes(data), start_addr=start)

                if len(data) < length:
                    self.logger.warning(
                        f"Partial {label.lower()} dump: {len(data)}/{length} bytes (read stopped early)"
                    )
                else:
                    self.logger.display(f"{label} dump complete: {len(data)} bytes")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error dumping {label.lower()}: {e}")

        return result

    async def _dump_memory(
        self, knx: "XKNX", address: str, start: int, length: int
    ) -> Dict[str, Any]:
        """Dump memory from device"""
        return await self._chunked_memory_read(
            knx,
            address,
            start,
            length,
            read_cls=_xknx_cls.MemoryRead,
            response_cls=_xknx_cls.MemoryResponse,
            max_chunk=12,
            label="Memory",
        )

    # System memory boundary - writes below this can brick devices
    SYSTEM_MEMORY_END = 0x00FF

    async def _write_memory(
        self, knx: "XKNX", address: str, mem_addr: int, data: bytes
    ) -> Dict[str, Any]:
        """Write data to device memory"""
        self.logger.debug(f"Memory write: device={address}, addr={hex(mem_addr)}, len={len(data)}")
        result = {
            "address": address,
            "mem_addr": hex(mem_addr),
            "data": data.hex(),
            "success": False,
            "verified": False,
            "error": None,
        }

        # Safety check: prevent writes to system memory that could brick device
        if mem_addr <= self.SYSTEM_MEMORY_END:
            result["error"] = (
                f"BLOCKED: Write to system memory (0x{mem_addr:04X}) could brick device"
            )
            self.logger.fail(
                f"Write blocked: address 0x{mem_addr:04X} is in system memory (0x0000-0x{self.SYSTEM_MEMORY_END:04X})"
            )
            self.logger.display("Use memory addresses >= 0x0100 for safe writes")
            return result

        # Require --confirm for memory writes
        if not self.args.get("confirm"):
            result["error"] = "Missing --confirm flag"
            self.logger.fail("--memory-write requires --confirm flag (DANGEROUS operation)")
            return result

        try:
            self.logger.display(f"Writing {len(data)} bytes to {address} at {hex(mem_addr)}")
            addr = _xknx_cls.IndividualAddress(address)
            mgmt = knx.management

            async with mgmt.connection(addr) as p2p:
                # Write data
                await p2p.request(
                    _xknx_cls.MemoryWrite(address=mem_addr, count=len(data), data=data),
                    None,  # No response expected for write
                )
                result["success"] = True

                # Verify by reading back
                await asyncio.sleep(0.5)
                resp = await p2p.request(
                    _xknx_cls.MemoryRead(address=mem_addr, count=len(data)),
                    _xknx_cls.MemoryResponse,
                )
                if resp and resp.payload and resp.payload.data:
                    result["verified"] = resp.payload.data == data
                    if result["verified"]:
                        self.logger.success("Write verified successfully")
                    else:
                        self.logger.warning("Write verification failed")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error writing memory: {e}")

        return result

    async def _dump_extended_memory(
        self, knx: "XKNX", address: str, start: int, length: int
    ) -> Dict[str, Any]:
        """Dump extended memory (24-bit addresses) using MemoryExtendedRead"""
        return await self._chunked_memory_read(
            knx,
            address,
            start,
            length,
            read_cls=_xknx_cls.MemoryExtendedRead,
            response_cls=_xknx_cls.MemoryExtendedReadResponse,
            max_chunk=16,
            label="Extended memory",
        )

    async def _dump_user_memory(
        self, knx: "XKNX", address: str, start: int, length: int
    ) -> Dict[str, Any]:
        """Dump user memory using UserMemoryRead"""
        return await self._chunked_memory_read(
            knx,
            address,
            start,
            length,
            read_cls=_xknx_cls.UserMemoryRead,
            response_cls=_xknx_cls.UserMemoryResponse,
            max_chunk=10,
            label="User memory",
        )

    async def _write_group_value(
        self, knx: "XKNX", group_addr: str, value: bytes
    ) -> Dict[str, Any]:
        """Write value to group address"""
        self.logger.debug(f"Group write: addr={group_addr}, value={value.hex()}")
        result = {
            "group_address": group_addr,
            "value": value.hex(),
            "success": False,
            "error": None,
        }

        # Reject the sentinel produced by _parse_group_write on malformed input
        # so a bad --group-write argument never actuates a default device.
        if not group_addr:
            result["error"] = "Invalid group address"
            self.logger.fail("Refusing group write: invalid/empty group address")
            return result

        try:
            self.logger.display(f"Writing {value.hex()} to group address {group_addr}")
            ga = _xknx_cls.GroupAddress(group_addr)

            telegram = _xknx_cls.Telegram(
                destination_address=ga, payload=_xknx_cls.GroupValueWrite(_xknx_cls.DPTArray(value))
            )
            await knx.telegrams.put(telegram)
            result["success"] = True
            self.logger.success("  Group write sent successfully")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error writing to group address: {e}")

        return result

    async def _restart_device(self, knx: "XKNX", address: str) -> Dict[str, Any]:
        """Restart/reboot a KNX device using dm_restart procedure"""
        self.logger.debug(f"Restart device: {address}")
        result = {
            "address": address,
            "success": False,
            "error": None,
        }

        # Safety check: require --confirm for device restart
        if not self.args.get("confirm"):
            result["error"] = "Missing --confirm flag"
            self.logger.fail("--restart requires --confirm flag (device will reboot)")
            return result

        try:
            self.logger.display(f"Restarting device {address}...")
            addr = _xknx_cls.IndividualAddress(address)

            # Use xknx's dm_restart procedure
            await _xknx_cls.dm_restart(knx, addr)

            result["success"] = True
            self.logger.success(f"  Device {address} restart command sent")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error restarting device: {e}")

        return result

    def _parse_memory_range(self, memory_arg: str) -> tuple:
        """Parse memory dump argument (START:LENGTH)"""
        try:
            parts = memory_arg.split(":")
            if len(parts) != 2:
                raise ValueError("Expected format: START:LENGTH")

            start_str, length_str = parts
            # Handle hex or decimal
            start = int(start_str, 16) if start_str.startswith("0x") else int(start_str)
            length = int(length_str)
            return start, length
        except Exception as e:
            self.logger.fail(f"Invalid memory range format '{memory_arg}': {e}")
            return 0x0100, 256  # Default

    def _parse_memory_write(self, write_arg: str) -> tuple:
        """Parse memory write argument (ADDR:DATA)"""
        try:
            parts = write_arg.split(":")
            if len(parts) != 2:
                raise ValueError("Expected format: ADDR:DATA")

            addr_str, data_str = parts
            # Handle hex or decimal address
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            # Data is always hex
            data = bytes.fromhex(data_str)
            return addr, data
        except Exception as e:
            self.logger.fail(f"Invalid memory write format '{write_arg}': {e}")
            return 0, b""

    def _parse_group_write(self, write_arg: str) -> tuple:
        """Parse group write argument (ADDR:VALUE)

        Returns (group_addr, value) on success, or (None, b"") on malformed
        input so the caller never falls back to a default address. A None
        group address is rejected by _write_group_value before any telegram
        is sent.
        """
        try:
            parts = write_arg.split(":")
            if len(parts) != 2:
                raise ValueError("Expected format: ADDR:VALUE")

            group_addr = parts[0]
            value = bytes.fromhex(parts[1])
            return group_addr, value
        except Exception as e:
            # Do NOT fall back to a default group address: returning 0/0/0 here
            # would silently actuate a real device the operator never typed.
            self.logger.fail(f"Invalid group write format '{write_arg}': {e}")
            return None, b""

    # =========================================================================
    # Phase 2: Advanced Object Discovery & Firmware Reconnaissance
    # =========================================================================
    # BCU_TYPES, OBJECT_TYPES, DATA_TYPES imported from data.py
