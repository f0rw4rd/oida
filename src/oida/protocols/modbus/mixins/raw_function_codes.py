"""
Modbus Raw Function Code Mixin

Handles custom/raw function code operations:
- Send arbitrary function codes
- Parse and display responses
- Save responses to files
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from oida.utils.payload import resolve_file_payload

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class RawFCMixin(_ScannerBase):
    """Mixin providing Modbus raw function code operations."""

    def _handle_raw_fc(self):
        """Handle --raw-fc/--custom-fc flag."""
        fc = getattr(self.args, "raw_fc", None)
        if fc is None:
            return

        # --raw-fc can send any function code including writes (5/6/15/16),
        # restart (FC 8), FC 23 (read-write multiple), and vendor codes
        # 65-72 — all of which can modify PLC state.
        if not self.require_confirm(
            "--raw-fc",
            detail="--raw-fc sends arbitrary function codes (incl. writes 5/6/15/16, "
            "restart FC 8, vendor 65-72) — requires --confirm",
        ):
            return
        payload_str = getattr(self.args, "payload", None)
        response_format = getattr(self.args, "response_format", "hex")
        save_file = getattr(self.args, "save_response", None)

        # Parse payload
        payload = self._parse_payload(payload_str) if payload_str else bytes()

        self.logger.display(f"Sending raw function code {fc} (0x{fc:02X})...")
        if payload:
            self.logger.display(f"  Payload ({len(payload)} bytes): {payload.hex()}")

        result = self.scanner.send_custom_fc(self.conn, fc, payload, self.scanner.unit_id)

        if result:
            self.results["data"]["raw_fc"] = result

            if result.get("is_exception"):
                exc_code = result.get("exception_code", 0)
                exc_name = result.get("exception_name", "Unknown")
                self.logger.warning(f"  Exception: {exc_code} ({exc_name})")
            else:
                response_data = result.get("response_payload", b"")
                self.logger.success(f"  Response ({len(response_data)} bytes):")

                if response_format == "hexdump":
                    self._display_hexdump(response_data)
                else:
                    self.logger.display(f"    {response_data.hex()}")

                # Save to file if requested
                if save_file and response_data:
                    self._save_response_to_file(save_file, response_data)
        else:
            self.logger.fail("No response or connection error")

    def _parse_payload(self, payload_str: str) -> bytes:
        """Parse payload string into bytes."""
        if not payload_str:
            return bytes()

        # Check for file reference (@path/to/file)
        try:
            data, _path = resolve_file_payload(payload_str)
            if data is not None:
                return data
        except OSError as e:
            self.logger.warning(f"Could not read payload file: {e}")
            return bytes()

        # Remove common separators and parse as hex
        payload_str = payload_str.replace(" ", "").replace(":", "").replace("-", "")

        # Handle 0x prefix
        if payload_str.lower().startswith("0x"):
            payload_str = payload_str[2:]

        try:
            return bytes.fromhex(payload_str)
        except ValueError as e:
            self.logger.warning(f"Invalid hex payload: {e}")
            return bytes()

    def _display_hexdump(self, data: bytes, bytes_per_line: int = 16):
        """Display data in hexdump format."""
        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset : offset + bytes_per_line]

            # Hex part
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)

            # ASCII part
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

            self.logger.display(f"    {offset:04X}  {hex_part}  |{ascii_part}|")

    def _save_response_to_file(self, filepath: str, data: bytes):
        """Save raw response data to file."""
        try:
            with open(filepath, "wb") as f:
                f.write(data)
            self.logger.success(f"  Saved {len(data)} bytes to {filepath}")
        except Exception as e:
            self.logger.warning(f"Could not save response: {e}")

    def _handle_enumerate_functions(self):
        """Handle --enumerate-functions flag.

        This probes every FC in range with an EMPTY payload (including write FCs
        5/6/15/16/23) WITHOUT --confirm, unlike _test_function_codes which gates
        the same MUTATING_FCS behind --confirm. The exemption is deliberate: a
        spec-compliant server rejects an empty write request as an
        illegal-data-value exception before performing any write, so an
        empty-payload probe only reveals whether the FC is *implemented*, never
        mutates state. (Do not add real payloads here without a --confirm gate.)
        """
        self.logger.display("Enumerating supported function codes...")

        fc_range_str = getattr(self.args, "fc_range", "1-8,11,12,15-17,20-23,43")
        fc_all = getattr(self.args, "fc_all", False)

        if fc_all:
            fc_list = list(range(1, 128))
        else:
            fc_list = self._parse_fc_range(fc_range_str)

        supported = []
        exceptions = []

        for fc in fc_list:
            result = self.scanner.send_custom_fc(self.conn, fc, bytes(), self.scanner.unit_id)

            # Only a response that was actually received counts. send_custom_fc
            # sets success=True for both normal AND exception responses, and
            # success=False on a failed/timed-out send — the previous `if result:`
            # was always truthy, so errored sends were mis-counted as supported.
            if result and result.get("success"):
                if result.get("is_exception"):
                    exc_code = result.get("exception_code", 0)
                    # Exception 1 (Illegal Function) means not supported
                    # Other exceptions may indicate partial support
                    if exc_code != 1:
                        exceptions.append({"fc": fc, "exception": exc_code})
                else:
                    supported.append(fc)

        self.results["data"]["function_codes"] = {"supported": supported, "exceptions": exceptions}

        if supported:
            self.logger.success(f"Supported function codes: {supported}")
        if exceptions:
            self.logger.display(
                f"FCs with non-'Illegal Function' exceptions: {[e['fc'] for e in exceptions]}"
            )

    def _parse_fc_range(self, range_str: str) -> list:
        """Parse function code range string (central parser)."""
        from ....utils import ProtocolParser

        return ProtocolParser.parse_address_range(range_str)
