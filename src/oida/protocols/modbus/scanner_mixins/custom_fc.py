"""
Modbus Scanner Custom Function Code Mixin

Handles custom/raw function code operations:
- Send arbitrary function codes with custom payloads
- Exception name mapping
"""

from __future__ import annotations

import struct
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerCustomFCMixin(_ScannerBase):
    """Mixin providing custom function code handling for ModbusScanner."""

    def send_custom_fc(self, client: Any, fc: int, payload: bytes, unit_id: int) -> Dict[str, Any]:
        """
        Send custom function code with payload and return full response.

        Uses pymodbus's custom PDU registration to properly capture responses.
        See: https://github.com/pymodbus-dev/pymodbus/blob/dev/examples/custom_msg.py

        Args:
            client: Connected Modbus client
            fc: Function code (1-127)
            payload: Raw payload bytes to send after FC
            unit_id: Modbus unit/slave ID

        Returns:
            Dict with keys:
                success: bool - Whether request succeeded
                function_code: int - Requested FC
                request_payload: bytes - Sent payload
                response_payload: bytes - Raw response bytes (excluding FC)
                response_fc: int - Response function code
                is_exception: bool - True if exception response (FC >= 0x80)
                exception_code: int|None - Exception code if is_exception
                exception_name: str|None - Exception name if is_exception
                error: str|None - Error message if failed
        """
        result = {
            "success": False,
            "function_code": fc,
            "request_payload": payload,
            "response_payload": b"",
            "response_fc": 0,
            "is_exception": False,
            "exception_code": None,
            "exception_name": None,
            "error": None,
        }

        # Validate FC range
        if not 1 <= fc <= 127:
            result["error"] = f"Function code must be 1-127, got {fc}"
            return result

        try:
            from pymodbus.pdu import ModbusPDU

            # Create custom request class for this specific FC
            class CustomFCRequest(ModbusPDU):
                """Custom request that sends raw payload bytes."""

                function_code = fc
                rtu_frame_size = 4 + len(payload)

                def __init__(self, data_bytes: bytes, dev_id: int = 1, **kwargs):
                    super().__init__(dev_id=dev_id, **kwargs)
                    self._payload = data_bytes

                def encode(self) -> bytes:
                    return self._payload

                def decode(self, data: bytes) -> None:
                    self._payload = data

            # Create custom response class that captures raw bytes
            class CustomFCResponse(ModbusPDU):
                """Custom response that captures all raw bytes."""

                function_code = fc
                rtu_byte_count_pos = 2

                def __init__(self, dev_id: int = 1, **kwargs):
                    super().__init__(dev_id=dev_id, **kwargs)
                    self.raw_data: bytes = b""

                def encode(self) -> bytes:
                    return self.raw_data

                def decode(self, data: bytes) -> None:
                    # Capture ALL response bytes
                    self.raw_data = bytes(data)

            # Register the custom response class with the client
            # This tells pymodbus how to decode responses with this FC
            if hasattr(client, "register"):
                client.register(CustomFCResponse)

            # Create and execute request
            request = CustomFCRequest(payload, dev_id=unit_id)

            # Execute - pymodbus 3.x uses execute(no_response_expected, pdu)
            # For sync client, it's just execute(pdu) or execute(False, pdu)
            try:
                # Try pymodbus 3.x style first
                response = client.execute(False, request)
            except TypeError as e:
                # Fallback for older style
                self.logger.debug("decode failed: %s", e)
                response = client.execute(request)

            if response is None:
                result["error"] = "No response received (timeout)"
                return result

            # Get response function code
            response_fc = getattr(response, "function_code", 0)
            result["response_fc"] = response_fc

            # Check for exception response (FC >= 0x80)
            if response_fc >= 0x80:
                result["is_exception"] = True
                result["exception_code"] = getattr(response, "exception_code", None)
                if result["exception_code"] is not None:
                    result["exception_name"] = self._get_exception_name(result["exception_code"])
                result["success"] = True
                return result

            # Extract response payload from our custom response class
            if hasattr(response, "raw_data"):
                result["response_payload"] = response.raw_data
            elif hasattr(response, "encode"):
                try:
                    result["response_payload"] = response.encode()
                except Exception as e:
                    self.logger.debug(f"Failed to encode response: {e}")

            # Also try standard response attributes
            if not result["response_payload"]:
                if hasattr(response, "registers"):
                    reg_bytes = b""
                    for reg in response.registers:
                        reg_bytes += struct.pack(">H", reg)
                    result["response_payload"] = reg_bytes
                elif hasattr(response, "bits"):
                    result["response_payload"] = bytes(response.bits)

            result["success"] = True

        except Exception as e:
            self.logger.debug("decode failed: %s", e)
            result["error"] = str(e)

        return result

    def _get_exception_name(self, code: int) -> str:
        """Map Modbus exception code to name."""
        exception_names = {
            1: "ILLEGAL FUNCTION",
            2: "ILLEGAL DATA ADDRESS",
            3: "ILLEGAL DATA VALUE",
            4: "SERVER DEVICE FAILURE",
            5: "ACKNOWLEDGE",
            6: "SERVER DEVICE BUSY",
            8: "MEMORY PARITY ERROR",
            10: "GATEWAY PATH UNAVAILABLE",
            11: "GATEWAY TARGET DEVICE FAILED TO RESPOND",
        }
        return exception_names.get(code, "UNKNOWN")

    def _send_mei_canopen(self, client: Any, request_data: bytes) -> Dict[str, Any] | None:
        """Send a CANopen request encapsulated in a Modbus MEI frame (FC 43/13).

        CiA 309-2 tunnels CANopen SDOs through Modbus/TCP by wrapping the
        request inside FC 43 with MEI Type 13 (0x0D). This helper builds
        that envelope on top of send_custom_fc and returns the unwrapped
        payload (with the MEI type byte stripped) plus the raw bytes so
        callers in canopen.py can decode SDO/upload/download responses.

        Returns None when the target rejects the FC entirely (so callers
        get the same 'unsupported / failed' branch they already have), or
        a dict {data, raw, error?} on any other outcome.
        """
        from ..constants import MEIType

        payload = bytes([int(MEIType.CANOPEN)]) + bytes(request_data)
        result = self.send_custom_fc(client, 43, payload, self.unit_id)

        if not result or not result.get("success"):
            return None
        if result.get("is_exception"):
            # FC 43 with unknown MEI type returns ILLEGAL FUNCTION or
            # ILLEGAL DATA VALUE -- treat as 'unsupported'.
            return None

        raw = result.get("response_payload", b"") or b""
        # Per FC 43 response format: first byte echoes MEI Type. Strip it
        # so canopen.py sees just the SDO payload.
        if raw and raw[0] == int(MEIType.CANOPEN):
            return {"data": raw[1:], "raw": raw}
        return {"data": raw, "raw": raw, "error": "Unexpected MEI type in response"}
