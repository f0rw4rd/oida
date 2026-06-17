"""
Snap7 Slot Scan Mixin

Handles slot scanning and S7CommPlus detection:
- S7CommPlus not-supported display
- Single slot probing with device info extraction
- Multi-phase slot scanning (S7-1200/1500 first, then S7-300/400)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class SlotScanMixin(_ScannerBase):
    """Mixin providing slot scanning and S7CommPlus detection."""

    def _display_s7plus_not_supported(self, series: str, firmware: str, order_code: str) -> None:
        """Display message that S7-1200/1500 require S7CommPlus which is not supported.

        S7-1200 and S7-1500 PLCs use the S7CommPlus protocol which requires
        proprietary authentication. This is not implemented.
        Falling back to Snap7 HMI-mode (limited functionality).
        """
        # Generate NVD search link for the PLC model
        nvd_url = (
            f"https://nvd.nist.gov/vuln/search/results?query=siemens+{series.replace('-', '_')}"
        )

        self.logger.warning(f"{series} detected - S7CommPlus protocol NOT SUPPORTED")
        self.logger.display(f"  Model: {order_code or 'unknown'}")
        self.logger.display(f"  Firmware: {firmware or 'unknown'}")
        self.logger.display("")
        self.logger.display("S7-1200/1500 PLCs use the S7CommPlus protocol which requires")
        self.logger.display("proprietary authentication. This protocol is not implemented.")
        self.logger.display("")
        self.logger.display("Falling back to Snap7 (limited HMI-mode access)")
        self.logger.display(f"[CVE] {nvd_url}")

    def _scan_single_slot(
        self, host: str, port: int, rack: int, slot: int, detailed: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Probe a single rack/slot combination and extract device info.

        Args:
            host: Target IP address.
            port: Target TCP port.
            rack: S7 rack number.
            slot: S7 slot number.
            detailed: If True, perform SZL queries, device name lookup,
                      bootloader extraction, and PLC status check (Phase 1).
                      If False, only extract order code and firmware (Phase 2).

        Returns:
            Dict with slot info if a device was found, or None.
        """
        from ..scanner import _get_snap7_client, _get_order_code_extended
        from ..szl_parser import SZLParser
        from ..device_lookup import lookup_device_name
        from ....utils.protocol_helpers import ConnectionHelper
        from snap7.type import Parameter

        try:
            snap7_client = _get_snap7_client()
            client = snap7_client.Client()

            # Set short timeouts for scanning (ms)
            try:
                client.set_param(Parameter.PingTimeout, 2000)
                client.set_param(Parameter.RecvTimeout, 3000)
                client.set_param(Parameter.SendTimeout, 3000)
            except Exception as e:
                self.logger.debug("scan slots set_param failed: %s", e)

            self.logger.debug(f"Trying rack {rack}, slot {slot}...")
            # snap7 C library requires IP addresses, not hostnames
            ip = ConnectionHelper.resolve_hostname(host)
            client.connect(ip, rack, slot, tcp_port=port)

            if not client.get_connected():
                self.logger.debug(f"Slot {slot}: no response")
                return None

            self.logger.debug("Slot %d: detailed=%s mode", slot, detailed)

            info = {"rack": rack, "slot": slot}
            module_name = None
            hw_order_code = None
            fw_version = None
            bootloader_version = None

            # Method 1: Extended order code with bootloader extraction
            try:
                oc_extended = _get_order_code_extended(client)
                code = oc_extended.get("code")
                if code:
                    if (
                        code.startswith("6ES7")
                        or code.startswith("6ED1")
                        or code.startswith("6GK7")
                    ):
                        hw_order_code = code
                    else:
                        module_name = code
                fw_version = oc_extended.get("firmware")
                bootloader_version = oc_extended.get("bootloader")
            except Exception as e:
                self.logger.debug("scan slots order_code failed: %s", e)

            if detailed:
                # python-snap7 exposes get_cpu_state() (returns a status string
                # like "S7CpuStatusRun"), not get_plc_status(); the old call
                # raised AttributeError so plc_status was always None.
                plc_status = None
                try:
                    plc_status = client.get_cpu_state()
                except Exception as e:
                    self.logger.debug("scan slots plc_status failed: %s", e)

                # SZL 0x0011 for better module info (if order code not found)
                if not hw_order_code:
                    try:
                        szl_data = client.read_szl(0x0011, 0)
                        if szl_data:
                            parsed = SZLParser.parse(0x0011, 0, bytes(szl_data))
                            if parsed.get("order_code"):
                                hw_order_code = parsed["order_code"].strip()
                            if parsed.get("module_name") and not module_name:
                                module_name = parsed["module_name"].strip()
                    except Exception as e:
                        self.logger.debug("scan slots SZL 0x0011 failed: %s", e)

                # SZL 0x001C for module type (if still missing)
                if not module_name:
                    try:
                        szl_data = client.read_szl(0x001C, 1)
                        if szl_data:
                            parsed = SZLParser.parse(0x001C, 1, bytes(szl_data))
                            if parsed.get("module_type"):
                                module_name = parsed["module_type"]
                    except Exception as e:
                        self.logger.debug("scan slots SZL 0x001C failed: %s", e)

                # Build detailed info
                info["order_code"] = hw_order_code or module_name or "Unknown"
                info["module_name"] = module_name
                info["hw_order_code"] = hw_order_code
                info["firmware"] = fw_version or "?"
                info["series"] = self._identify_series_from_order_code(
                    hw_order_code or module_name or ""
                )

                # Build display string - lookup device name from order code
                device_name = lookup_device_name(hw_order_code) if hw_order_code else None
                if device_name:
                    display_str = f"{device_name} ({hw_order_code})"
                elif hw_order_code and module_name:
                    display_str = f"{module_name} ({hw_order_code})"
                elif hw_order_code:
                    display_str = hw_order_code
                elif module_name:
                    display_str = module_name
                else:
                    display_str = "Unknown"

                series = info.get("series", "S7")
                fw_str = info.get("firmware", "?")
                if bootloader_version:
                    version_str = f"FW:{fw_str} BL:{bootloader_version}"
                else:
                    version_str = fw_str
                status_str = f" ({plc_status})" if plc_status else ""
                msg = f"Rack {rack} Slot {slot}: {series} - "
                msg += f"{display_str} [{version_str}]{status_str}"
            else:
                # Simplified info for Phase 2
                info["order_code"] = hw_order_code or module_name or "Unknown"
                info["firmware"] = fw_version or "?"
                info["series"] = self._identify_series_from_order_code(info["order_code"])

                msg = f"Rack {rack} Slot {slot}: {info['series']} - "
                msg += f"{info['order_code']} [{info['firmware']}]"

            self.logger.success(msg)
            client.disconnect()
            return info

        except Exception as e:
            self.logger.debug(f"Slot {slot}: {e}")
            return None

    def scan_slots(self, host: str, port: int) -> List[Dict[str, Any]]:
        """Scan all rack/slot combinations to find S7 PLCs"""
        from ..scanner import _suppress_snap7_logging, _identify_main_slot

        found = []

        # Slot configurations based on PLC series:
        # S7-1200/1500: rack 0, slots 0-1 (integrated CPU)
        # S7-300/400: rack 0, slots 2-11 (modular, CPU typically slot 2)
        # S7-400H (redundant): rack 0 and rack 1
        #
        # OPTIMIZATION: Scan S7-1200/1500 slots first (most common)
        # If found, skip S7-300/400 slots to save ~20 seconds
        slots_phase1 = [
            (0, 1),  # S7-1200/1500 default
            (0, 0),  # S7-1200/1500 alternate / CP slot
        ]
        slots_phase2 = [
            (0, 2),  # S7-300/400 CPU default
            (0, 3),  # S7-300/400 extended
            (0, 4),  # S7-300/400 extended
            (0, 5),  # S7-300/400 extended
            (0, 6),  # S7-300/400 extended
            (0, 7),  # S7-300/400 extended
            (1, 2),  # Rack 1 for redundant/multi-rack systems
            (1, 3),  # Rack 1 extended
        ]

        import time

        with _suppress_snap7_logging():
            # Phase 1: Check S7-1200/1500 slots (fast - only 2 slots)
            self.logger.debug("Phase 1: scanning S7-1200/1500 slots...")
            found_modern_plc = False
            for rack, slot in slots_phase1:
                info = self._scan_single_slot(host, port, rack, slot, detailed=True)
                if info:
                    found.append(info)
                    series = info.get("series", "")
                    if series in ("S7-1200", "S7-1500"):
                        found_modern_plc = True
                    time.sleep(0.1)

            # Phase 2: Only scan S7-300/400 slots if no S7-1200/1500 found
            # This saves ~20 seconds of timeout delays on modern PLCs
            # Use --full-scan to force scanning all slots
            full_scan = self.args.get("full-scan", False) or self.args.get("full_scan", False)
            self.logger.debug(
                "Phase 1 complete: %d slot(s) found, modern_plc=%s", len(found), found_modern_plc
            )
            if full_scan or (not found_modern_plc and not found):
                self.logger.debug("Phase 2: scanning S7-300/400 slots (full_scan=%s)...", full_scan)
                for rack, slot in slots_phase2:
                    info = self._scan_single_slot(host, port, rack, slot, detailed=False)
                    if info:
                        found.append(info)
                        time.sleep(0.1)

        # Identify main CPU slot and mark it
        if found:
            main_slot = _identify_main_slot(found)
            if main_slot:
                self.logger.display(f"Main CPU: Rack {main_slot['rack']} Slot {main_slot['slot']}")

        return found
