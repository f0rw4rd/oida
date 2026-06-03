"""Custom cEMI handler for fast bus discovery.

Provides optimized bus scanning using cEMI frame interception
for parallel device discovery.
"""

import asyncio
from datetime import datetime
from typing import Dict, Set, List, Any, Callable, Optional, TYPE_CHECKING

from .helpers import (
    _get_cemi_classes,
    _get_xknx_classes,
    parse_bus_ranges,
)

if TYPE_CHECKING:
    from xknx import XKNX


class CustomCEMIHandler:
    """Custom cEMI handler for fast parallel bus discovery.

    Intercepts L_DATA_IND frames to detect actual device responses.
    Sends TConnect probes in batch and listens for responses from devices.
    """

    def __init__(self, xknx_instance: "XKNX", logger):
        """Initialize the handler.

        Args:
            xknx_instance: XKNX instance with active connection
            logger: ICSLogger instance for output
        """
        self.xknx = xknx_instance
        self.is_in_discovery = False
        self._original_handler = None
        self.logger = logger
        self.alive_bus_members: Set[str] = set()

    async def fast_bus_discovery(
        self,
        bus_range: str,
        callback: Optional[Callable[[str], None]] = None,
        timeout: int = 5,
        listen_time: int = 0,
    ) -> Dict[str, Any]:
        """Perform fast parallel bus discovery using cEMI frame interception.

        Sends TConnect telegrams in batch and listens for L_DATA_IND responses
        from actual devices on the bus. Optionally captures group traffic in parallel.

        Args:
            bus_range: Address range to scan (e.g., "1.1.1-1.1.255")
            callback: Optional callback for each found device
            timeout: Seconds to wait for responses (default: 5)
            listen_time: Additional seconds to listen for traffic after scan (0 = disabled)

        Returns:
            Dict with 'devices' (set) and 'traffic' (list of telegrams)
        """
        self.logger.debug(
            f"fast_bus_discovery: range={bus_range}, timeout={timeout}s, listen={listen_time}s"
        )
        self.alive_bus_members.clear()

        # Get required classes
        _, CEMIFrame, CEMIMessageCode = _get_cemi_classes()
        _, _, _, _, _, Telegram, _, tpci = _get_xknx_classes()

        self.is_in_discovery = True
        found_devices: Set[str] = set()
        pending_probes: Set[str] = set()
        captured_traffic: List[Dict[str, Any]] = []

        try:
            # Get the original cEMI handler
            original_handler = self.xknx.cemi_handler

            # Build an intercepting subclass that captures L_DATA_IND responses.
            # CEMIHandler uses __slots__, so we can't monkey-patch instances.
            # Instead, we replace xknx.cemi_handler with a subclass instance.
            from xknx.cemi import CEMIHandler as _CEMIHandler

            class _InterceptingCEMIHandler(_CEMIHandler):
                __slots__ = ("_intercept_cb",)

                def handle_cemi_frame(self, cemi):
                    # Intercept before delegating to default behaviour
                    if self._intercept_cb is not None:
                        self._intercept_cb(cemi)
                    return super().handle_cemi_frame(cemi)

            intercepting = _InterceptingCEMIHandler(self.xknx)
            # Copy state from the original handler
            intercepting.data_secure = original_handler.data_secure
            intercepting._l_data_confirmation_event = original_handler._l_data_confirmation_event

            def _on_cemi(cemi):
                """Capture L_DATA_IND — actual device responses."""
                if self.is_in_discovery and cemi.code == CEMIMessageCode.L_DATA_IND and cemi.data:
                    src_addr = str(cemi.data.src_addr)
                    if src_addr in pending_probes and src_addr not in found_devices:
                        found_devices.add(src_addr)
                        self.alive_bus_members.add(src_addr)
                        if callback:
                            callback(src_addr)
                        self.logger.success(f"Found device: {src_addr}")

            intercepting._intercept_cb = _on_cemi

            # Swap in the intercepting handler
            self.xknx.cemi_handler = intercepting
            self.logger.debug("Installed intercepting cEMI handler for L_DATA_IND interception")

            # Register telegram callback for group traffic (parallel capture)
            async def capture_telegram(telegram):
                if telegram.destination_address:
                    src = str(telegram.source_address)
                    dst = str(telegram.destination_address)
                    # Skip our own probes (individual addresses we're scanning)
                    if src not in pending_probes:
                        tg_info = {
                            "source": src,
                            "destination": dst,
                            "payload": str(telegram.payload) if telegram.payload else "",
                            "timestamp": datetime.now().isoformat(),
                        }
                        captured_traffic.append(tg_info)
                        payload_str = tg_info["payload"][:30] if tg_info["payload"] else ""
                        self.logger.success(f"  {src} -> {dst}  {payload_str}")

            self.xknx.telegram_queue.register_telegram_received_cb(capture_telegram)

            # Parse and send probes
            addresses = list(parse_bus_ranges(bus_range))
            total = len(addresses)
            self.logger.debug(f"Sending TConnect probes to {total} addresses")

            self.logger.display(f"Fast scanning {total} addresses...")

            # Batch send TConnect telegrams to all addresses
            for addr in addresses:
                try:
                    pending_probes.add(str(addr))
                    telegram = Telegram(
                        destination_address=addr,
                        source_address=self.xknx.current_address,
                        tpci=tpci.TConnect(),
                    )
                    await intercepting.send_telegram(telegram)
                except Exception as e:
                    self.logger.debug(f"Error sending TConnect to {addr}: {e}")

            # Wait for responses (scan phase)
            self.logger.debug(f"All probes sent, waiting {timeout}s for responses")
            await asyncio.sleep(timeout)

            self.logger.debug(f"Response phase complete: {len(found_devices)} devices responded")
            self.logger.display(f"Scan complete: {len(found_devices)}/{total} devices found")

            # Continue listening for additional traffic if requested
            if listen_time > 0:
                self.logger.display(f"Listening for traffic ({listen_time}s)...")
                await asyncio.sleep(listen_time)

            # Summary
            if captured_traffic:
                unique_sources = set(t["source"] for t in captured_traffic)
                unique_groups = set(t["destination"] for t in captured_traffic)
                self.logger.display(
                    f"Captured {len(captured_traffic)} telegrams from "
                    f"{len(unique_sources)} devices to {len(unique_groups)} groups"
                )

        except Exception as e:
            self.logger.fail(f"Error in fast bus discovery: {e}")
        finally:
            # ALWAYS restore the original cEMI handler — previously the
            # restoration was inside the try block, so any exception
            # during the scan (interrupt, network error, parse error)
            # left xknx permanently hooked into our intercepting
            # handler. The next protocol invocation in the same process
            # then crashed on stale callbacks.
            try:
                self.xknx.cemi_handler = original_handler
                self.logger.debug("Restored original cEMI handler")
            except Exception as restore_err:
                self.logger.debug(f"cEMI handler restore failed: {restore_err}")
            self.is_in_discovery = False

        return {"devices": found_devices, "traffic": captured_traffic}
