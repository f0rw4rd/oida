"""
BACnet Connection Mixin

Handles BAC0 and bacpypes3 connection lifecycle.
"""

import asyncio

from ..constants import _get_bac0


class ConnectionMixin:
    """Mixin providing BACnet connection lifecycle operations."""

    def create_conn_obj(self) -> bool:
        """Initialize BAC0 BACnet connection (sync wrapper)"""
        # This is called by base class, but we use async version
        return True

    async def _async_create_conn_obj(self) -> bool:
        """Initialize BAC0 BACnet connection (async)"""
        try:
            # Silence BAC0 logging
            BAC0 = _get_bac0()
            BAC0.log_level("silence")

            # Get network configuration
            interface = getattr(self.args, "interface", None)
            bbmd = getattr(self.args, "bbmd", None)

            # Build connection kwargs
            kwargs = {}
            if interface:
                kwargs["localIPAddr"] = interface
            if bbmd:
                # Parse BBMD address (IP:PORT format)
                if ":" in bbmd:
                    bbmd_ip, bbmd_port = bbmd.rsplit(":", 1)
                    kwargs["bbmdAddress"] = bbmd_ip
                    kwargs["bbmdTTL"] = 30
                else:
                    kwargs["bbmdAddress"] = bbmd
                    kwargs["bbmdTTL"] = 30

            # Connect to BACnet network
            self.logger.display("Connecting to BACnet network...")
            self.bacnet = BAC0.lite(**kwargs)

            # Give BAC0 time to initialize
            await asyncio.sleep(0.5)

            self.logger.success(f"Connected via {self.bacnet.localIPAddr}")
            return True

        except Exception as e:
            self.logger.debug(f"async create conn obj failed: {e}")
            self.logger.fail(f"Failed to connect to BACnet network: {e}")
            return False

    def _disconnect(self):
        """Disconnect from BACnet network"""
        if self.bacnet:
            try:
                self.bacnet.disconnect()
                self.logger.debug("Disconnected from BACnet network")
            except Exception as e:
                self.logger.debug(f"Disconnect error: {e}")
