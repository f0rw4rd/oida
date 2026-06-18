#!/usr/bin/env python3
"""
Mock MMS/IEC 61850 Server using existing libiec61850 framework
"""

import logging
import time
import threading
import random
import math

try:
    import libiec61850

    HAS_LIBIEC61850 = True
except ImportError:
    try:
        # Alternative import structure
        from libiec61850 import server as iec61850_server
        from libiec61850 import model as iec61850_model

        HAS_LIBIEC61850 = True
    except ImportError:
        HAS_LIBIEC61850 = False

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class MockMMSServerFramework:
    """Mock MMS/IEC 61850 server using existing frameworks"""

    def __init__(self, host="0.0.0.0", port=102):
        self.host = host
        self.port = port
        self.running = False

    def start_server_libiec61850(self):
        """Start server using libiec61850 framework"""
        log.info("Starting MMS/IEC 61850 server with libiec61850 framework")

        # Create IED model
        ied_model = libiec61850.IedModel_create("MSF_ICS_MOCK")

        # Create logical devices
        logical_device_prot = libiec61850.LogicalDevice_create("PROT", ied_model)
        logical_device_ctrl = libiec61850.LogicalDevice_create("CTRL", ied_model)
        logical_device_meas = libiec61850.LogicalDevice_create("MEAS", ied_model)

        # Add logical nodes to PROT device
        lln0_prot = libiec61850.LogicalNode_create("LLN0", logical_device_prot)
        xcbr1 = libiec61850.LogicalNode_create("XCBR1", logical_device_prot)
        xcbr2 = libiec61850.LogicalNode_create("XCBR2", logical_device_prot)
        mmxu1 = libiec61850.LogicalNode_create("MMXU1", logical_device_prot)
        ptoc1 = libiec61850.LogicalNode_create("PTOC1", logical_device_prot)

        # Add data objects to LLN0
        libiec61850.DataObject_create("Mod", lln0_prot, libiec61850.IEC61850_FC_CO)
        libiec61850.DataObject_create("Beh", lln0_prot, libiec61850.IEC61850_FC_ST)
        libiec61850.DataObject_create("Health", lln0_prot, libiec61850.IEC61850_FC_ST)

        # Add data objects to XCBR1 (Circuit Breaker)
        libiec61850.DataObject_create("Pos", xcbr1, libiec61850.IEC61850_FC_ST)
        libiec61850.DataObject_create("BlkOpn", xcbr1, libiec61850.IEC61850_FC_BL)
        libiec61850.DataObject_create("BlkCls", xcbr1, libiec61850.IEC61850_FC_BL)
        libiec61850.DataObject_create("OpCnt", xcbr1, libiec61850.IEC61850_FC_ST)

        # Add data objects to MMXU1 (Measurements)
        libiec61850.DataObject_create("TotW", mmxu1, libiec61850.IEC61850_FC_MX)
        libiec61850.DataObject_create("TotVAr", mmxu1, libiec61850.IEC61850_FC_MX)
        libiec61850.DataObject_create("TotVA", mmxu1, libiec61850.IEC61850_FC_MX)
        libiec61850.DataObject_create("Hz", mmxu1, libiec61850.IEC61850_FC_MX)
        libiec61850.DataObject_create("PPV", mmxu1, libiec61850.IEC61850_FC_MX)
        libiec61850.DataObject_create("A", mmxu1, libiec61850.IEC61850_FC_MX)

        # Add data objects to PTOC1 (Protection)
        libiec61850.DataObject_create("Str", ptoc1, libiec61850.IEC61850_FC_ST)
        libiec61850.DataObject_create("Op", ptoc1, libiec61850.IEC61850_FC_ST)
        libiec61850.DataObject_create("TmASt", ptoc1, libiec61850.IEC61850_FC_SE)

        # Create server
        ied_server = libiec61850.IedServer_create(ied_model)

        # Set server configuration
        libiec61850.IedServer_setLocalIpAddress(ied_server, self.host)

        # Start server
        libiec61850.IedServer_start(ied_server, self.port)

        if not libiec61850.IedServer_isRunning(ied_server):
            log.error("Failed to start IEC 61850 server!")
            return

        log.info(f"IEC 61850 MMS server running on {self.host}:{self.port}")

        # Start simulation thread
        def simulation_loop():
            counter = 0
            while self.running:
                try:
                    counter += 1
                    current_time = time.time()

                    # Update power measurements
                    power_variation = (
                        1250.0 + 200.0 * math.sin(current_time * 0.1) + random.uniform(-50, 50)
                    )
                    var_variation = (
                        300.0 + 50.0 * math.cos(current_time * 0.08) + random.uniform(-20, 20)
                    )
                    frequency = (
                        50.0 + 0.05 * math.sin(current_time * 0.05) + random.uniform(-0.01, 0.01)
                    )

                    # Update data attributes
                    libiec61850.IedServer_updateFloatAttributeValue(
                        ied_server,
                        libiec61850.ModelNode_getReference(
                            libiec61850.IedModel_getModelNodeByReference(
                                ied_model, "PROT/MMXU1.TotW.mag.f"
                            )
                        ),
                        power_variation,
                    )

                    libiec61850.IedServer_updateFloatAttributeValue(
                        ied_server,
                        libiec61850.ModelNode_getReference(
                            libiec61850.IedModel_getModelNodeByReference(
                                ied_model, "PROT/MMXU1.TotVAr.mag.f"
                            )
                        ),
                        var_variation,
                    )

                    libiec61850.IedServer_updateFloatAttributeValue(
                        ied_server,
                        libiec61850.ModelNode_getReference(
                            libiec61850.IedModel_getModelNodeByReference(
                                ied_model, "PROT/MMXU1.Hz.mag.f"
                            )
                        ),
                        frequency,
                    )

                    # Simulate breaker operations
                    if counter % 50 == 0:  # Every 100 seconds
                        current_pos = libiec61850.IedServer_getBooleanAttributeValue(
                            ied_server,
                            libiec61850.ModelNode_getReference(
                                libiec61850.IedModel_getModelNodeByReference(
                                    ied_model, "PROT/XCBR1.Pos.stVal"
                                )
                            ),
                        )
                        libiec61850.IedServer_updateBooleanAttributeValue(
                            ied_server,
                            libiec61850.ModelNode_getReference(
                                libiec61850.IedModel_getModelNodeByReference(
                                    ied_model, "PROT/XCBR1.Pos.stVal"
                                )
                            ),
                            not current_pos,
                        )
                        log.debug(f"Toggled XCBR1 position to {'ON' if not current_pos else 'OFF'}")

                    # Simulate protection activation
                    if power_variation > 1400.0 or frequency < 49.5 or frequency > 50.5:
                        libiec61850.IedServer_updateBooleanAttributeValue(
                            ied_server,
                            libiec61850.ModelNode_getReference(
                                libiec61850.IedModel_getModelNodeByReference(
                                    ied_model, "PROT/PTOC1.Str.stVal"
                                )
                            ),
                            True,
                        )
                    else:
                        libiec61850.IedServer_updateBooleanAttributeValue(
                            ied_server,
                            libiec61850.ModelNode_getReference(
                                libiec61850.IedModel_getModelNodeByReference(
                                    ied_model, "PROT/PTOC1.Str.stVal"
                                )
                            ),
                            False,
                        )

                    time.sleep(2)

                except Exception as e:
                    log.debug(f"Simulation error: {e}")
                    time.sleep(5)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        log.info("Started MMS data simulation")
        log.info("Available logical devices: PROT, CTRL, MEAS")
        log.info("Available data objects:")
        log.info("  PROT/LLN0.Mod, PROT/LLN0.Beh, PROT/LLN0.Health")
        log.info("  PROT/XCBR1.Pos, PROT/XCBR1.OpCnt")
        log.info("  PROT/MMXU1.TotW, PROT/MMXU1.TotVAr, PROT/MMXU1.Hz")
        log.info("  PROT/PTOC1.Str, PROT/PTOC1.Op")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down MMS server...")
            self.running = False
            libiec61850.IedServer_stop(ied_server)
            libiec61850.IedServer_destroy(ied_server)
            libiec61850.IedModel_destroy(ied_model)

    def start_server_fallback(self):
        """Fallback to our custom implementation"""
        log.info("Starting MMS server with fallback implementation")

        # Import our custom implementation
        from mms_server import IEC61850Server

        server = IEC61850Server(self.host, self.port)

        # Start simulation
        def simulation_loop():
            while self.running:
                server._simulate_values()
                time.sleep(2)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        # Start server (this will block)
        import asyncio

        asyncio.run(server.start_server())

    def start(self):
        """Start the server using the best available framework"""
        if HAS_LIBIEC61850:
            try:
                self.start_server_libiec61850()
            except Exception as e:
                log.warning(f"libiec61850 failed: {e}, falling back to custom implementation")
                self.start_server_fallback()
        else:
            log.warning("libiec61850 not available, using fallback implementation")
            self.start_server_fallback()


def main():
    """Start the mock MMS server"""
    server = MockMMSServerFramework()
    server.start()


if __name__ == "__main__":
    main()
