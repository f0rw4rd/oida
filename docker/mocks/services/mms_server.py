#!/usr/bin/env python3
"""
Mock MMS (IEC 61850) Server for testing OIDA MMS scanner
"""

import asyncio
import logging
import struct
import time
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class MMSConstants:
    """MMS/IEC 61850 protocol constants"""

    # MMS PDU Types
    CONFIRMED_REQUEST = 0xA0
    CONFIRMED_RESPONSE = 0xA1
    CONFIRMED_ERROR = 0xA2
    UNCONFIRMED = 0xA3
    REJECT = 0xA4
    CANCEL_REQUEST = 0x85
    CANCEL_RESPONSE = 0x86
    CANCEL_ERROR = 0x87
    INITIATE_REQUEST = 0xA8
    INITIATE_RESPONSE = 0xA9
    INITIATE_ERROR = 0xAA
    CONCLUDE_REQUEST = 0x8B
    CONCLUDE_RESPONSE = 0x8C
    CONCLUDE_ERROR = 0x8D

    # Service Types
    READ = 0x04
    WRITE = 0x05
    GET_NAME_LIST = 0x01
    GET_VARIABLE_ACCESS_ATTRIBUTES = 0x06

    # MMS Data Types
    MMS_BOOLEAN = 0x83
    MMS_BIT_STRING = 0x84
    MMS_INTEGER = 0x85
    MMS_UNSIGNED = 0x86
    MMS_FLOATING_POINT = 0x87
    MMS_REAL = 0x88
    MMS_OCTET_STRING = 0x89
    MMS_VISIBLE_STRING = 0x8A
    MMS_GENERALIZED_TIME = 0x8B
    MMS_BINARY_TIME = 0x8C
    MMS_BCD = 0x8D
    MMS_STRUCTURE = 0xA2
    MMS_ARRAY = 0xA1


class IEC61850Server:
    """Mock IEC 61850 MMS server implementation"""

    def __init__(self, host="0.0.0.0", port=102):
        self.host = host
        self.port = port
        self.logical_devices = self._create_logical_devices()
        self.session_id = 1

    def _create_logical_devices(self) -> Dict[str, Any]:
        """Create mock IEC 61850 logical devices"""
        devices = {}

        # Main Protection Device
        devices["PROT"] = {
            "description": "Protection Device",
            "logical_nodes": {
                "LLN0": {  # Logical Node Zero
                    "description": "Logical Node Zero",
                    "data_objects": {
                        "Mod": {"type": "status", "value": "on", "description": "Mode"},
                        "Beh": {"type": "status", "value": "on", "description": "Behaviour"},
                        "Health": {"type": "status", "value": "ok", "description": "Health"},
                        "NamPlt": {
                            "type": "nameplate",
                            "value": "Protection Device",
                            "description": "Nameplate",
                        },
                    },
                },
                "XCBR1": {  # Circuit Breaker
                    "description": "Circuit Breaker 1",
                    "data_objects": {
                        "Pos": {"type": "position", "value": "on", "description": "Position"},
                        "BlkOpn": {
                            "type": "boolean",
                            "value": False,
                            "description": "Block Opening",
                        },
                        "BlkCls": {
                            "type": "boolean",
                            "value": False,
                            "description": "Block Closing",
                        },
                        "OpCnt": {
                            "type": "integer",
                            "value": 1234,
                            "description": "Operation Counter",
                        },
                    },
                },
                "XCBR2": {  # Circuit Breaker 2
                    "description": "Circuit Breaker 2",
                    "data_objects": {
                        "Pos": {"type": "position", "value": "off", "description": "Position"},
                        "BlkOpn": {
                            "type": "boolean",
                            "value": False,
                            "description": "Block Opening",
                        },
                        "BlkCls": {
                            "type": "boolean",
                            "value": False,
                            "description": "Block Closing",
                        },
                        "OpCnt": {
                            "type": "integer",
                            "value": 567,
                            "description": "Operation Counter",
                        },
                    },
                },
                "MMXU1": {  # Measurement Unit
                    "description": "Measurement Unit 1",
                    "data_objects": {
                        "TotW": {
                            "type": "float",
                            "value": 1250.5,
                            "description": "Total Active Power",
                        },
                        "TotVAr": {
                            "type": "float",
                            "value": 300.2,
                            "description": "Total Reactive Power",
                        },
                        "TotVA": {
                            "type": "float",
                            "value": 1285.8,
                            "description": "Total Apparent Power",
                        },
                        "Hz": {"type": "float", "value": 50.02, "description": "Frequency"},
                        "PPV": {
                            "type": "voltage",
                            "value": {"phsA": 230.1, "phsB": 229.8, "phsC": 230.3},
                            "description": "Phase Voltages",
                        },
                        "A": {
                            "type": "current",
                            "value": {"phsA": 5.42, "phsB": 5.38, "phsC": 5.45},
                            "description": "Phase Currents",
                        },
                    },
                },
                "PTOC1": {  # Overcurrent Protection
                    "description": "Overcurrent Protection",
                    "data_objects": {
                        "Str": {"type": "boolean", "value": False, "description": "Start"},
                        "Op": {"type": "boolean", "value": False, "description": "Operate"},
                        "TmASt": {
                            "type": "float",
                            "value": 0.5,
                            "description": "Time Multiplier Setting",
                        },
                        "TypRsCrv": {"type": "integer", "value": 1, "description": "Curve Type"},
                    },
                },
                "PDIF1": {  # Differential Protection
                    "description": "Differential Protection",
                    "data_objects": {
                        "Str": {"type": "boolean", "value": False, "description": "Start"},
                        "Op": {"type": "boolean", "value": False, "description": "Operate"},
                        "DifA": {
                            "type": "float",
                            "value": 0.15,
                            "description": "Differential Current A",
                        },
                        "RstA": {
                            "type": "float",
                            "value": 5.4,
                            "description": "Restraint Current A",
                        },
                    },
                },
            },
        }

        # Control Device
        devices["CTRL"] = {
            "description": "Control Device",
            "logical_nodes": {
                "LLN0": {
                    "description": "Logical Node Zero",
                    "data_objects": {
                        "Mod": {"type": "status", "value": "on", "description": "Mode"},
                        "Beh": {"type": "status", "value": "on", "description": "Behaviour"},
                        "Health": {"type": "status", "value": "ok", "description": "Health"},
                    },
                },
                "CSWI1": {  # Switch Controller
                    "description": "Switch Controller 1",
                    "data_objects": {
                        "Pos": {
                            "type": "position",
                            "value": "intermediate",
                            "description": "Position",
                        },
                        "OpOpn": {"type": "boolean", "value": False, "description": "Operate Open"},
                        "OpCls": {
                            "type": "boolean",
                            "value": False,
                            "description": "Operate Close",
                        },
                    },
                },
                "CILO1": {  # Interlocking
                    "description": "Interlocking",
                    "data_objects": {
                        "EnaOpn": {
                            "type": "boolean",
                            "value": True,
                            "description": "Enable Opening",
                        },
                        "EnaCls": {
                            "type": "boolean",
                            "value": True,
                            "description": "Enable Closing",
                        },
                    },
                },
            },
        }

        # Measurement Device
        devices["MU"] = {
            "description": "Measurement Unit Device",
            "logical_nodes": {
                "LLN0": {
                    "description": "Logical Node Zero",
                    "data_objects": {
                        "Mod": {"type": "status", "value": "on", "description": "Mode"},
                        "Health": {"type": "status", "value": "ok", "description": "Health"},
                    },
                },
                "MMXU1": {
                    "description": "Measurement Unit 1",
                    "data_objects": {
                        "TotW": {
                            "type": "float",
                            "value": 2150.7,
                            "description": "Total Active Power",
                        },
                        "TotVAr": {
                            "type": "float",
                            "value": 485.3,
                            "description": "Total Reactive Power",
                        },
                        "Hz": {"type": "float", "value": 49.98, "description": "Frequency"},
                    },
                },
                "MMXU2": {
                    "description": "Measurement Unit 2",
                    "data_objects": {
                        "TotW": {
                            "type": "float",
                            "value": 1875.2,
                            "description": "Total Active Power",
                        },
                        "TotVAr": {
                            "type": "float",
                            "value": 312.8,
                            "description": "Total Reactive Power",
                        },
                        "Hz": {"type": "float", "value": 50.01, "description": "Frequency"},
                    },
                },
            },
        }

        return devices

    def _simulate_values(self):
        """Simulate changing values for realistic behavior"""
        import random
        import math

        current_time = time.time()

        # Update measurement values
        for device_name, device in self.logical_devices.items():
            for ln_name, ln in device["logical_nodes"].items():
                if ln_name.startswith("MMXU"):
                    # Simulate power measurements
                    if "TotW" in ln["data_objects"]:
                        base_power = ln["data_objects"]["TotW"]["value"]
                        variation = (
                            base_power * 0.1 * math.sin(current_time * 0.05 + hash(ln_name) * 0.1)
                        )
                        noise = random.uniform(-base_power * 0.02, base_power * 0.02)
                        ln["data_objects"]["TotW"]["value"] = round(
                            base_power + variation + noise, 2
                        )

                    if "TotVAr" in ln["data_objects"]:
                        base_var = ln["data_objects"]["TotVAr"]["value"]
                        variation = (
                            base_var * 0.15 * math.cos(current_time * 0.08 + hash(ln_name) * 0.1)
                        )
                        noise = random.uniform(-base_var * 0.03, base_var * 0.03)
                        ln["data_objects"]["TotVAr"]["value"] = round(
                            base_var + variation + noise, 2
                        )

                    if "Hz" in ln["data_objects"]:
                        base_freq = 50.0
                        variation = 0.05 * math.sin(current_time * 0.1)
                        noise = random.uniform(-0.01, 0.01)
                        ln["data_objects"]["Hz"]["value"] = round(base_freq + variation + noise, 3)

                    # Simulate three-phase voltages
                    if "PPV" in ln["data_objects"]:
                        base_voltage = 230.0
                        for phase in ["phsA", "phsB", "phsC"]:
                            phase_offset = {"phsA": 0, "phsB": 2.094, "phsC": 4.189}[phase]
                            variation = 5.0 * math.sin(current_time * 0.1 + phase_offset)
                            noise = random.uniform(-1.0, 1.0)
                            ln["data_objects"]["PPV"]["value"][phase] = round(
                                base_voltage + variation + noise, 2
                            )

                    # Simulate three-phase currents
                    if "A" in ln["data_objects"]:
                        base_current = 5.4
                        for phase in ["phsA", "phsB", "phsC"]:
                            phase_offset = {"phsA": 0, "phsB": 2.094, "phsC": 4.189}[phase]
                            variation = 0.5 * math.sin(current_time * 0.1 + phase_offset)
                            noise = random.uniform(-0.1, 0.1)
                            ln["data_objects"]["A"]["value"][phase] = round(
                                base_current + variation + noise, 2
                            )

                # Simulate protection status
                if ln_name.startswith("PTOC") or ln_name.startswith("PDIF"):
                    # Occasionally trigger protection start
                    if random.random() < 0.01:  # 1% chance
                        ln["data_objects"]["Str"]["value"] = True
                    elif random.random() < 0.05:  # 5% chance to reset
                        ln["data_objects"]["Str"]["value"] = False

    def _encode_ber_length(self, length: int) -> bytes:
        """Encode BER length"""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            raise ValueError("Length too large")

    def _encode_mms_value(self, value: Any, data_type: str) -> bytes:
        """Encode MMS value"""
        if data_type == "boolean":
            return bytes([MMSConstants.MMS_BOOLEAN, 0x01, 0xFF if value else 0x00])
        elif data_type == "integer":
            value_bytes = struct.pack(">i", int(value))
            return bytes([MMSConstants.MMS_INTEGER]) + self._encode_ber_length(4) + value_bytes
        elif data_type == "float":
            value_bytes = struct.pack(">f", float(value))
            return (
                bytes([MMSConstants.MMS_FLOATING_POINT]) + self._encode_ber_length(4) + value_bytes
            )
        elif (
            data_type == "string"
            or data_type == "status"
            or data_type == "position"
            or data_type == "nameplate"
        ):
            value_str = str(value).encode("utf-8")
            return (
                bytes([MMSConstants.MMS_VISIBLE_STRING])
                + self._encode_ber_length(len(value_str))
                + value_str
            )
        elif data_type == "voltage" or data_type == "current":
            # Encode as structure with three phases
            if isinstance(value, dict):
                struct_data = b""
                for phase in ["phsA", "phsB", "phsC"]:
                    if phase in value:
                        phase_bytes = struct.pack(">f", float(value[phase]))
                        struct_data += (
                            bytes([MMSConstants.MMS_FLOATING_POINT])
                            + self._encode_ber_length(4)
                            + phase_bytes
                        )
                return (
                    bytes([MMSConstants.MMS_STRUCTURE])
                    + self._encode_ber_length(len(struct_data))
                    + struct_data
                )
            else:
                value_bytes = struct.pack(">f", float(value))
                return (
                    bytes([MMSConstants.MMS_FLOATING_POINT])
                    + self._encode_ber_length(4)
                    + value_bytes
                )
        else:
            # Default to visible string
            value_str = str(value).encode("utf-8")
            return (
                bytes([MMSConstants.MMS_VISIBLE_STRING])
                + self._encode_ber_length(len(value_str))
                + value_str
            )

    def _create_mms_response(self, request_data: bytes) -> bytes:
        """Create MMS response"""
        # Simulate data changes
        self._simulate_values()

        # Simple response with logical device list for GetNameList
        response_data = b""

        # Encode logical device names
        for device_name in self.logical_devices.keys():
            name_bytes = device_name.encode("utf-8")
            response_data += (
                bytes([MMSConstants.MMS_VISIBLE_STRING])
                + self._encode_ber_length(len(name_bytes))
                + name_bytes
            )

        # Create MMS confirmed response
        mms_header = bytes([MMSConstants.CONFIRMED_RESPONSE, 0x01, 0x00])  # Invoke ID = 0

        # Service specific response
        service_response = bytes([0x01])  # GetNameList response
        service_response += self._encode_ber_length(len(response_data))
        service_response += response_data

        full_response = (
            mms_header + self._encode_ber_length(len(service_response)) + service_response
        )

        return full_response

    async def handle_client(self, reader, writer):
        """Handle MMS client connection"""
        client_addr = writer.get_extra_info("peername")
        log.info(f"MMS client connected from {client_addr}")

        try:
            while True:
                # Read ISO 8823 session header (simplified)
                data = await reader.read(1024)
                if not data:
                    break

                log.debug(f"Received {len(data)} bytes from MMS client")

                # Create response
                response = self._create_mms_response(data)

                # Add simple session/presentation headers
                session_header = bytes([0x01, 0x00, 0x00, 0x00])  # Simplified session header
                presentation_header = bytes([0x61])  # Presentation header
                presentation_header += self._encode_ber_length(len(response))

                full_response = session_header + presentation_header + response

                writer.write(full_response)
                await writer.drain()

        except Exception as e:
            log.error(f"Error handling MMS client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            log.info(f"MMS client {client_addr} disconnected")

    async def start_server(self):
        """Start the MMS server"""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)

        log.info(f"Mock IEC 61850 MMS server started on {self.host}:{self.port}")
        log.info(f"Serving {len(self.logical_devices)} logical devices:")

        total_objects = 0
        for device_name, device in self.logical_devices.items():
            ln_count = len(device["logical_nodes"])
            obj_count = sum(len(ln["data_objects"]) for ln in device["logical_nodes"].values())
            total_objects += obj_count
            log.info(f"  {device_name}: {ln_count} logical nodes, {obj_count} data objects")

        log.info(f"Total: {total_objects} data objects available")

        async with server:
            await server.serve_forever()


async def main():
    """Start the mock MMS server"""
    server = IEC61850Server()
    await server.start_server()


if __name__ == "__main__":
    asyncio.run(main())
