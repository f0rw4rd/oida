#!/usr/bin/env python3
"""
Real CANopen slave node for testing OIDA's `oida can --canopen-*` scanner.

Unlike the legacy can_server.py (a hand-rolled UDP-multicast SIMULATION of
CANopen frames), this runs a GENUINE CANopen device using the python-canopen
stack (canopen.LocalNode) on a real SocketCAN virtual bus (vcan0). The node
brings up its own heartbeat producer and SDO server, answering standard
CiA-301 SDO uploads of the Object Dictionary -- in particular the identity
objects the OIDA scanner fingerprints:

  0x1000  Device Type        (UNSIGNED32, profile in low word)
  0x1001  Error Register     (UNSIGNED8)
  0x1008  Device Name        (VISIBLE_STRING)
  0x1009  HW Version         (VISIBLE_STRING)
  0x100A  SW Version         (VISIBLE_STRING)
  0x1017  Producer Heartbeat (UNSIGNED16, ms)
  0x1018  Identity Object    (RECORD: vendor / product / revision / serial)

The device profile, node-ID and identity are fully env-driven so several
distinct nodes (e.g. a CiA-401 generic-I/O node and a CiA-402 motion node)
can share one bus from separate containers / processes.

Wire layer (CiA-301, what the scanner expects):
  heartbeat   COB-ID 0x700 + node_id
  SDO server  RX 0x600 + node_id (client->server), TX 0x580 + node_id

Dependencies: canopen (MIT), python-can (LGPL-3.0).

Usage:
  python canopen_node.py            # config from CANOPEN_* env vars
  CANOPEN_NODE_ID=4 CANOPEN_PROFILE=402 python canopen_node.py
"""

import logging
import os
import signal
import sys
import time

import canopen
from canopen.objectdictionary import ObjectDictionary, Record, Variable
from canopen.objectdictionary import datatypes as DT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("canopen-node")


def _env_int(name: str, default: int) -> int:
    """Parse an int env var accepting decimal or 0x-prefixed hex."""
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return int(val.strip(), 0)


def _ro(index: int, sub: int, data_type: int, value, name: str) -> Variable:
    """Build a read-only OD Variable with a constant value."""
    v = Variable(name, index, sub)
    v.data_type = data_type
    v.access_type = "ro"
    v.value = value
    return v


def build_od() -> ObjectDictionary:
    """
    Construct the Object Dictionary from CANOPEN_* environment variables.

    Profile number (CANOPEN_PROFILE, e.g. 401 / 402) lands in the low 16 bits
    of 0x1000 Device Type; the OIDA scanner maps 401 -> "Generic I/O Modules
    (CiA 401)" and 402 -> "Drives and Motion Control (CiA 402)".
    """
    profile = _env_int("CANOPEN_PROFILE", 401)
    add_info = _env_int("CANOPEN_DEVICE_TYPE_HI", 0x0000)
    device_type = ((add_info & 0xFFFF) << 16) | (profile & 0xFFFF)

    vendor_id = _env_int("CANOPEN_VENDOR_ID", 0x000002AA)
    product_code = _env_int("CANOPEN_PRODUCT_CODE", profile)
    revision = _env_int("CANOPEN_REVISION", 0x00010000)  # v1.0
    serial = _env_int("CANOPEN_SERIAL", 0x00000001)

    device_name = os.environ.get("CANOPEN_DEVICE_NAME", f"OIDA-CANopen-{profile}")
    hw_version = os.environ.get("CANOPEN_HW_VERSION", "HW-1.0")
    sw_version = os.environ.get("CANOPEN_SW_VERSION", "SW-1.0.0")
    err_register = _env_int("CANOPEN_ERROR_REGISTER", 0x00)
    heartbeat_ms = _env_int("CANOPEN_HEARTBEAT_MS", 1000)

    od = ObjectDictionary()

    # --- Mandatory CiA-301 communication objects ---
    od.add_object(_ro(0x1000, 0, DT.UNSIGNED32, device_type, "Device type"))
    od.add_object(_ro(0x1001, 0, DT.UNSIGNED8, err_register, "Error register"))
    od.add_object(_ro(0x1008, 0, DT.VISIBLE_STRING, device_name, "Manufacturer device name"))
    od.add_object(_ro(0x1009, 0, DT.VISIBLE_STRING, hw_version, "Manufacturer hardware version"))
    od.add_object(_ro(0x100A, 0, DT.VISIBLE_STRING, sw_version, "Manufacturer software version"))

    # Producer heartbeat time (ms). LocalNode reads this to drive its producer.
    hb = _ro(0x1017, 0, DT.UNSIGNED16, heartbeat_ms, "Producer heartbeat time")
    hb.access_type = "rw"
    od.add_object(hb)

    # --- Identity Object 0x1018 (the headline fingerprint record) ---
    ident = Record("Identity object", 0x1018)
    ident.add_member(_ro(0x1018, 0, DT.UNSIGNED8, 4, "Highest sub-index supported"))
    ident.add_member(_ro(0x1018, 1, DT.UNSIGNED32, vendor_id, "Vendor-ID"))
    ident.add_member(_ro(0x1018, 2, DT.UNSIGNED32, product_code, "Product code"))
    ident.add_member(_ro(0x1018, 3, DT.UNSIGNED32, revision, "Revision number"))
    ident.add_member(_ro(0x1018, 4, DT.UNSIGNED32, serial, "Serial number"))
    od.add_object(ident)

    # --- A profile-specific OD entry so the two configs differ on OD-scan ---
    # CiA-401: 0x6000 read digital input 8-bit array (generic I/O)
    # CiA-402: 0x6041 statusword / 0x6064 position actual value (motion)
    if profile == 402:
        od.add_object(_ro(0x6040, 0, DT.UNSIGNED16, 0x0006, "Controlword"))
        od.add_object(_ro(0x6041, 0, DT.UNSIGNED16, 0x0231, "Statusword"))
        od.add_object(_ro(0x6064, 0, DT.INTEGER32, 0x00000000, "Position actual value"))
        od.add_object(_ro(0x6502, 0, DT.UNSIGNED32, 0x000003A4, "Supported drive modes"))
    else:
        rec = Record("Read input 8-bit", 0x6000)
        rec.add_member(_ro(0x6000, 0, DT.UNSIGNED8, 1, "Number of input 8-bit"))
        rec.add_member(_ro(0x6000, 1, DT.UNSIGNED8, 0xA5, "Read input 8-bit 1"))
        od.add_object(rec)
        wrec = Record("Write output 8-bit", 0x6200)
        wrec.add_member(_ro(0x6200, 0, DT.UNSIGNED8, 1, "Number of output 8-bit"))
        wm = _ro(0x6200, 1, DT.UNSIGNED8, 0x00, "Write output 8-bit 1")
        wm.access_type = "rw"
        wrec.add_member(wm)
        od.add_object(wrec)

    return od


def main() -> int:
    node_id = _env_int("CANOPEN_NODE_ID", 1)
    channel = os.environ.get("CANOPEN_CHANNEL", "vcan0")
    interface = os.environ.get("CANOPEN_INTERFACE", "socketcan")
    profile = _env_int("CANOPEN_PROFILE", 401)

    od = build_od()

    network = canopen.Network()
    log.info("Connecting to %s on %s ...", interface, channel)
    network.connect(interface=interface, channel=channel)

    node = canopen.LocalNode(node_id, od)
    network.add_node(node)

    # Bring the slave up the proper CiA-301 way so the heartbeat PRODUCER
    # actually starts. canopen.NmtSlave only spins up the periodic 0x700+id
    # transmit task on the INITIALISING -> PRE-OPERATIONAL transition driven
    # by send_command() (NMT code 0x80); simply assigning nmt.state does NOT
    # start it. So: boot-up (sends 0x700+id [0]) -> pre-op (starts heartbeat
    # from 0x1017) -> operational.
    heartbeat_ms = od[0x1017].value
    node.nmt.send_command(0x80)  # enter PRE-OPERATIONAL -> start_heartbeat()
    # Belt-and-suspenders: ensure the producer is running at the OD-configured
    # interval even if the OD default for 0x1017 differs.
    if heartbeat_ms and node.nmt._send_task is None:
        node.nmt.start_heartbeat(heartbeat_ms)
    node.nmt.state = "OPERATIONAL"
    node.nmt.update_heartbeat()  # reflect the new state byte in the producer

    dev_type = od[0x1000].value if hasattr(od[0x1000], "value") else None
    log.info(
        "CANopen node UP: node-id=%d (0x%02X) profile=CiA-%d device-type=0x%08X name=%r vcan=%s",
        node_id,
        node_id,
        profile,
        dev_type or 0,
        od[0x1008].value,
        channel,
    )
    log.info(
        "  heartbeat COB-ID=0x%03X  SDO-RX=0x%03X  SDO-TX=0x%03X  state=OPERATIONAL",
        0x700 + node_id,
        0x600 + node_id,
        0x580 + node_id,
    )

    running = {"on": True}

    def _stop(signum, frame):
        log.info("Signal %d received, shutting down node %d", signum, node_id)
        running["on"] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        while running["on"]:
            time.sleep(0.5)
    finally:
        try:
            node.nmt.state = "STOPPED"
        except Exception:
            pass
        network.disconnect()
        log.info("Node %d disconnected", node_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
