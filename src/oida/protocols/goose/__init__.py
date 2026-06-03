#!/usr/bin/env python3
"""
GOOSE (Generic Object Oriented Substation Event) Protocol Scanner

Passive GOOSE message capture and GoCB (GOOSE Control Block) enumerator via MMS.

Uses pyiec61850-ng >= 1.6.1.0 high-level Python API:
  - GooseSubscriber for GOOSE message capture
  - MMSClient + GoCBClient for MMS GoCB enumeration

Requires: pip install 'pyiec61850-ng>=1.6.1.0'
"""

import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

from ...utils import (
    SecurityAnalyzer,
    create_protocol_module,
    parse_bool,
    register_protocol,
    safe_int_conversion,
)
from ...utils.base_scanner import SerialScanner
from ...utils.lazy_import import lazy_import

import logging

logger = logging.getLogger(__name__)


# Lazy imports for pyiec61850-ng (only loaded when actually used)
_pyiec61850_goose = lazy_import(
    "pyiec61850.goose", "GOOSE", install_hint="pip install pyiec61850-ng"
)
_pyiec61850_mms = lazy_import("pyiec61850.mms", "GOOSE", install_hint="pip install pyiec61850-ng")
_pyiec61850_raw = lazy_import(
    "pyiec61850.pyiec61850", "GOOSE", install_hint="pip install pyiec61850-ng"
)


# GOOSE EtherType constant
GOOSE_ETHERTYPE = 0x88B8

# Default GOOSE multicast MAC prefix (01-0C-CD-01-xx-xx)
GOOSE_MULTICAST_PREFIX = bytes([0x01, 0x0C, 0xCD, 0x01])


protocol_options = {
    "timeout": {
        "type": "int",
        "description": "Capture/listen timeout in seconds",
        "required": False,
        "default": 10,
    },
    "gocb-ref": {
        "type": "string",
        "description": "GOOSE Control Block reference for capture (e.g., 'myLD/LLN0$GO$gcb01')",
        "required": False,
        "default": "",
    },
    "appid": {
        "type": "int",
        "description": "Filter by GOOSE Application ID",
        "required": False,
        "default": None,
    },
    "rgoose": {
        "type": "bool",
        "description": "Enable R-GOOSE (routable GOOSE over UDP) mode",
        "required": False,
        "default": False,
    },
    "rgoose-port": {
        "type": "int",
        "description": "R-GOOSE UDP port (required when rgoose is enabled)",
        "required": False,
        "default": None,
    },
    "rgoose-auth": {
        "type": "bool",
        "description": "Enable R-GOOSE authentication per IEC 62351-6",
        "required": False,
        "default": False,
    },
    "rgoose-key": {
        "type": "string",
        "description": "Path to R-GOOSE authentication key file (IEC 62351-6)",
        "required": False,
        "default": None,
    },
    "mms-enum": {
        "type": "string",
        "description": "Enumerate GoCBs via MMS connection to target IP",
        "required": False,
        "default": "",
    },
    "mms-port": {
        "type": "int",
        "description": "MMS port for GoCB enumeration",
        "required": False,
        "default": 102,
    },
}


@register_protocol(
    name="GOOSE Scanner",
    description="""IEC 61850 GOOSE protocol passive scanner and GoCB enumerator""",
    default_port=0,
    authors=["f0rw4rd"],
    references=[
        {
            "type": "url",
            "ref": "https://en.wikipedia.org/wiki/Generic_Object_Oriented_Substation_Event",
        }
    ],
    protocol_options=protocol_options,
    protocol_type="serial",
)
class GOOSEScanner(SerialScanner):
    """IEC 61850 GOOSE Scanner implementing the base scanner interface.

    Supports three operating modes:
    1. GOOSE capture on a network interface (requires gocb-ref)
    2. R-GOOSE listening over UDP (not yet supported in high-level API)
    3. GoCB enumeration via MMS connection
    """

    def __init__(self, args: Dict[str, Any]):
        # Set interface from target before super().__init__
        if not args.get("interface"):
            args["interface"] = args.get("rhost", args.get("host", "eth0"))

        super().__init__(args)

        self.capture_timeout = safe_int_conversion(args.get("timeout"), 10)
        self.gocb_ref = args.get("gocb-ref", "")
        self.appid_filter = args.get("appid")
        if self.appid_filter is not None:
            self.appid_filter = safe_int_conversion(self.appid_filter, None)
        self.rgoose_mode = parse_bool(args.get("rgoose", False))
        self.rgoose_port = safe_int_conversion(args.get("rgoose-port"), None)
        self.rgoose_auth = parse_bool(args.get("rgoose-auth", False))
        self.rgoose_key = args.get("rgoose-key")
        self.mms_enum_target = args.get("mms-enum", "")
        self.mms_port = safe_int_conversion(args.get("mms-port"), 102)

        # Discovered GOOSE messages
        self.discovered_messages = []
        self.goose_sources = {}  # MAC -> list of messages
        self.gocb_info = []  # GoCB enumeration results
        self.security_findings = []

        # Active GooseSubscriber for cleanup
        self._goose_subscriber = None

    def get_protocol_name(self) -> str:
        return "IEC 61850 GOOSE"

    def get_default_port(self) -> int:
        return 0  # Layer 2 protocol

    def check_dependencies(self) -> bool:
        """Check if pyiec61850-ng is available."""
        return _pyiec61850_goose.is_available

    def connect(self) -> Any:
        """Create GOOSE capture config or MMS connection depending on mode."""
        _pyiec61850_goose()  # trigger DependencyError if missing

        if self.mms_enum_target:
            self.logger.debug(
                f"Mode: MMS GoCB enumeration -> {self.mms_enum_target}:{self.mms_port}"
            )
            return self._connect_mms(self.mms_enum_target, self.mms_port)
        elif self.rgoose_mode:
            self.logger.fail(
                "R-GOOSE mode not yet supported in the high-level API. "
                "R-GOOSE support will be added when pyiec61850-ng provides a wrapper."
            )
            return None
        else:
            self.logger.debug(f"Mode: GOOSE capture on interface {self.interface}")
            return self._create_goose_connection()

    def _create_goose_connection(self) -> Any:
        """Prepare GOOSE capture connection config.

        The actual GooseSubscriber is created in _capture_goose() since it
        needs to be started and stopped within the capture window.
        """
        _pyiec61850_goose()  # trigger DependencyError if missing

        if not self.gocb_ref:
            self.logger.fail(
                "gocb-ref required for GOOSE capture. "
                "Use --gocb-ref 'LD/LLN0$GO$gcbName' to specify the GoCB reference. "
                "Use --mms-enum <ip> to discover GoCB references first."
            )
            return None

        self.logger.debug(
            f"GOOSE capture config: interface={self.interface}, gocb_ref={self.gocb_ref}"
        )
        return {
            "type": "goose_receiver",
            "interface": self.interface,
            "gocb_ref": self.gocb_ref,
        }

    def _connect_mms(self, host: str, port: int) -> Any:
        """Create an MMS connection using the high-level MMSClient."""
        try:
            self.logger.debug(f"Connecting MMSClient to {host}:{port}")
            client = _pyiec61850_mms.MMSClient()
            connected = client.connect(host, port)

            if not connected:
                self.logger.fail(f"MMSClient.connect returned False for {host}:{port}")
                return None

            self.logger.success(f"Connected to IEC 61850 server at {host}:{port}")
            return {
                "type": "mms_connection",
                "client": client,
                "host": host,
                "port": port,
            }

        except Exception as e:
            self.logger.fail(f"Failed to create MMS connection: {e}")
            return None

    def disconnect(self, connection: Any) -> None:
        """Close GOOSE subscriber or MMS connection."""
        if connection is None:
            return

        conn_type = connection.get("type", "")
        self.logger.debug(f"Disconnecting {conn_type}")

        try:
            if conn_type == "goose_receiver":
                if self._goose_subscriber:
                    try:
                        self._goose_subscriber.stop()
                        self.logger.debug("GooseSubscriber stopped")
                    except Exception as e:
                        self.logger.debug(f"GooseSubscriber stop error: {e}")
                    self._goose_subscriber = None

            elif conn_type == "mms_connection":
                client = connection.get("client")
                if client:
                    try:
                        client.disconnect()
                        self.logger.debug("MMSClient disconnected")
                    except Exception as e:
                        self.logger.debug(f"MMSClient disconnect error: {e}")

        except Exception as e:
            self.logger.debug(f"Unexpected error during disconnect: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform GOOSE discovery based on operating mode."""
        results = {
            "goose_messages": [],
            "goose_sources": {},
            "gocb_info": [],
            "security_analysis": {},
        }

        try:
            conn_type = connection.get("type", "")
            self.logger.debug(f"Starting discovery, connection type: {conn_type}")

            if conn_type == "goose_receiver":
                results["goose_messages"] = self._capture_goose(connection)
                results["goose_sources"] = dict(self.goose_sources)

            elif conn_type == "mms_connection":
                results["gocb_info"] = self._enumerate_gocbs(connection)

            results["security_analysis"] = self._analyze_security(results)
            self._report_findings(results)

        except Exception as e:
            self.logger.fail(f"Error during GOOSE discovery: {e}")
            results["error"] = str(e)

        return results

    def _capture_goose(self, connection: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Capture GOOSE messages using the high-level GooseSubscriber API.

        Creates a GooseSubscriber with a listener callback that collects
        GooseMessage objects into a list for the configured timeout.
        """
        interface = connection.get("interface", self.interface)
        gocb_ref = connection.get("gocb_ref", self.gocb_ref)

        if not gocb_ref:
            self.logger.fail("No gocb-ref specified for GOOSE capture")
            return []

        messages: List[Dict[str, Any]] = []
        seen_gocbs: set = set()

        def on_message(msg):
            """Callback invoked by GooseSubscriber for each received GOOSE message."""
            try:
                # Extract src_mac from the raw subscriber before converting.
                # GooseSubscriber_getSrcMac fills a 6-byte buffer with the
                # source MAC of the last received frame.
                try:
                    if sub._subscriber is not None:
                        mac_buf = bytearray(6)
                        _pyiec61850_raw.GooseSubscriber_getSrcMac(sub._subscriber, mac_buf)
                        msg.src_mac = bytes(mac_buf)
                except Exception as e:
                    logger.debug(f"if sub._subscriber is not None:: {e}")

                msg_info = self._goose_message_to_dict(msg)
                messages.append(msg_info)

                gocb = msg_info.get("gocb_ref", "")
                is_new = gocb and gocb not in seen_gocbs
                if is_new:
                    seen_gocbs.add(gocb)
                self._display_goose_message(msg_info, is_new=is_new)

                src = msg_info.get("src_mac", "unknown")
                if src not in self.goose_sources:
                    self.goose_sources[src] = []
                self.goose_sources[src].append(msg_info)
            except Exception as e:
                self.logger.debug(f"Error processing GOOSE message in callback: {e}")

        self.logger.display(
            f"Listening for GOOSE on {interface} for GoCB '{gocb_ref}' "
            f"(timeout: {self.capture_timeout}s)..."
        )
        if self.appid_filter is not None:
            self.logger.display(f"  Filtering by AppID: 0x{self.appid_filter:04X}")

        try:
            sub = _pyiec61850_goose.GooseSubscriber(interface, gocb_ref)
            self.logger.debug(
                f"Created GooseSubscriber: interface={interface}, gocb_ref={gocb_ref}"
            )

            if self.appid_filter is not None:
                sub.set_app_id(self.appid_filter)
                self.logger.debug(f"AppID filter set to 0x{self.appid_filter:04X}")

            sub.set_listener(on_message)
            self._goose_subscriber = sub

            self.logger.debug("Starting GooseSubscriber...")
            sub.start()
            self.logger.debug(f"GooseSubscriber is_running={sub.is_running}")

            if not sub.is_running:
                self.logger.fail(
                    f"GooseSubscriber failed to start on '{interface}'. "
                    "Check: (1) interface exists, (2) running as root or CAP_NET_RAW."
                )
                self._goose_subscriber = None
                return []

            # Wait for timeout or keyboard interrupt
            start_time = time.time()
            try:
                while time.time() - start_time < self.capture_timeout:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                self.logger.display("Capture interrupted by user")

            elapsed = time.time() - start_time
            sub.stop()
            self._goose_subscriber = None
            self.logger.debug(
                f"GooseSubscriber stopped after {elapsed:.1f}s, "
                f"{len(messages)} msgs from {len(seen_gocbs)} GoCBs"
            )

        except Exception as e:
            self.logger.fail(f"GOOSE capture error: {e}")
            if self._goose_subscriber:
                try:
                    self._goose_subscriber.stop()
                except Exception as e:
                    logger.debug(f"self._goose_subscriber.stop(): {e}")
                self._goose_subscriber = None

        self.logger.display(f"Captured {len(messages)} GOOSE messages from {len(seen_gocbs)} GoCBs")
        return messages

    def _goose_message_to_dict(self, msg) -> Dict[str, Any]:
        """Convert a GooseMessage to our internal dict format."""
        info: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "transport": "GOOSE/L2",
        }

        if msg.go_cb_ref:
            info["gocb_ref"] = msg.go_cb_ref
        if msg.go_id:
            info["goose_id"] = msg.go_id
        if msg.data_set:
            info["dataset_name"] = msg.data_set

        # src_mac is set dynamically on the GooseMessage in on_message()
        src_mac = getattr(msg, "src_mac", None)
        if src_mac:
            info["src_mac"] = self._format_mac(src_mac)

        info["appid"] = msg.app_id
        info["st_num"] = msg.st_num
        info["sq_num"] = msg.sq_num
        info["conf_rev"] = msg.conf_rev
        info["valid"] = msg.is_valid
        info["needs_commission"] = msg.needs_commissioning
        info["time_allowed_to_live"] = msg.time_allowed_to_live
        info["dataset_size"] = msg.num_data_set_entries
        # IEC 61850-8-1 §A.5 GOOSE PDU 'test' boolean flag. Was never
        # populated, so _display_msg's `if msg.get("is_test"):` warning
        # and _check_test_simulation_flag's `[m for m in messages if
        # m.get("is_test")]` block were dead code. Pyiec61850 exposes
        # the field as either 'is_test' (newer) or 'test' (legacy);
        # accept both.
        is_test = getattr(msg, "is_test", None)
        if is_test is None:
            is_test = getattr(msg, "test", None)
        info["is_test"] = bool(is_test) if is_test is not None else False

        if msg.values:
            info["dataset_values"] = msg.values
        if msg.timestamp:
            info["goose_timestamp"] = msg.timestamp.isoformat()

        return info

    def _enumerate_gocbs(self, connection: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enumerate GOOSE Control Blocks using the high-level GoCBClient API.

        GoCBClient.enumerate() walks logical devices -> logical nodes -> GoCB
        directory and reads each discovered GoCB automatically.
        """
        client = connection.get("client")
        host = connection.get("host", "")
        if not client:
            return []

        self.logger.display(f"Enumerating GoCBs on {host}...")
        gocb_list = []

        try:
            gocb_client = _pyiec61850_mms.GoCBClient(client)
            gocb_infos = gocb_client.enumerate()

            self.logger.debug(f"GoCBClient.enumerate() returned {len(gocb_infos)} GoCBs")

            for info in gocb_infos:
                gocb_dict = self._gocb_info_to_dict(info)
                gocb_list.append(gocb_dict)
                self._display_gocb(gocb_dict)

        except Exception as e:
            self.logger.fail(f"GoCB enumeration error: {e}")

        self.logger.display(f"Discovered {len(gocb_list)} GOOSE Control Blocks")
        self.gocb_info = gocb_list
        return gocb_list

    def _gocb_info_to_dict(self, info) -> Dict[str, Any]:
        """Convert a GoCBInfo dataclass to our internal dict format."""
        d: Dict[str, Any] = {"gocb_ref": info.gocb_ref}

        if info.goose_id:
            d["goose_id"] = info.goose_id
        if info.dataset:
            d["dataset"] = info.dataset

        d["enabled"] = info.enabled
        d["conf_rev"] = info.conf_rev
        d["min_time"] = info.min_time
        d["max_time"] = info.max_time
        d["fixed_offs"] = info.fixed_offs
        d["nds_comm"] = info.nds_comm

        if info.appid is not None:
            d["appid"] = info.appid
        if info.vlan_id is not None:
            d["vlan_id"] = info.vlan_id
        if info.vlan_priority is not None:
            d["vlan_priority"] = info.vlan_priority
        if info.dst_mac:
            d["dst_mac"] = info.dst_mac

        return d

    def _format_mac(self, mac_data: Any) -> str:
        """Format MAC address bytes to string."""
        try:
            if isinstance(mac_data, (bytes, bytearray)):
                return ":".join(f"{b:02X}" for b in mac_data[:6])
            elif isinstance(mac_data, str):
                return mac_data
            elif hasattr(mac_data, "__len__") and len(mac_data) >= 6:
                return ":".join(f"{mac_data[i]:02X}" for i in range(6))
            return str(mac_data)
        except Exception:
            return str(mac_data)

    def _display_goose_message(self, msg: Dict[str, Any], is_new: bool = False) -> None:
        """Display a captured GOOSE message in NXC style."""
        gocb_ref = msg.get("gocb_ref", "unknown")
        appid = msg.get("appid", "?")
        st_num = msg.get("st_num", "?")
        sq_num = msg.get("sq_num", "?")
        src_mac = msg.get("src_mac", "unknown")

        if is_new:
            self.logger.success(f"GOOSE: {gocb_ref} AppID:{appid} from {src_mac}")
            go_id = msg.get("goose_id", "")
            if go_id:
                self.logger.display(f"  GoID: {go_id}")
            if msg.get("vlan_id") is not None:
                self.logger.display(f"  VLAN: ID={msg['vlan_id']} Prio={msg.get('vlan_prio', '?')}")
            if msg.get("dst_mac"):
                self.logger.display(f"  Dst MAC: {msg['dst_mac']}")
            if msg.get("is_test"):
                self.logger.warning("  TEST/SIMULATION flag is SET")
            if msg.get("dataset_size") is not None:
                self.logger.display(f"  Dataset: {msg['dataset_size']} elements")
        else:
            self.logger.debug(f"GOOSE: {gocb_ref} stNum={st_num} sqNum={sq_num}")

    def _display_gocb(self, gocb: Dict[str, Any]) -> None:
        """Display a GoCB entry in NXC style."""
        ref = gocb.get("gocb_ref", "unknown")
        enabled = gocb.get("enabled", False)
        status = "ENABLED" if enabled else "disabled"

        self.logger.success(f"GoCB: {ref} [{status}]")

        go_id = gocb.get("goose_id", "")
        if go_id:
            self.logger.display(f"  GoID: {go_id}")

        dataset = gocb.get("dataset", "")
        if dataset:
            self.logger.display(f"  Dataset: {dataset}")

        appid = gocb.get("appid")
        if appid is not None:
            self.logger.display(f"  AppID: {appid} (0x{appid:04X})")

        dst_mac = gocb.get("dst_mac", "")
        if dst_mac:
            self.logger.display(f"  Dst MAC: {dst_mac}")

        vlan_id = gocb.get("vlan_id")
        if vlan_id is not None:
            self.logger.display(f"  VLAN: ID={vlan_id} Prio={gocb.get('vlan_priority', '?')}")

        conf_rev = gocb.get("conf_rev")
        if conf_rev is not None:
            self.logger.display(f"  ConfRev: {conf_rev}")

        min_t = gocb.get("min_time")
        max_t = gocb.get("max_time")
        if min_t is not None and max_t is not None:
            self.logger.display(f"  Timing: min={min_t}ms max={max_t}ms")

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GOOSE security posture."""
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": False,
                "integrity_check": False,
                "access_control": False,
            }
        )

        analysis["concerns"] = []

        messages = results.get("goose_messages", [])
        gocbs = results.get("gocb_info", [])

        # Check for unprotected GOOSE (no authentication per IEC 62351)
        if messages:
            analysis["concerns"].append(
                f"Unprotected GOOSE traffic detected ({len(messages)} messages) - "
                "no IEC 62351-6 authentication"
            )

        # Check for simulation/test flags
        test_messages = [m for m in messages if m.get("is_test")]
        if test_messages:
            analysis["concerns"].append(
                f"{len(test_messages)} GOOSE messages have TEST/SIMULATION flag set"
            )

        # Check for default AppIDs (0x0000 or 0x0001 suggest unconfigured)
        default_appids = [m for m in messages if m.get("appid") in (0, 1)]
        if default_appids:
            analysis["concerns"].append(
                f"{len(default_appids)} messages use default AppID (0x0000 or 0x0001)"
            )

        # Check for stNum/sqNum anomalies (potential replay)
        self._check_sequence_anomalies(messages, analysis)

        # Check GoCB security
        enabled_gocbs = [g for g in gocbs if g.get("enabled")]
        if enabled_gocbs:
            analysis["concerns"].append(
                f"{len(enabled_gocbs)} active GOOSE Control Blocks discovered via MMS"
            )

        # Check for needs_commission flag
        nds_comm = [g for g in gocbs if g.get("nds_comm")]
        if nds_comm:
            analysis["concerns"].append(
                f"{len(nds_comm)} GoCBs have NdsComm flag (needs commissioning)"
            )

        # Multiple sources suggest complex substation network
        sources = results.get("goose_sources", {})
        if len(sources) > 1:
            analysis["concerns"].append(f"{len(sources)} unique GOOSE sources detected")

        return analysis

    def _check_sequence_anomalies(
        self, messages: List[Dict[str, Any]], analysis: Dict[str, Any]
    ) -> None:
        """Check for stNum/sqNum anomalies that may indicate replay attacks."""
        # Group by GoCB reference
        by_gocb = defaultdict(list)
        for msg in messages:
            gocb_ref = msg.get("gocb_ref", "")
            if gocb_ref:
                by_gocb[gocb_ref].append(msg)

        for gocb_ref, msgs in by_gocb.items():
            if len(msgs) < 2:
                continue

            # Check for decreasing stNum (potential replay)
            st_nums = [m.get("st_num", 0) for m in msgs]
            for i in range(1, len(st_nums)):
                if st_nums[i] < st_nums[i - 1]:
                    analysis["concerns"].append(
                        f"Decreasing stNum on {gocb_ref}: {st_nums[i - 1]} -> {st_nums[i]} "
                        "(possible replay)"
                    )
                    break

            # Check for large sqNum gaps
            sq_nums = [m.get("sq_num", 0) for m in msgs]
            for i in range(1, len(sq_nums)):
                gap = abs(sq_nums[i] - sq_nums[i - 1])
                if gap > 100:
                    analysis["concerns"].append(
                        f"Large sqNum gap on {gocb_ref}: {sq_nums[i - 1]} -> {sq_nums[i]} "
                        f"(gap={gap}, possible message loss)"
                    )
                    break

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings."""
        interface_or_host = self.interface
        if self.mms_enum_target:
            interface_or_host = self.mms_enum_target

        self.report_host_info(interface_or_host)

        if self.mms_enum_target:
            self.report_service_info(
                interface_or_host,
                port=self.mms_port,
                name="iec61850-goose-mms",
                proto="tcp",
            )

        security_analysis = results.get("security_analysis", {})
        for concern in security_analysis.get("concerns", []):
            self.report_vulnerability(interface_or_host, "goose_security", description=concern)


# Create metadata and run function using protocol module factory
metadata, run = create_protocol_module(
    GOOSEScanner, dependencies_check_func=lambda: not _pyiec61850_goose.is_available
)


if __name__ == "__main__":
    from utils.cli import main  # type: ignore[import-not-found]

    main(sys.argv, run, metadata)


# Re-export NXC-style callable class
from .nxc_connection import goose as goose  # noqa: E402
