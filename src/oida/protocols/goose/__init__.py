#!/usr/bin/env python3
"""
GOOSE (Generic Object Oriented Substation Event) Protocol Scanner

Passive GOOSE message capture and GoCB (GOOSE Control Block) enumerator via MMS.

Uses pyiec61850-ng >= 1.6.1.0 high-level Python API:
  - GooseSubscriber for GOOSE message capture
  - MMSClient + GoCBClient for MMS GoCB enumeration

Requires: pip install oida-ics[goose]
"""

import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

from oida.utils import SecurityAnalyzer, parse_bool, safe_int_conversion
from oida.utils.base_scanner import SerialScanner
from oida.utils.lazy_import import lazy_import


# Lazy imports for pyiec61850-ng (only loaded when actually used)
_pyiec61850_goose = lazy_import(
    "pyiec61850.goose", "GOOSE", install_hint="pip install oida-ics[goose]"
)
_pyiec61850_mms = lazy_import("pyiec61850.mms", "GOOSE", install_hint="pip install oida-ics[goose]")
_pyiec61850_raw = lazy_import(
    "pyiec61850.pyiec61850", "GOOSE", install_hint="pip install oida-ics[goose]"
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


class GOOSEScanner(SerialScanner):
    """IEC 61850 GOOSE Scanner implementing the base scanner interface.

    Supports three operating modes:
    1. GOOSE capture on a network interface (requires gocb-ref)
    2. R-GOOSE listening over UDP (not yet supported in high-level API)
    3. GoCB enumeration via MMS connection
    """

    # Cap for the in-RAM GOOSE message accumulators (used for the summary); a
    # busy substation bus over a long --timeout would otherwise grow unbounded.
    _MAX_GOOSE_MESSAGES = 10000

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

        # TLS for the MMS GoCB-enumeration sub-connection (pyiec61850-ng >=
        # 1.6.1.9). Certificate validation is DISABLED by default; see
        # oida.protocols.mms.build_mms_tls_config.
        self.tls = parse_bool(args.get("tls", False))
        self.tls_port = safe_int_conversion(args.get("tls-port"), 3782)
        self.tls_ca = args.get("tls-ca") or None
        self.tls_pin = args.get("tls-pin") or None
        self.tls_client_cert = args.get("tls-client-cert") or None
        self.tls_client_key = args.get("tls-client-key") or None

        # Discovered GOOSE messages
        self.goose_sources = {}  # MAC -> list of messages

        # Active GooseSubscriber for cleanup
        self._goose_subscriber = None

        # Seconds the last MMS connect consumed (pyiec61850 collapses refused
        # and timeout into one message; elapsed is the discriminator).
        self._connect_elapsed: float | None = None

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
            from oida.protocols.mms import build_mms_tls_config

            tls_config = build_mms_tls_config(
                tls=self.tls,
                tls_ca=self.tls_ca,
                tls_pin=self.tls_pin,
                client_cert=self.tls_client_cert,
                client_key=self.tls_client_key,
                logger=self.logger,
            )
            # MMS-over-TLS listens on 3782; switch to it when --tls is set and
            # the caller passed the plaintext default.
            if tls_config is not None and port == 102:
                port = self.tls_port

            self.logger.debug(f"Connecting MMSClient to {host}:{port}")
            # --timeout is the GOOSE *capture* budget, not a connect budget;
            # cap the MMS sub-connection at a modest fixed 10s (the library
            # default) so an unroutable --mms-enum host cannot hang the run
            # for the full capture window.
            mms_connect_timeout_ms = 10_000
            if tls_config is not None:
                client = _pyiec61850_mms.MMSClient(timeout=mms_connect_timeout_ms, tls=tls_config)
            else:
                client = _pyiec61850_mms.MMSClient(timeout=mms_connect_timeout_ms)
            _connect_started = time.monotonic()
            try:
                connected = client.connect(host, port)
            finally:
                # Set even when connect raises: pyiec61850 reports a blackhole
                # (full-budget wait, then rejection) with the same message as an
                # actively-refused connect - elapsed is the only discriminator.
                self._connect_elapsed = time.monotonic() - _connect_started

            if not connected:
                # Keep quiet here: the cli_runner prints the single canonical
                # failure line via record_connect_failure() (GH issue #59).
                self.logger.debug(f"MMSClient.connect returned False for {host}:{port}")
                return None

            self.logger.success(f"Connected to IEC 61850 server at {host}:{port}")
            return {
                "type": "mms_connection",
                "client": client,
                "host": host,
                "port": port,
            }

        except Exception as e:
            # Discriminate real connect failures (refused/timeout: keep the
            # exception for the runner to classify from its message - the
            # mms-enum path targets potentially unroutable hosts, and a
            # runner-side TCP probe would wait the full --timeout a second
            # time on top of the scanner's own wait) from TLS config errors
            # (bad --tls-ca path, unreadable pin: keep the exception for the
            # runner's record_connect_failure(exc=...) so the offending path
            # is operator-visible; the scanner stays quiet per GH #59).
            # The class is fetched defensively: unit tests patch this whole
            # module with a MagicMock, and except/isinstance on a mock
            # raises TypeError.
            conn_failed_cls = getattr(_pyiec61850_mms, "ConnectionFailedError", None)
            if isinstance(conn_failed_cls, type) and isinstance(e, conn_failed_cls):
                self.logger.debug(f"MMSClient connect failed to {host}:{port}: {e}")
                self._last_connect_exc = e
                return None
            self.logger.debug(f"Failed to create MMS connection: {e}")
            self._last_connect_error = e
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
                # Extract the L2 / link-layer fields the high-level
                # GooseMessage does not carry (src/dst MAC, VLAN, test flag)
                # from the raw subscriber before converting. The getters fill
                # buffers / return scalars for the last received frame.
                try:
                    if sub._subscriber is not None:
                        raw_sub = sub._subscriber
                        src_buf = bytearray(6)
                        _pyiec61850_raw.GooseSubscriber_getSrcMac(raw_sub, src_buf)
                        msg.src_mac = bytes(src_buf)
                        dst_buf = bytearray(6)
                        _pyiec61850_raw.GooseSubscriber_getDstMac(raw_sub, dst_buf)
                        msg.dst_mac = bytes(dst_buf)
                        msg.vlan_id = _pyiec61850_raw.GooseSubscriber_getVlanId(raw_sub)
                        msg.vlan_prio = _pyiec61850_raw.GooseSubscriber_getVlanPrio(raw_sub)
                        msg.is_test = bool(_pyiec61850_raw.GooseSubscriber_isTest(raw_sub))
                except Exception as e:
                    # A library rename/API change here silently degrades all L2
                    # extraction (src/dst MAC, VLAN) and suppresses the
                    # TEST/SIMULATION security finding, so surface it above debug.
                    self.logger.warning(f"raw subscriber field extraction failed: {e}")

                msg_info = self._goose_message_to_dict(msg)
                messages.append(msg_info)
                # Cap both accumulators: a chatty/hostile substation bus at
                # hundreds-thousands of frames/s with a large --timeout would
                # otherwise grow memory unbounded (doubled by the per-source
                # copy). Trim in chunks so it's amortized O(1) per frame.
                if len(messages) > 2 * self._MAX_GOOSE_MESSAGES:
                    del messages[: -self._MAX_GOOSE_MESSAGES]

                gocb = msg_info.get("gocb_ref", "")
                is_new = gocb and gocb not in seen_gocbs
                if is_new:
                    seen_gocbs.add(gocb)
                self._display_goose_message(msg_info, is_new=is_new)

                src = msg_info.get("src_mac", "unknown")
                if src not in self.goose_sources:
                    self.goose_sources[src] = []
                self.goose_sources[src].append(msg_info)
                if len(self.goose_sources[src]) > 2 * self._MAX_GOOSE_MESSAGES:
                    del self.goose_sources[src][: -self._MAX_GOOSE_MESSAGES]
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
                # start() was called, so stop() to release any bound socket
                # before dropping the reference (other exit paths do this).
                try:
                    sub.stop()
                except Exception as e:
                    self.logger.debug(f"Failed to stop GOOSE subscriber after failed start: {e}")
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
                    self.logger.debug(f"Failed to stop GOOSE subscriber during cleanup: {e}")
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

        # src_mac / dst_mac / vlan / is_test are set dynamically on the
        # GooseMessage in on_message() from the raw subscriber, since the
        # high-level GooseMessage does not carry L2 / link-layer fields.
        src_mac = getattr(msg, "src_mac", None)
        if src_mac:
            info["src_mac"] = self._format_mac(src_mac)
        dst_mac = getattr(msg, "dst_mac", None)
        if dst_mac:
            info["dst_mac"] = self._format_mac(dst_mac)
        vlan_id = getattr(msg, "vlan_id", None)
        if vlan_id is not None:
            info["vlan_id"] = vlan_id
        vlan_prio = getattr(msg, "vlan_prio", None)
        if vlan_prio is not None:
            info["vlan_prio"] = vlan_prio

        info["appid"] = msg.app_id
        info["st_num"] = msg.st_num
        info["sq_num"] = msg.sq_num
        info["conf_rev"] = msg.conf_rev
        info["valid"] = msg.is_valid
        info["needs_commission"] = msg.needs_commissioning
        info["time_allowed_to_live"] = msg.time_allowed_to_live
        info["dataset_size"] = msg.num_data_set_entries
        # IEC 61850-8-1 §A.5 GOOSE PDU 'test' boolean flag, extracted from
        # the raw subscriber in on_message() (GooseSubscriber_isTest).
        info["is_test"] = bool(getattr(msg, "is_test", False))

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
        """Format MAC address bytes to a colon-separated hex string.

        Callers always pass bytes (from the raw subscriber MAC buffers);
        anything else falls back to str().
        """
        if isinstance(mac_data, (bytes, bytearray)):
            return ":".join(f"{b:02X}" for b in mac_data[:6])
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
            # VLAN/dst_mac ARE captured here too (see on_message()'s raw
            # subscriber extraction / _goose_message_to_dict), but are not
            # rendered in this summary line; the MMS GoCB path's counterparts
            # are shown by _display_gocb instead.
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

            # Check for large sqNum gaps. sqNum legitimately resets (drops back
            # to 0/1) whenever stNum increments for a new event -- that is not
            # message loss, so only flag a gap between messages that share the
            # same stNum (i.e. retransmissions of the same state).
            sq_nums = [m.get("sq_num", 0) for m in msgs]
            for i in range(1, len(sq_nums)):
                if st_nums[i] != st_nums[i - 1]:
                    continue
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


# Re-export NXC-style callable class
from oida.protocols.goose.cli_runner import goose as goose  # noqa: E402
