"""
R-GOOSE (Routable GOOSE over UDP) Passive Listener (PyShark-based).

Passively monitors R-GOOSE traffic -- the IP/UDP-routable variant of
IEC 61850 GOOSE defined in IEC 61850-8-2 (formerly IEC 61850-90-5).
R-GOOSE encapsulates standard GOOSE PDUs inside a Session Protocol Data Unit
(SPDU) carried over UDP, enabling GOOSE messages to traverse IP networks
rather than being limited to a single Ethernet segment.

Key differences from L2 GOOSE:
- Transported over UDP (routable across subnets)
- Session header with SPDU number, security info (key ID, HMAC, IV)
- Optional IEC 62351-6 authentication via HMAC in the session header
- Same GOOSE PDU payload (gocbRef, stNum, sqNum, allData, etc.)

tshark fields used:

R-GOOSE session header (rgoose.* prefix):
- rgoose.spdu_id: Session PDU identifier (FT_UINT8)
- rgoose.session_hdr_len: Session header length (FT_UINT8)
- rgoose.spdu_len: SPDU length (FT_UINT32)
- rgoose.spdu_num: SPDU number (FT_UINT32, monotonically increasing)
- rgoose.version: Protocol version (FT_UINT16)
- rgoose.curr_key_t: Time of current key (FT_UINT32)
- rgoose.next_key_t: Time of next key (FT_UINT16)
- rgoose.key_id: Key ID for HMAC authentication (FT_UINT32)
- rgoose.init_v_len: Initialization vector length (FT_UINT8)
- rgoose.init_v: Initialization vector (FT_BYTES)
- rgoose.payload_len: Payload length (FT_UINT32)
- rgoose.simulation: Simulation flag (FT_UINT8)
- rgoose.appid: Application ID (FT_UINT16)
- rgoose.apdu_len: APDU length (FT_UINT16)
- rgoose.hmac: HMAC value (FT_BYTES, present when authenticated)

GOOSE PDU fields (goose.* prefix -- same dissector as L2 GOOSE):
- goose.gocbRef: GOOSE Control Block Reference (FT_STRING)
- goose.datSet: Dataset reference (FT_STRING)
- goose.goID: GOOSE ID (FT_STRING)
- goose.stNum: State Number (FT_UINT32)
- goose.sqNum: Sequence Number (FT_UINT32)
- goose.confRev: Configuration Revision (FT_INT32)
- goose.simulation: Test/simulation flag (FT_BOOLEAN)
- goose.ndsCom: Needs Commissioning (FT_BOOLEAN)
- goose.numDatSetEntries: Number of data entries (FT_INT32)
- goose.timeAllowedtoLive: Time to live in ms (FT_INT32)
- goose.boolean: Boolean data values (FT_BOOLEAN)
- goose.integer: Integer data values (FT_INT32)
- goose.unsigned: Unsigned integer values (FT_INT32)
- goose.float_value: Float data values (FT_FLOAT)
- goose.real: Real/double data values (FT_DOUBLE)
- goose.bit_string: Bitstring data values (FT_BYTES)
- goose.visible_string: Visible string data (FT_STRING)

Security notes:
- R-GOOSE may or may not include HMAC authentication (rgoose.hmac field)
- Unauthenticated R-GOOSE over IP is easier to spoof than L2 GOOSE
  (attacker does not need to be on the same Ethernet segment)
- StNum rollback (decrease) may indicate replay attack
- confRev mismatch between publishers can cause protection failures
- Test/simulation mode (goose.simulation=true) in production is a red flag
- Absence of HMAC when key_id is present indicates possible auth bypass

References:
- IEC 61850-8-2: Communication networks -- Mapping to IP networks (R-GOOSE)
- IEC 61850-90-5: Use of IEC 61850 to transmit synchrophasor info (R-GOOSE/R-SV)
- IEC 62351-6: Security for IEC 61850 (GOOSE/R-GOOSE authentication)
- Wireshark dissector: packet-goose.c (shared with L2 GOOSE)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from oida.pcap._goose_common import collect_field_values, format_bool_display
from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip


@dataclass
class RGOOSEPublisher:
    """Track an R-GOOSE publisher (identified by GoCBRef + source IP)."""

    src_ip: str
    gocb_ref: str
    appid: int = 0
    datasets: Set[str] = field(default_factory=set)
    go_ids: Set[str] = field(default_factory=set)
    conf_revs: Set[int] = field(default_factory=set)
    last_st_num: int = -1
    max_st_num: int = 0
    total_frames: int = 0
    state_changes: int = 0
    test_frames: int = 0
    nds_com_seen: bool = False
    st_num_rollbacks: int = 0
    hmac_present: int = 0
    hmac_absent: int = 0
    key_ids: Set[int] = field(default_factory=set)
    spdu_nums: List[int] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


class RGOOSEPassiveListener(PySharkListenerBase):
    """Passive R-GOOSE (Routable GOOSE over UDP) traffic listener.

    Monitors R-GOOSE traffic to:
    - Identify IEDs publishing R-GOOSE messages by source IP and GoCBRef
    - Track GOOSE Control Block References and datasets
    - Monitor state transitions (StNum) vs heartbeat retransmissions (SqNum)
    - Extract R-GOOSE session header fields (SPDU number, key ID, HMAC)
    - Detect HMAC authentication presence/absence
    - Alert on StNum rollback (possible replay attack)
    - Alert on configuration revision mismatches
    - Detect test/simulation mode frames

    R-GOOSE uses UDP transport, so devices are keyed by IP address.
    The GOOSE PDU payload is identical to L2 GOOSE (same tshark dissector).

    Usage:
        listener = RGOOSEPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

    Data stored in device.rgoose_passive_data:
        {
            "role": "publisher",
            "gocb_refs": ["IED1/LLN0$GO$GoCB01"],
            "datasets": ["IED1/LLN0$DataSet01"],
            "appid": 1,
            "conf_revs": [1],
            "state_changes": 42,
            "total_frames": 1000,
            "hmac_authenticated": true,
            "key_ids": [1],
            "protocol": "R-GOOSE/UDP",
        }
    """

    PROTOCOL_NAME = "rgoose"
    DISPLAY_FILTER = "r-goose"
    REQUIRED_LAYERS = ("goose",)
    PROTOCOL_COLUMNS = (
        "gocbref",
        "dataset",
        "st_num",
        "sq_num",
        "test",
        "hmac",
        "spdu_num",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize R-GOOSE passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.publishers: Dict[str, RGOOSEPublisher] = {}
        self._conf_rev_by_gocb: Dict[str, Set[int]] = {}

    def process_packet(self, packet) -> None:
        """Process an R-GOOSE packet using PyShark dissection.

        R-GOOSE packets have both rgoose.* session fields and goose.* PDU fields.
        The goose layer is shared with L2 GOOSE.
        """
        if not hasattr(packet, "goose"):
            return

        goose_layer = packet.goose

        # R-GOOSE is IP/UDP -- extract IP addresses. The 'goose' layer is
        # shared with the L2 GOOSE listener, so a combined-pcap run feeds
        # plain L2 GOOSE (no IP) here too; reject those (and any malformed
        # R-GOOSE with an unparsable IP) with a trace instead of vanishing.
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip:
            self.logger.debug(
                "rgoose: dropping GOOSE packet with no IP "
                "(L2 GOOSE or malformed R-GOOSE, no rgoose session)"
            )
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)

        # -- R-GOOSE session header fields --
        # tshark registers these under the ``rgoose.`` abbreviation even though
        # they live on the shared ``goose`` layer, so at runtime they are
        # reachable as ``rgoose_<name>`` (EK mode) / ``rgoose.<name>`` (XML mode)
        # -- NOT as bare names off the goose layer. Reading the bare name
        # returned the default for every field, so has_hmac was always False and
        # a bogus rgoose_no_auth verdict fired even on authenticated R-GOOSE.
        spdu_num = self._parse_int(self.get_field(goose_layer, "rgoose_spdu_num"), 0)
        spdu_len = self._parse_int(self.get_field(goose_layer, "rgoose_spdu_len"), 0)
        rgoose_version = self._parse_int(self.get_field(goose_layer, "rgoose_version"), 0)
        key_id = self._parse_int(self.get_field(goose_layer, "rgoose_key_id"), 0)
        curr_key_t = self._parse_int(self.get_field(goose_layer, "rgoose_curr_key_t"), 0)
        next_key_t = self._parse_int(self.get_field(goose_layer, "rgoose_next_key_t"), 0)
        init_v_len = self._parse_int(self.get_field(goose_layer, "rgoose_init_v_len"), 0)
        payload_len = self._parse_int(self.get_field(goose_layer, "rgoose_payload_len"), 0)

        # HMAC -- presence indicates authentication is enabled
        hmac_raw = self.get_field(goose_layer, "rgoose_hmac")
        has_hmac = hmac_raw is not None and str(hmac_raw).strip() not in ("", "None")

        # R-GOOSE APPID (rgoose session header -- distinct from the L2 goose.appid)
        rgoose_appid = self._parse_int(self.get_field(goose_layer, "rgoose_appid"), 0)

        # R-GOOSE session-level simulation flag (rgoose.simulation -- distinct
        # from the GOOSE PDU goose.simulation read below)
        rgoose_sim = self._parse_int(self.get_field(goose_layer, "rgoose_simulation"), 0)

        # -- GOOSE PDU fields (standard goose.* prefix) --
        gocb_ref = str(self.get_field(goose_layer, "gocbRef") or "")
        dat_set = str(self.get_field(goose_layer, "datSet") or "")
        go_id = str(self.get_field(goose_layer, "goID") or "")
        st_num = self._parse_int(self.get_field(goose_layer, "stNum"), 0)
        sq_num = self._parse_int(self.get_field(goose_layer, "sqNum"), 0)
        conf_rev = self._parse_int(self.get_field(goose_layer, "confRev"), 0)
        ttl_ms = self._parse_int(self.get_field(goose_layer, "timeAllowedtoLive"), 0)
        num_entries = self._parse_int(self.get_field(goose_layer, "numDatSetEntries"), 0)

        # Parse boolean flags from GOOSE PDU
        goose_sim_raw = self.get_field(goose_layer, "simulation")
        # Use the GOOSE PDU simulation flag; if it's the same as rgoose, use rgoose
        simulation = (
            self._parse_bool(goose_sim_raw) if goose_sim_raw is not None else bool(rgoose_sim)
        )
        nds_com = self._parse_bool(self.get_field(goose_layer, "ndsCom"))

        # Extract data values from allData (same as L2 GOOSE)
        values = self._extract_all_data(goose_layer)

        # Use GoCBRef as the publisher key; fall back to src_ip:appid
        pub_key = gocb_ref if gocb_ref else f"{src_ip}:0x{rgoose_appid:04x}"

        # Update publisher state
        publisher = self._update_publisher(
            pub_key,
            src_ip,
            gocb_ref,
            rgoose_appid,
            dat_set,
            go_id,
            st_num,
            sq_num,
            conf_rev,
            simulation,
            nds_com,
            has_hmac,
            key_id,
            spdu_num,
        )

        is_state_change = sq_num == 0 and publisher.total_frames > 1

        # Build interaction details
        now = datetime.now().isoformat()
        details: Dict[str, Any] = {
            "gocb_ref": gocb_ref,
            "dataset": dat_set,
            "st_num": st_num,
            "sq_num": sq_num,
            "conf_rev": conf_rev,
            "test": simulation,
            "nds_com": nds_com,
            "ttl_ms": ttl_ms,
            "num_entries": num_entries,
            "appid": rgoose_appid,
            "spdu_num": spdu_num,
            "spdu_len": spdu_len,
            "rgoose_version": rgoose_version,
            "key_id": key_id,
            "has_hmac": has_hmac,
        }
        if values:
            details["values"] = values
        if go_id:
            details["go_id"] = go_id
        if curr_key_t:
            details["curr_key_t"] = curr_key_t
        if next_key_t:
            details["next_key_t"] = next_key_t
        if init_v_len:
            details["init_v_len"] = init_v_len
        if payload_len:
            details["payload_len"] = payload_len

        operation = "state_change" if is_state_change else "heartbeat"
        summary = self._build_summary(
            gocb_ref,
            st_num,
            sq_num,
            simulation,
            is_state_change,
            has_hmac,
            values,
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",  # R-GOOSE is publish-only (multicast)
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update device entry
        self._update_device(src_ip, pub_key, publisher)

    # ------------------------------------------------------------------
    # Publisher tracking
    # ------------------------------------------------------------------

    def _update_publisher(
        self,
        pub_key: str,
        src_ip: str,
        gocb_ref: str,
        appid: int,
        dat_set: str,
        go_id: str,
        st_num: int,
        sq_num: int,
        conf_rev: int,
        simulation: bool,
        nds_com: bool,
        has_hmac: bool,
        key_id: int,
        spdu_num: int,
    ) -> RGOOSEPublisher:
        """Update or create an R-GOOSE publisher entry."""
        now = datetime.now().isoformat()

        if pub_key not in self.publishers:
            self.publishers[pub_key] = RGOOSEPublisher(
                src_ip=src_ip,
                gocb_ref=gocb_ref,
                appid=appid,
                first_seen=now,
                last_seen=now,
            )

        pub = self.publishers[pub_key]
        pub.last_seen = now
        pub.total_frames += 1

        if dat_set:
            pub.datasets.add(dat_set)
        if go_id:
            pub.go_ids.add(go_id)
        if conf_rev:
            pub.conf_revs.add(conf_rev)
        if key_id:
            pub.key_ids.add(key_id)

        # Track confRev for mismatch detection
        if gocb_ref and conf_rev:
            self._conf_rev_by_gocb.setdefault(gocb_ref, set()).add(conf_rev)

        # Track HMAC presence
        if has_hmac:
            pub.hmac_present += 1
        else:
            pub.hmac_absent += 1

        # Detect state change (StNum increased and SqNum reset to 0)
        if st_num > pub.max_st_num:
            pub.max_st_num = st_num
            if pub.last_st_num >= 0:
                pub.state_changes += 1

        # Detect StNum rollback (possible replay attack)
        if pub.last_st_num >= 0 and st_num < pub.last_st_num:
            pub.st_num_rollbacks += 1

        pub.last_st_num = st_num

        if simulation:
            pub.test_frames += 1
        if nds_com:
            pub.nds_com_seen = True

        # Track SPDU numbers for gap detection
        pub.spdu_nums.append(spdu_num)

        return pub

    # ------------------------------------------------------------------
    # Data value extraction (mirrors L2 GOOSE -- same dissector)
    # ------------------------------------------------------------------

    def _extract_all_data(self, goose_layer) -> List[str]:
        """Extract data values from GOOSE allData entries.

        Same logic as L2 GOOSE -- the GOOSE PDU is identical.
        """
        values: List[str] = []

        for field_name in (
            "boolean",
            "integer",
            "unsigned",
            "float_value",
            "real",
            "bit_string",
            "visible_string",
        ):
            if self.get_field(goose_layer, field_name, None) is not None:
                formatter = None
                if field_name == "boolean":
                    formatter = self._format_bool_val
                elif field_name in ("float_value", "real"):
                    formatter = self._format_float
                self._collect_field_values(goose_layer, field_name, values, formatter)

        return values

    def _collect_field_values(
        self,
        layer,
        field_name: str,
        values: List[str],
        formatter=None,
    ) -> None:
        """Collect all instances of a field from a PyShark layer into values list."""
        collect_field_values(layer, field_name, values, formatter)

    @staticmethod
    def _format_bool_val(val: str) -> str:
        """Format a boolean value for display."""
        return format_bool_display(val)

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details

        gocb_ref = d.get("gocb_ref", "")
        dataset = d.get("dataset", "")
        st_num = d.get("st_num", "")
        sq_num = d.get("sq_num", "")

        test = d.get("test", False)
        test_str = "YES" if test else ""

        has_hmac = d.get("has_hmac", False)
        hmac_str = "HMAC" if has_hmac else "none"

        spdu_num = d.get("spdu_num", "")

        return [
            gocb_ref,
            dataset,
            st_num,
            sq_num,
            test_str,
            hmac_str,
            spdu_num,
        ]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with R-GOOSE-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        for pub in self.publishers.values():
            # Alert: test/simulation frames
            if pub.test_frames > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "rgoose_test_mode",
                        "message": (
                            f"R-GOOSE TEST MODE: {pub.src_ip} GoCBRef={pub.gocb_ref} "
                            f"sent {pub.test_frames} test frames "
                            f"(simulation=true may indicate spoofing or misconfiguration)"
                        ),
                    }
                )

            # Alert: StNum rollback (possible replay attack)
            if pub.st_num_rollbacks > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "rgoose_replay",
                        "message": (
                            f"R-GOOSE REPLAY RISK: {pub.src_ip} GoCBRef={pub.gocb_ref} "
                            f"StNum decreased {pub.st_num_rollbacks} time(s) "
                            f"(possible replay attack or IED restart)"
                        ),
                    }
                )

            # Alert: unauthenticated R-GOOSE (no HMAC)
            if pub.hmac_absent > 0 and pub.hmac_present == 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "rgoose_no_auth",
                        "message": (
                            f"R-GOOSE NO AUTH: {pub.src_ip} GoCBRef={pub.gocb_ref} "
                            f"sent {pub.hmac_absent} frames without HMAC "
                            f"(IEC 62351-6 authentication not enabled -- "
                            f"R-GOOSE over IP is vulnerable to spoofing)"
                        ),
                    }
                )

            # Alert: mixed HMAC presence (some authenticated, some not)
            if pub.hmac_present > 0 and pub.hmac_absent > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "rgoose_mixed_auth",
                        "message": (
                            f"R-GOOSE MIXED AUTH: {pub.src_ip} GoCBRef={pub.gocb_ref} "
                            f"sent {pub.hmac_present} authenticated and "
                            f"{pub.hmac_absent} unauthenticated frames "
                            f"(inconsistent security configuration)"
                        ),
                    }
                )

            # Alert: needs commissioning
            if pub.nds_com_seen:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "rgoose_commissioning",
                        "message": (
                            f"R-GOOSE COMMISSIONING: {pub.src_ip} GoCBRef={pub.gocb_ref} "
                            f"has ndsCom=true (device needs commissioning)"
                        ),
                    }
                )

        # Alert: configuration revision mismatch
        for gocb_ref, revs in self._conf_rev_by_gocb.items():
            if len(revs) > 1:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "rgoose_confrev_mismatch",
                        "message": (
                            f"R-GOOSE CONFIG MISMATCH: GoCBRef={gocb_ref} "
                            f"has multiple confRev values: {sorted(revs)} "
                            f"(subscribers may reject data or malfunction)"
                        ),
                    }
                )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, src_ip: str, pub_key: str, publisher: RGOOSEPublisher) -> None:
        """Update or create a device entry for an R-GOOSE publisher."""
        if not src_ip or not is_valid_discovered_ip(src_ip):
            return

        device_key = f"rgoose-ied:{src_ip}"
        device, _is_new = self._ensure_device(
            device_key,
            src_ip,
            device_type="IEC 61850 IED (R-GOOSE Publisher)",
        )

        device.rgoose_passive_data = self._build_device_data(src_ip)

        if _is_new:
            self.logger.debug(
                f"R-GOOSE: IED {src_ip} GoCBRef={publisher.gocb_ref} APPID=0x{publisher.appid:04x}"
            )

    def _build_device_data(self, src_ip: str) -> Dict[str, Any]:
        """Build rgoose_passive_data dict for all publishers from a source IP."""
        gocb_refs: List[str] = []
        datasets: Set[str] = set()
        go_ids: Set[str] = set()
        conf_revs: Set[int] = set()
        appids: Set[int] = set()
        key_ids: Set[int] = set()
        total_frames = 0
        state_changes = 0
        test_frames = 0
        st_num_rollbacks = 0
        hmac_present = 0
        hmac_absent = 0
        first_seen = ""
        last_seen = ""

        for pub in self.publishers.values():
            if pub.src_ip != src_ip:
                continue
            if pub.gocb_ref:
                gocb_refs.append(pub.gocb_ref)
            datasets.update(pub.datasets)
            go_ids.update(pub.go_ids)
            conf_revs.update(pub.conf_revs)
            key_ids.update(pub.key_ids)
            if pub.appid:
                appids.add(pub.appid)
            total_frames += pub.total_frames
            state_changes += pub.state_changes
            test_frames += pub.test_frames
            st_num_rollbacks += pub.st_num_rollbacks
            hmac_present += pub.hmac_present
            hmac_absent += pub.hmac_absent
            if not first_seen or (pub.first_seen and pub.first_seen < first_seen):
                first_seen = pub.first_seen
            if not last_seen or (pub.last_seen and pub.last_seen > last_seen):
                last_seen = pub.last_seen

        return {
            "role": "publisher",
            "gocb_refs": sorted(gocb_refs),
            "datasets": sorted(datasets),
            "go_ids": sorted(go_ids),
            "appids": sorted(appids),
            "conf_revs": sorted(conf_revs),
            "key_ids": sorted(key_ids),
            "state_changes": state_changes,
            "total_frames": total_frames,
            "test_frames": test_frames,
            "st_num_rollbacks": st_num_rollbacks,
            "hmac_authenticated": hmac_present > 0 and hmac_absent == 0,
            "hmac_present_count": hmac_present,
            "hmac_absent_count": hmac_absent,
            "protocol": "R-GOOSE/UDP",
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        gocb_ref: str,
        st_num: int,
        sq_num: int,
        simulation: bool,
        is_state_change: bool,
        has_hmac: bool,
        values: List[str],
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = []

        if is_state_change:
            parts.append(f"STATE_CHANGE StNum={st_num}")
        else:
            parts.append(f"StNum={st_num} SqNum={sq_num}")

        if gocb_ref:
            short_ref = gocb_ref.rsplit("/", 1)[-1] if "/" in gocb_ref else gocb_ref
            parts.append(short_ref)

        if simulation:
            parts.append("[TEST]")

        if has_hmac:
            parts.append("[HMAC]")

        if values:
            parts.append(f"[{','.join(values)}]")

        return " ".join(parts)
