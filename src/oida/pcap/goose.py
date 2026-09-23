"""
IEC 61850 GOOSE Passive Listener (PyShark-based).

Passively monitors GOOSE (Generic Object Oriented Substation Event) traffic
to identify:
- IEDs (Intelligent Electronic Devices) publishing GOOSE frames
- GOOSE Control Block References (GoCBRef) in use
- Dataset references and data values
- State transitions (StNum changes) vs heartbeat retransmissions (SqNum)
- Test mode usage and configuration revisions
- Security anomalies (replay attacks, config mismatches)

GOOSE is a Layer 2 multicast protocol (EtherType 0x88B8) used in IEC 61850
power substations for fast event distribution (typically <4ms). It has no
IP/TCP layers -- frames are identified by source MAC and APPID.

Protocol format:
- Ethernet header: dst MAC (multicast 01:0c:cd:01:xx:xx), src MAC, EtherType 0x88B8
- GOOSE header: APPID (2), Length (2), Reserved1 (2), Reserved2 (2)
- GOOSE PDU (ASN.1 BER encoded):
  - gocbRef: GOOSE Control Block Reference (identifies the publisher)
  - timeAllowedtoLive: TTL in ms (receiver should discard if exceeded)
  - datSet: Dataset reference
  - goID: GOOSE ID (optional human-readable identifier)
  - t: Timestamp of the event
  - stNum: State Number (increments on value change)
  - sqNum: Sequence Number (resets to 0 on state change, increments on retransmit)
  - simulation/test: Test flag (true = simulated data, not real process values)
  - confRev: Configuration Revision (must match between publisher and subscriber)
  - ndsCom: Needs Commissioning flag
  - numDatSetEntries: Number of data entries in allData
  - allData: The actual data values (boolean, integer, float, bitstring, etc.)

Security notes:
- GOOSE has NO authentication by default -- any device on the LAN can inject frames
- IEC 62351-6 adds HMAC authentication but is rarely deployed in practice
- Test mode (simulation=true) in production is a red flag
- StNum rollback (decrease) may indicate a replay attack
- confRev mismatch between IEDs can cause protection failures

tshark fields used:
- goose.appid: Application ID (FT_UINT16)
- goose.gocbRef: GOOSE Control Block Reference (FT_STRING)
- goose.datSet: Dataset reference (FT_STRING)
- goose.goID: GOOSE ID (FT_STRING)
- goose.stNum: State Number (FT_UINT32)
- goose.sqNum: Sequence Number (FT_UINT32)
- goose.simulation: Test/simulation flag (FT_BOOLEAN)
- goose.confRev: Configuration Revision (FT_INT32)
- goose.ndsCom: Needs Commissioning (FT_BOOLEAN)
- goose.numDatSetEntries: Number of data entries (FT_INT32)
- goose.timeAllowedtoLive: Time to live in ms (FT_INT32)
- goose.t: Event timestamp (FT_STRING)
- goose.allData: Top-level data sequence count (FT_UINT32)
- goose.structure: Nested structure member counts (FT_UINT32)
- goose.boolean: Boolean data values (FT_BOOLEAN)
- goose.integer: Integer data values (FT_INT32)
- goose.unsigned: Unsigned data values (FT_INT32)
- goose.floating_point: Floating point data (FT_BYTES)
- goose.real: Real/double data values (FT_DOUBLE)
- goose.float_value: Float data values (FT_FLOAT)
- goose.bit_string: Bitstring data values (FT_BYTES)
- goose.visible_string: Visible string data (FT_STRING)

References:
- IEC 61850-8-1: Communication networks and systems -- Part 8-1: GOOSE
- IEC 62351-6: Security for IEC 61850 (GOOSE authentication)
- Wireshark dissector: packet-goose.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ._goose_common import collect_field_values, format_bool_display
from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor


@dataclass
class GOOSEPublisher:
    """Track a GOOSE publisher (identified by GoCBRef)."""

    src_mac: str
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
    first_seen: str = ""
    last_seen: str = ""


class GOOSEPassiveListener(PySharkListenerBase):
    """Passive IEC 61850 GOOSE traffic listener (PyShark-based).

    Monitors GOOSE multicast traffic without sending packets to:
    - Identify IEDs publishing GOOSE frames by source MAC and APPID
    - Track GOOSE Control Block References (GoCBRef) and datasets
    - Monitor state transitions (StNum) vs heartbeat retransmissions (SqNum)
    - Detect test/simulation mode frames in production
    - Alert on StNum rollback (possible replay attack)
    - Alert on configuration revision mismatches
    - Extract data values from allData (boolean, integer, float, etc.)

    GOOSE is Layer 2 only (EtherType 0x88B8) -- there are no IP addresses.
    Devices are keyed by source MAC address. Flow IDs use MAC addresses.

    Usage:
        listener = GOOSEPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access publisher statistics
        for pub in listener.publishers.values():
            print(f"{pub.src_mac} GoCBRef={pub.gocb_ref}")
            print(f"  State changes: {pub.state_changes}")
            print(f"  Test frames: {pub.test_frames}")

    Data stored in device.goose_passive_data:
        {
            "role": "publisher",
            "gocb_refs": ["IED1/LLN0$GO$GoCB01"],
            "datasets": ["IED1/LLN0$DataSet01"],
            "appid": 1,
            "conf_revs": [1],
            "state_changes": 42,
            "total_frames": 1000,
            "test_frames": 0,
            "protocol": "GOOSE/L2",
        }
    """

    PROTOCOL_NAME = "goose"
    DISPLAY_FILTER = "goose"
    REQUIRED_LAYERS = ("goose",)
    PROTOCOL_COLUMNS = (
        "gocbref",
        "dataset",
        "st_num",
        "sq_num",
        "test",
        "values",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize GOOSE passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        # Track publishers by GoCBRef (unique per GOOSE control block)
        self.publishers: Dict[str, GOOSEPublisher] = {}
        # Security tracking: per-GoCBRef confRev history for mismatch detection
        self._conf_rev_by_gocb: Dict[str, Set[int]] = {}

    def process_packet(self, packet) -> None:
        """Process a GOOSE packet using PyShark dissection."""
        if not hasattr(packet, "goose"):
            return

        goose_layer = packet.goose

        # The 'goose' layer is shared with R-GOOSE (routable GOOSE over
        # IP/UDP, see rgoose.py). A combined-pcap run feeds R-GOOSE frames
        # here too; reject those so they aren't double-counted as phantom
        # L2 publishers (mirrors rgoose.py's reciprocal "no IP" guard).
        src_ip, _dst_ip = self.get_ip_info(packet)
        if src_ip:
            self.logger.debug("goose: dropping GOOSE packet with IP layer (R-GOOSE, not L2 GOOSE)")
            return

        # GOOSE is Layer 2 -- extract MAC addresses (no IP)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not src_mac:
            return

        # Extract GOOSE header fields
        appid = self._parse_int(self.get_field(goose_layer, "appid"), 0)
        gocb_ref = str(self.get_field(goose_layer, "gocbRef") or "")
        dat_set = str(self.get_field(goose_layer, "datSet") or "")
        go_id = str(self.get_field(goose_layer, "goID") or "")
        st_num = self._parse_int(self.get_field(goose_layer, "stNum"), 0)
        sq_num = self._parse_int(self.get_field(goose_layer, "sqNum"), 0)
        conf_rev = self._parse_int(self.get_field(goose_layer, "confRev"), 0)
        ttl_ms = self._parse_int(self.get_field(goose_layer, "timeAllowedtoLive"), 0)
        num_entries = self._parse_int(self.get_field(goose_layer, "numDatSetEntries"), 0)

        # Parse boolean flags
        simulation = self._parse_bool(self.get_field(goose_layer, "simulation"))
        nds_com = self._parse_bool(self.get_field(goose_layer, "ndsCom"))

        # Extract allData count (number of top-level data entries in the sequence)
        all_data_count = self._parse_int(self.get_field(goose_layer, "allData"), 0)

        # Extract structure counts (nested data sequences within allData)
        structure_counts = self._extract_structure_counts(goose_layer)

        # Extract data values from allData
        values = self._extract_all_data(goose_layer)

        # Use GoCBRef as the publisher key (unique per control block)
        # Fall back to src_mac:appid if GoCBRef is empty
        pub_key = gocb_ref if gocb_ref else f"{src_mac}:0x{appid:04x}"

        # Update publisher state
        publisher = self._update_publisher(
            pub_key,
            src_mac,
            gocb_ref,
            appid,
            dat_set,
            go_id,
            st_num,
            sq_num,
            conf_rev,
            simulation,
            nds_com,
        )

        # Determine direction label for display
        # GOOSE is publish-only (multicast), so all frames are "pub" (publish)
        direction = "request"  # publisher -> subscribers
        is_state_change = sq_num == 0 and publisher.total_frames > 1

        # Build flow ID from MAC (no IP/TCP for GOOSE)
        flow_id = self.get_flow_id(packet)

        # Record interaction
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
            "all_data_count": all_data_count,
            "appid": appid,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        if values:
            details["values"] = values
        if go_id:
            details["go_id"] = go_id
        if structure_counts:
            details["structure_counts"] = structure_counts

        operation = "state_change" if is_state_change else "heartbeat"
        summary = self._build_summary(
            gocb_ref,
            st_num,
            sq_num,
            simulation,
            is_state_change,
            values,
        )
        self._record_interaction(
            now,
            src_mac,
            dst_mac,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
        )

        # Update device entry
        self._update_device(src_mac, pub_key, publisher)

    # ------------------------------------------------------------------
    # Publisher tracking
    # ------------------------------------------------------------------

    def _update_publisher(
        self,
        pub_key: str,
        src_mac: str,
        gocb_ref: str,
        appid: int,
        dat_set: str,
        go_id: str,
        st_num: int,
        sq_num: int,
        conf_rev: int,
        simulation: bool,
        nds_com: bool,
    ) -> GOOSEPublisher:
        """Update or create a GOOSE publisher entry."""
        now = datetime.now().isoformat()

        if pub_key not in self.publishers:
            self.publishers[pub_key] = GOOSEPublisher(
                src_mac=src_mac,
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

        # Track confRev for mismatch detection
        if gocb_ref and conf_rev:
            self._conf_rev_by_gocb.setdefault(gocb_ref, set()).add(conf_rev)

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

        return pub

    # ------------------------------------------------------------------
    # Data value extraction
    # ------------------------------------------------------------------

    def _extract_all_data(self, goose_layer) -> List[str]:
        """Extract data values from GOOSE allData entries.

        GOOSE allData is ASN.1 BER encoded. tshark decodes individual
        data entries into typed fields: boolean, integer, unsigned,
        floating_point, real, float_value, bit_string, visible_string.

        Each typed field is extracted via an explicit get_field() probe
        before collecting all instances.
        """
        values: List[str] = []

        # Boolean values (goose.boolean)
        if self.get_field(goose_layer, "boolean", None) is not None:
            self._collect_field_values(goose_layer, "boolean", values, self._format_bool)

        # Integer values (goose.integer)
        if self.get_field(goose_layer, "integer", None) is not None:
            self._collect_field_values(goose_layer, "integer", values)

        # Unsigned integer values (goose.unsigned)
        if self.get_field(goose_layer, "unsigned", None) is not None:
            self._collect_field_values(goose_layer, "unsigned", values)

        # Float values (goose.float_value, decoded by tshark)
        if self.get_field(goose_layer, "float_value", None) is not None:
            self._collect_field_values(goose_layer, "float_value", values, self._format_float)

        # Real (double) values (goose.real)
        if self.get_field(goose_layer, "real", None) is not None:
            self._collect_field_values(goose_layer, "real", values, self._format_float)

        # Bitstring values (goose.bit_string)
        if self.get_field(goose_layer, "bit_string", None) is not None:
            self._collect_field_values(goose_layer, "bit_string", values)

        # Visible string values (goose.visible_string)
        if self.get_field(goose_layer, "visible_string", None) is not None:
            self._collect_field_values(goose_layer, "visible_string", values)

        return values

    def _extract_structure_counts(self, goose_layer) -> List[int]:
        """Extract structure member counts from nested GOOSE data sequences.

        The goose.structure field (FT_UINT32) indicates how many members
        each nested SEQUENCE_OF_Data structure contains. These counts are
        important for understanding the IEC 61850 data model layout.

        Handles EK mode (Python list) and XML mode (.all_fields).
        """
        raw_attr = getattr(goose_layer, "structure", None)
        if raw_attr is None:
            return []

        counts: List[int] = []

        # EK mode: field is a Python list of ints
        if isinstance(raw_attr, list):
            for item in raw_attr:
                counts.append(self._parse_int(item, 0))
            return counts

        # XML mode: try .all_fields iterator
        try:
            for fld in raw_attr.all_fields:
                counts.append(self._parse_int(str(fld.show), 0))
        except Exception:
            val = self._parse_int(str(raw_attr), 0)
            if val:
                counts.append(val)
        return counts

    def _collect_field_values(
        self,
        layer,
        field_name: str,
        values: List[str],
        formatter=None,
    ) -> None:
        """Collect all instances of a field from a PyShark layer into values list.

        Handles both EK mode (fields are Python lists) and XML mode
        (fields have .all_fields iterators).
        """
        collect_field_values(layer, field_name, values, formatter)

    @staticmethod
    def _format_bool(val: str) -> str:
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

        # Test flag
        test = d.get("test", False)
        test_str = "YES" if test else ""

        # Values — show all, no truncation; use " | " to avoid CSV ambiguity
        values = d.get("values", [])
        val_str = " | ".join(values) if isinstance(values, list) else ""

        return [
            gocb_ref,
            dataset,
            st_num,
            sq_num,
            test_str,
            val_str,
        ]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with GOOSE-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        # Alert: test/simulation frames detected
        for pub in self.publishers.values():
            if pub.test_frames > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "goose_test_mode",
                        "message": (
                            f"GOOSE TEST MODE: {pub.src_mac} GoCBRef={pub.gocb_ref} "
                            f"sent {pub.test_frames} test frames "
                            f"(simulation=true may indicate spoofing or misconfiguration)"
                        ),
                    }
                )

        # Alert: StNum rollback (possible replay attack)
        for pub in self.publishers.values():
            if pub.st_num_rollbacks > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "goose_replay",
                        "message": (
                            f"GOOSE REPLAY RISK: {pub.src_mac} GoCBRef={pub.gocb_ref} "
                            f"StNum decreased {pub.st_num_rollbacks} time(s) "
                            f"(possible replay attack or IED restart)"
                        ),
                    }
                )

        # Alert: configuration revision mismatch (multiple confRevs for same GoCBRef)
        for gocb_ref, revs in self._conf_rev_by_gocb.items():
            if len(revs) > 1:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "goose_confrev_mismatch",
                        "message": (
                            f"GOOSE CONFIG MISMATCH: GoCBRef={gocb_ref} "
                            f"has multiple confRev values: {sorted(revs)} "
                            f"(subscribers may reject data or malfunction)"
                        ),
                    }
                )

        # Alert: needs commissioning flag seen
        for pub in self.publishers.values():
            if pub.nds_com_seen:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "goose_commissioning",
                        "message": (
                            f"GOOSE COMMISSIONING: {pub.src_mac} GoCBRef={pub.gocb_ref} "
                            f"has ndsCom=true (device needs commissioning)"
                        ),
                    }
                )

        # Clean up empty results
        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, src_mac: str, pub_key: str, publisher: GOOSEPublisher) -> None:
        """Update or create a device entry for a GOOSE publisher."""
        if not src_mac:
            return

        device_key = f"goose-ied:{src_mac}"
        vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        device, _is_new = self._ensure_device(
            device_key,
            "",  # No IP address for GOOSE (Layer 2 only)
            mac=src_mac,
            device_type="IEC 61850 IED (GOOSE Publisher)",
            manufacturer=vendor if vendor else "",
        )

        # Aggregate data from all publishers for this MAC
        device.goose_passive_data = self._build_device_data(src_mac)

        if _is_new:
            self.logger.debug(
                f"GOOSE: IED {src_mac} GoCBRef={publisher.gocb_ref} APPID=0x{publisher.appid:04x}"
            )

    def _build_device_data(self, src_mac: str) -> Dict[str, Any]:
        """Build goose_passive_data dict aggregated across all publishers for a MAC."""
        gocb_refs: List[str] = []
        datasets: Set[str] = set()
        go_ids: Set[str] = set()
        conf_revs: Set[int] = set()
        appids: Set[int] = set()
        total_frames = 0
        state_changes = 0
        test_frames = 0
        st_num_rollbacks = 0
        first_seen = ""
        last_seen = ""

        for pub in self.publishers.values():
            if pub.src_mac != src_mac:
                continue
            if pub.gocb_ref:
                gocb_refs.append(pub.gocb_ref)
            datasets.update(pub.datasets)
            go_ids.update(pub.go_ids)
            conf_revs.update(pub.conf_revs)
            if pub.appid:
                appids.add(pub.appid)
            total_frames += pub.total_frames
            state_changes += pub.state_changes
            test_frames += pub.test_frames
            st_num_rollbacks += pub.st_num_rollbacks
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
            "state_changes": state_changes,
            "total_frames": total_frames,
            "test_frames": test_frames,
            "st_num_rollbacks": st_num_rollbacks,
            "protocol": "GOOSE/L2",
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
        values: List[str],
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = []

        if is_state_change:
            parts.append(f"STATE_CHANGE StNum={st_num}")
        else:
            parts.append(f"StNum={st_num} SqNum={sq_num}")

        if gocb_ref:
            # Show last component for brevity
            short_ref = gocb_ref.rsplit("/", 1)[-1] if "/" in gocb_ref else gocb_ref
            parts.append(short_ref)

        if simulation:
            parts.append("[TEST]")

        if values:
            parts.append(f"[{','.join(values)}]")

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Parse helpers
    # ------------------------------------------------------------------
