"""
GE EGD (Ethernet Global Data) Passive Listener (PyShark-based).

Passively monitors GE Ethernet Global Data traffic to identify:
- EGD producers (data sources) and the consumers/groups they publish to
- Producer IDs and exchange IDs (the produced data blocks)
- Production status codes and configuration signatures
- Exchange update timeline (stale-data / status-change detection)

EGD is a UDP publish protocol (GE PACSystems, Series 90-30/70, RX3i/RX7i).
A *producer* periodically broadcasts/multicasts an *exchange* (a fixed data
block) to one or more *consumers*.  There is no request/response -- every
packet is a production, so the source is always the producer.

Protocol format (UDP 18246, header is 32 bytes, little-endian except pid):
- type (1) + ver (1)   -- guarded by tshark on the 0x0d01 signature
- request id (2)
- producer id (4, rendered as an IPv4 address by tshark)
- exchange id (4)
- timestamp (8)        -- 0 => "no timestamp" (egd.notime)
- status (4)
- config signature (4)
- reserved (4)
- data (variable)

tshark fields used (egd layer):
- egd.type / egd.ver : PDU type and version
- egd.rid            : request id
- egd.pid            : producer id (IPv4-formatted)
- egd.exid           : exchange id
- egd.time / egd.notime : production timestamp
- egd.stat           : status code
- egd.csig           : configuration signature

Reference: https://en.wikipedia.org/wiki/Ethernet_Global_Data_Protocol
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# EGD production status codes -- verbatim from the packet-egd.c value_string
# (`tshark -G values | grep egd.stat`).  The previous 4-entry table mislabeled
# code 1 (a HEALTHY state) as "resource in use" and invented a code 20.
EGD_STATUS = {
    "0": "No new status event has occurred",
    "1": "No error currently exists",
    "2": "No error, data consumed",
    "3": "SNTP error",
    "4": "Specification error",
    "6": "Data refresh error",
    "7": "Data refresh period exceeded",
    "10": "IP Layer not currently initialized",
    "12": "Lack of resource error",
    "16": "Name Resolution in progress",
    "18": "Loss of Ethernet Interface error",
    "22": "Ethernet Interface does not support EGD",
    "26": "No Response from Ethernet Interface",
    "28": "Failed to create an exchange.",
    "30": "Configured exchange deleted.",
}

# Codes 0/1/2 are all normal operation -- only everything else is a producer
# fault.  Gating on "not 0" flagged healthy producers reporting 1 or 2.
EGD_HEALTHY_STATUS = frozenset({"0", "1", "2"})


class EGDPassiveListener(PySharkListenerBase):
    """Passive GE EGD traffic listener (PyShark-based).

    Monitors EGD production traffic to:
    - Identify producers and the exchanges they publish
    - Track producer/exchange IDs and status codes
    - Flag non-zero production status (a producer error condition)

    Data stored in device.egd_passive_data:
        {
            "role": "producer",
            "producer_id": "10.11.12.13",
            "exchange_ids": [100, 200],
            "status_seen": ["no error"],
            "protocol": "EGD/UDP",
        }
    """

    PROTOCOL_NAME = "egd"
    DISPLAY_FILTER = "egd"
    REQUIRED_LAYERS = ("egd",)
    SERVER_PORTS = (18246,)
    PROTOCOL_COLUMNS = ("producer", "exchange", "status", "csig", "timestamp")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Per-producer aggregate: producer_id -> {exchanges, statuses, ...}
        self.producers: Dict[str, Dict[str, Any]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        return [
            d.get("producer_id", "?"),
            d.get("exchange_id", "?"),
            d.get("status_name", d.get("status", "?")),
            d.get("config_signature", "?"),
            d.get("timestamp", "?"),
        ]

    @staticmethod
    def _is_fault_status(status: str) -> bool:
        """True only for genuine producer-fault status codes.

        Codes 0/1/2 ("no new status event", "no error currently exists",
        "no error, data consumed") are all healthy per the egd.stat registry.
        """
        s = str(status).strip()
        return bool(s) and s not in EGD_HEALTHY_STATUS

    def process_packet(self, packet) -> None:
        """Process an EGD production packet."""
        if not hasattr(packet, "egd"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        egd = packet.egd
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)

        producer_id = str(self.get_field(egd, "pid", "") or "")
        exchange_id = str(self.get_field(egd, "exid", "") or "")
        request_id = str(self.get_field(egd, "rid", "") or "")
        pdu_type = str(self.get_field(egd, "type", "") or "")
        version = str(self.get_field(egd, "ver", "") or "")
        status = str(self.get_field(egd, "stat", "") or "")
        config_sig = str(self.get_field(egd, "csig", "") or "")

        # Timestamp: egd.time when present, else the notime marker.
        ts = self.get_field(egd, "time", None)
        if ts is None:
            ts = self.get_field(egd, "notime", None)
        timestamp = str(ts) if ts is not None else ""

        status_name = EGD_STATUS.get(status.strip(), status)

        operation = f"EGD produce exid={exchange_id}"
        if self._is_fault_status(status):
            operation += f" status={status_name}"

        details: Dict[str, Any] = {
            "producer_id": producer_id,
            "exchange_id": exchange_id,
            "request_id": request_id,
            "pdu_type": pdu_type,
            "version": version,
            "status": status,
            "status_name": status_name,
            "config_signature": config_sig,
            "timestamp": timestamp,
        }

        now = datetime.now().isoformat()
        summary = f"EGD producer={producer_id or src_ip} exid={exchange_id}"
        if self._is_fault_status(status):
            summary += f" STATUS={status_name}"

        # EGD is publish-only: the source is always the producer (server role).
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Non-zero production status is a producer fault worth surfacing.
        if self._is_fault_status(status):
            self.logger.warning(
                f"EGD non-zero status from producer {producer_id or src_ip}: "
                f"{status_name} (exid={exchange_id})"
            )

        self._track_producer(producer_id, exchange_id, status_name, config_sig)

        # Register the producer device (keyed on the sending IP).
        if is_valid_discovered_ip(src_ip):
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"egd-producer:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type="EGD Producer",
                manufacturer=vendor if vendor and vendor != "Unknown" else "GE",
                data_attr="egd_passive_data",
                protocol_data={
                    "role": "producer",
                    "producer_id": producer_id,
                    "exchange_ids": sorted(
                        self.producers.get(producer_id, {}).get("exchanges", set())
                    ),
                    "status_seen": sorted(
                        self.producers.get(producer_id, {}).get("statuses", set())
                    ),
                    "protocol": "EGD/UDP",
                },
            )

        # The consumer endpoint (unicast destinations only; skip bcast/mcast).
        if is_valid_discovered_ip(dst_ip):
            self._ensure_device(
                f"egd-consumer:{dst_ip}",
                dst_ip,
                mac=dst_mac or "",
                device_type="EGD Consumer",
                data_attr="egd_passive_data",
                protocol_data={"role": "consumer", "protocol": "EGD/UDP"},
            )

    def _track_producer(
        self, producer_id: str, exchange_id: str, status_name: str, config_sig: str
    ) -> None:
        """Aggregate exchanges/statuses seen per producer."""
        if not producer_id:
            return
        info = self.producers.setdefault(
            producer_id,
            {"exchanges": set(), "statuses": set(), "config_sigs": set(), "count": 0},
        )
        if exchange_id:
            info["exchanges"].add(exchange_id)
        info["statuses"].add(status_name)
        if config_sig:
            info["config_sigs"].add(config_sig)
        info["count"] += 1

    def harvest(self) -> Dict[str, Any]:
        """Add a producer-inventory table on top of the base alerts."""
        result = super().harvest() or {}
        tables = result.setdefault("tables", [])
        if self.producers:
            rows = []
            for pid, info in sorted(self.producers.items()):
                rows.append(
                    [
                        pid,
                        ", ".join(sorted(info["exchanges"])) or "-",
                        ", ".join(sorted(info["statuses"])) or "-",
                        str(info["count"]),
                    ]
                )
            tables.append(
                {
                    "title": "EGD Producers",
                    "headers": ["Producer ID", "Exchanges", "Status", "Packets"],
                    "rows": rows,
                }
            )
        return result if (result.get("tables") or result.get("alerts")) else {}
