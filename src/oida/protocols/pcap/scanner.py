"""
PCAP analysis scanner and NXC-style connection class.

Contains:
- PcapScanner: Offline PCAP file analyzer using PyShark pipeline
- pcap: NXC-style callable class for CLI integration
"""

import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from oida.connection import SerialConnection
from oida.utils.result_types import ScanResult
from oida.utils.export_utils import configure as configure_export
from oida.utils.export_utils import export_data, get_export_path
from oida.utils.ics_logger import get_logger, get_module_logger, set_progress_active
from oida.utils.lazy_import import lazy_import

logger = get_module_logger(__name__)

_pyshark = lazy_import("pyshark", "pcap", install_hint="pip install oida-ics[pcap]")
_file_extraction = lazy_import(
    "oida.protocols.discovery.file_extraction", "pcap", install_hint="pip install oida-ics[pcap]"
)

# Default decode-as hints for common ICS protocols on non-standard ports.
DEFAULT_DECODE_AS_HINTS: Dict[str, str] = {
    "tcp.port==8883": "ssl",
    "tcp.port==4843": "opcua",
}


def _extract_tshark_error(exc: Exception) -> str:
    """Extract the tshark error line from a TSharkCrashException message."""
    for line in str(exc).splitlines():
        if line.strip().startswith("Last error line:"):
            return line.strip().removeprefix("Last error line:").strip()
    return str(exc).splitlines()[0] if str(exc) else "Unknown error"


class PcapScanner:
    """Offline PCAP file analyzer using PyShark pipeline.

    Processes pcap/pcapng files through passive listeners for credential
    extraction, TLS analysis, DNS records, ICS protocol traffic, and more.

    Usage:
        scanner = PcapScanner("capture.pcap")
        results = scanner.run_scan()
    """

    def __init__(self, pcap_file: str, args: Optional[Dict[str, Any]] = None):
        self.pcap_file = pcap_file
        self.args = args or {}
        self.logger = get_logger(
            protocol="PCAP",
            host="",
            port=0,
        )
        self.discovered_devices: Dict[str, Any] = {}
        self._endpoints: Dict[str, str] = {}  # IP -> MAC for endpoint tracking
        self.results: Dict[str, Any] = {
            "pcap_file": pcap_file,
            "scan_mode": ["pcap-replay"],
            "protocols_used": [],
            "devices": [],
        }

    @staticmethod
    def _get_packet_count(pcap_file: str) -> Optional[int]:
        """Get packet count via capinfos (header-only, no full decode)."""
        capinfos = shutil.which("capinfos")
        if not capinfos:
            return None
        try:
            out = subprocess.run(
                [capinfos, "-c", "-T", "-m", pcap_file],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if out.returncode == 0:
                # CSV: "filename,count"
                line = out.stdout.strip().splitlines()[-1]
                return int(line.split(",")[-1])
        except Exception as e:
            logger.debug("capinfos failed: %s", e)
        return None

    def run_scan(self) -> Dict[str, Any]:
        """Run full PCAP analysis."""
        # Handle --list-listeners before file validation
        if self.args.get("list_listeners"):
            self._print_listeners()
            return self.results

        if not os.path.isfile(self.pcap_file):
            self.logger.fail(f"PCAP file not found: {self.pcap_file}")
            return self.results

        # Honor -W/--full-width when rendering console tables (e.g. the
        # Discovered Assets table). pcap writes file exports directly in cli.py
        # and never relies on the export_utils global config for output_dir/fmt,
        # so configuring it here only affects console truncation -- but pass
        # through the resolved output_dir anyway so this call doesn't null out
        # the process-global output_dir the top-level CLI already configured
        # (configure() with output_dir=None resets it), which a few helpers
        # below (get_export_path for hashcat/ipv4/ipv6) still consult.
        configure_export(
            output_dir=self.args.get("output") or self.args.get("output_dir"),
            logger=self.logger,
            full_width=bool(self.args.get("full_width", False)),
        )

        file_size = os.path.getsize(self.pcap_file)
        self.logger.debug("run_scan: file=%s size=%d bytes", self.pcap_file, file_size)
        self.logger.debug("run_scan: args=%s", list(self.args.keys()))
        enabled = [k for k in ("extract_files",) if self.args.get(k)]
        self.logger.debug("run_scan: optional extractions enabled: %s", enabled or "none")

        self.logger.info(f"PCAP analysis: {self.pcap_file}")

        # Initialize traffic statistics
        from oida.protocols.discovery.stats import PassiveStatistics

        # Run PyShark pipeline with retry on tshark crash (intermittent retcode 255).
        # Truncated pcap files ("cut short") always exit non-zero — don't retry those.
        max_retries = 2
        scan_start = time.time()
        packet_count = 0
        for attempt in range(max_retries + 1):
            self.stats = PassiveStatistics(nxc_logger=self.logger)
            try:
                packet_count = self._run_pyshark_pipeline()
                break
            except Exception as e:
                err_msg = str(e).lower()
                if "cut short" in err_msg or "truncated" in err_msg:
                    self.logger.info("PCAP file appears truncated (incomplete final packet)")
                    break
                # File format errors — show tshark message, don't retry
                if "isn't a capture file" in err_msg or "not a capture file" in err_msg:
                    self.logger.fail(_extract_tshark_error(e))
                    break
                # Only retry a genuine tshark crash (retcode/crashed). Any other
                # exception (e.g. an AttributeError/KeyError in our own pipeline)
                # is not transient -- propagate it instead of burning retries on a
                # misleading "tshark crashed" message that hides the real error.
                is_crash = "crashed" in err_msg or "retcode" in err_msg
                if not is_crash:
                    raise
                if attempt < max_retries:
                    self.logger.info(
                        f"tshark crashed, retrying ({attempt + 2}/{max_retries + 1})..."
                    )
                    time.sleep(0.5)
                    continue
                # Final attempt exhausted — show clean tshark error
                self.logger.fail(_extract_tshark_error(e))
        elapsed = time.time() - scan_start
        self.logger.debug(
            "run_scan: pyshark pipeline completed in %.2fs (%d packets)", elapsed, packet_count
        )

        # Optional extractions (these do real extra work).
        # -e/--extract-all and -E/--extract-files share the extract_files dest.
        if self.args.get("extract_files"):
            self._run_file_extraction()

        # Print asset inventory (opt-in via -A/--assets)
        # Call unconditionally when --assets is set; _report_assets merges
        # endpoint-tracked IPs and handles the empty case internally.
        # Must run BEFORE results["devices"]/statistics are built below --
        # _report_assets() adds endpoint-only devices (IPs seen on the wire
        # with no protocol-level listener match) to self.discovered_devices,
        # and those need to make it into the JSON/statistics output too, not
        # just the console/CSV asset table.
        if self.args.get("assets"):
            self._report_assets()

        # Print traffic statistics (opt-in via -S/--stats)
        if self.args.get("stats") and self.stats.total_packets > 0:
            self.stats.print_summary(logger=self.logger)
            # Register the stats tables so they reach file export too, not
            # just the console render (cli.py exports results["tables"]).
            if "tables" not in self.results:
                self.results["tables"] = []
            self.results["tables"].extend(self.stats.get_tables())

        # Build device results (convert to dicts for JSON serialization).
        # Use vars() instead of dataclasses.asdict() because listeners add
        # dynamic attributes (e.g. mms_passive_data) not in the dataclass schema.
        if self.discovered_devices:
            self.results["devices"] = [
                {k: v for k, v in vars(d).items() if v not in (None, "", [], {}, ())}
                for d in self.discovered_devices.values()
            ]

        self.results["statistics"] = {
            "total_devices": len(self.discovered_devices),
            "packets_processed": packet_count,
            "pcap_file": self.pcap_file,
        }

        # Include traffic statistics
        self.results["traffic_statistics"] = self.stats.to_dict()

        self.logger.debug(
            "run_scan: finished — %d devices, %d protocols detected",
            len(self.discovered_devices),
            len(self.results.get("protocols_used", [])),
        )
        return self.results

    def _print_listeners(self) -> None:
        """Print available listeners and exit."""
        from oida.protocols.pcap.listener_registry import list_listeners, CATEGORIES

        listeners = list_listeners()
        self.logger.info(f"Available listeners ({len(listeners)}):")
        self.logger.info(f"Categories: {', '.join(sorted(CATEGORIES))}")
        self.logger.info("")

        by_cat: Dict[str, List] = {}
        for entry in listeners:
            cat = entry["category"]
            by_cat.setdefault(cat, []).append(entry)

        for cat in sorted(by_cat):
            self.logger.info(f"  [{cat}]")
            for entry in by_cat[cat]:
                tags = ", ".join(t for t in entry["tags"] if t != cat)
                self.logger.info(f"    {entry['name']:<16} tags: {tags}")
            self.logger.info("")

    def _resolve_listener_names(self):
        """Resolve which listeners to activate based on args."""
        from oida.protocols.pcap.listener_registry import resolve_listener_names

        protocols = None
        if self.args.get("protocols"):
            protocols = [p.strip() for p in self.args["protocols"].split(",")]

        category = None
        if self.args.get("category"):
            category = [c.strip() for c in self.args["category"].split(",")]

        exclude = None
        if self.args.get("exclude"):
            exclude = [e.strip() for e in self.args["exclude"].split(",")]

        quick = self.args.get("quick", False)

        self.logger.debug(
            "_resolve_listener_names: protocols=%s category=%s quick=%s exclude=%s",
            protocols,
            category,
            quick,
            exclude,
        )

        names = resolve_listener_names(
            protocols=protocols,
            category=category,
            quick=quick,
            exclude=exclude,
            logger=self.logger,
        )
        self.logger.debug(
            "_resolve_listener_names: resolved %d listeners: %s", len(names), sorted(names)
        )
        return names

    def _kill_capture_processes(self, capture) -> None:
        """Kill the tshark subprocesses owned by a pyshark capture and clear the
        list, so an orphaned capture does not trigger noisy asyncio __del__
        teardown when it is later garbage-collected.
        """
        if capture is None:
            return
        for proc in getattr(capture, "_running_processes", []):
            try:
                proc.kill()
            except Exception as e:
                self.logger.debug(f"proc.kill(): {e}")
        try:
            capture._running_processes.clear()
        except Exception as e:
            self.logger.debug(f"capture._running_processes.clear(): {e}")

    def _filter_supported_by_tshark(self, display_filter: str) -> Optional[str]:
        """Return *display_filter* if the local tshark accepts it, else None.

        The combined listener filter is only a performance pre-filter, so if any
        term names a protocol this tshark build doesn't have (which makes tshark
        reject the entire filter, retcode 4), it is safer to drop the whole
        filter and let every packet through than to abort the scan. Listeners
        still gate packets themselves, so nothing is missed -- only slower.

        A valid filter is confirmed with one bounded ``tshark -c 1`` check
        (invalid filters fail instantly, before any packet is read). Any
        non-filter error (or no tshark on PATH) leaves the filter untouched so
        the pipeline's own error handling still surfaces it.
        """
        tshark = shutil.which("tshark")
        if not tshark:
            return display_filter
        try:
            result = subprocess.run(
                [tshark, "-Y", display_filter, "-r", self.pcap_file, "-c", "1"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except Exception as e:  # timeout / spawn failure -> keep filter, don't block
            self.logger.debug("display_filter validation skipped: %s", e)
            return display_filter
        stderr = result.stderr or ""
        if result.returncode == 0 or "packet count is zero" in stderr:
            return display_filter
        if "is not a valid protocol or protocol field" in stderr:
            import re

            unknown = re.findall(r'"([^"]+)" is not a valid protocol', stderr)
            self.logger.debug(
                "display_filter names protocol(s) this tshark lacks (%s); "
                "dropping the pre-filter and processing all packets",
                ", ".join(unknown) or "unknown",
            )
            return None
        # Different tshark complaint (bad file, etc.) -- leave it to the pipeline.
        return display_filter

    def _run_pyshark_pipeline(self) -> int:
        """Process all protocols with PyShark-based listeners."""
        listeners = self._create_pyshark_listeners()
        if not listeners:
            # Almost always a filter that matched nothing (e.g. `--protocols typo` /
            # `--category bogus`); surface it instead of silently reporting 0
            # results, which reads as "no matching traffic".
            self.logger.fail(
                "No passive listeners resolved from the requested filter -- "
                "run with --list-listeners to see valid names/categories."
            )
            return 0

        self.logger.info(f"PyShark pipeline: {len(listeners)} listeners")
        self.logger.debug("Active listeners: %s", ", ".join(sorted(listeners.keys())))

        if not _pyshark.is_available:
            self.logger.info("PyShark not available - install pyshark: pip install oida-ics[pcap]")
            return 0

        # Pre-fetch total packet count for progress display (header-only, no decode)
        total_packets = self._get_packet_count(self.pcap_file)
        if total_packets:
            self.logger.debug("_run_pyshark_pipeline: capinfos reports %d packets", total_packets)

        try:
            # Bind names referenced by the except handler before any code that
            # could raise, so an early failure (decode_as parsing, pref merge,
            # event-loop setup) classified as a crash cannot mask the real error
            # with an UnboundLocalError.
            packet_count = 0
            capture = None
            self.logger.debug("_run_pyshark_pipeline: opening capture %s", self.pcap_file)
            t0 = time.time()

            # Build decode_as dict for pyshark from defaults + user overrides
            decode_as = dict(DEFAULT_DECODE_AS_HINTS)
            user_decode_as = self.args.get("decode_as")
            if user_decode_as:
                for hint in user_decode_as.split(";"):
                    hint = hint.strip()
                    if not hint:
                        continue
                    # Expect "tcp.port==13600,mqtt" format
                    parts = hint.split(",", 1)
                    if len(parts) == 2:
                        decode_as[parts[0].strip()] = parts[1].strip()
                self.logger.debug("_run_pyshark_pipeline: user decode-as: %s", user_decode_as)

            decode_as_final = {k: v for k, v in decode_as.items() if v}
            if decode_as_final:
                self.logger.debug("_run_pyshark_pipeline: decode_as=%s", decode_as_final)

            progress_interval = 200  # update every N packets
            collect_stats = bool(self.args.get("stats") or self.args.get("assets"))

            # Build layer→listeners dispatch table for fast per-packet routing.
            # Instead of calling all listeners for every packet, we only call
            # listeners whose REQUIRED_LAYERS match the packet's actual layers.
            layer_dispatch: Dict[str, List] = {}  # layer_name -> [listener, ...]
            always_listeners: List = []  # listeners with no REQUIRED_LAYERS
            for listener in listeners.values():
                required = getattr(listener, "REQUIRED_LAYERS", ())
                if required:
                    for layer_name in required:
                        layer_dispatch.setdefault(layer_name, []).append(listener)
                else:
                    always_listeners.append(listener)
            self.logger.debug(
                "_run_pyshark_pipeline: dispatch table: %d layer keys, %d always-on listeners",
                len(layer_dispatch),
                len(always_listeners),
            )

            # Build a combined Wireshark display filter from active listeners so
            # tshark skips packets that no listener cares about (e.g. bare TCP
            # SYN/ACK/FIN).  Disabled when collecting stats (needs every packet)
            # or when --assets is set (need all IPs for complete inventory).
            collect_endpoints = bool(self.args.get("assets"))
            display_filter = None
            if not collect_stats and not collect_endpoints:
                parts: List[str] = []
                for listener in listeners.values():
                    df = getattr(listener, "DISPLAY_FILTER", "")
                    if not df:
                        continue
                    # Skip overly broad filters that would match everything
                    tokens = df.replace("||", " ").replace("|", " ").split()
                    if any(t in ("data", "tcp.payload", "udp.payload") for t in tokens):
                        continue
                    parts.append(f"({df})" if " " in df else df)
                if parts:
                    display_filter = " or ".join(sorted(set(parts)))
                    self.logger.debug(
                        "_run_pyshark_pipeline: display_filter (%d terms): %s",
                        len(parts),
                        display_filter[:120],
                    )
                    # A single listener term naming a protocol this tshark build
                    # lacks (e.g. wsdiscovery on stock Wireshark) makes tshark
                    # reject the WHOLE combined filter (retcode 4) and abort the
                    # scan. Validate once; if unsupported, drop the filter and
                    # process every packet rather than crashing.
                    display_filter = self._filter_supported_by_tshark(display_filter)

            # Collect override_prefs from active listeners (e.g. Modbus needs
            # mbtcp.tcp.port:502 to enable full PDU dissection).
            override_prefs: Dict[str, str] = {}
            for listener in listeners.values():
                prefs = getattr(listener, "OVERRIDE_PREFS", None)
                if prefs:
                    override_prefs.update(prefs)

            # Collect per-listener DECODE_AS hints (ajp, rmi, rsync need their
            # non-standard ports decoded as the matching dissector).
            for listener in listeners.values():
                hints = getattr(listener, "DECODE_AS", None)
                if hints:
                    for filter_expr, dissector in hints.items():
                        decode_as_final.setdefault(filter_expr, dissector)
            if decode_as_final:
                self.logger.debug(
                    "_run_pyshark_pipeline: decode_as after listener merge: %s", decode_as_final
                )

            # Inject the resolved port map into each listener so direction
            # detection (resolve_direction) honours user --decode-as overrides
            # and per-listener OVERRIDE_PREFS in addition to canonical ports.
            for listener in listeners.values():
                configure = getattr(listener, "configure_ports", None)
                if callable(configure):
                    try:
                        configure(decode_as_final)
                    except Exception as e:
                        self.logger.debug("configure_ports failed for listener: %s", e)

            capture_kw: Dict[str, Any] = {
                "keep_packets": False,
                "decode_as": decode_as_final if decode_as_final else None,
                "display_filter": display_filter,
                "override_prefs": override_prefs if override_prefs else None,
            }
            # Routing-protocol keyed-MD5/HMAC hashes (JtR net-md5 / eigrp) need
            # the raw routing-packet bytes as the salt. Enable raw capture only
            # when a routing listener is active, so the per-packet raw-payload
            # cost is not paid by every scan.
            # NB: include_raw works WITH use_ek (raw bytes added alongside the EK
            # fields); do NOT also set use_json -- that switches pyshark to the
            # JSON parser and breaks the listeners' EK-mode field access.
            if {"ospf", "rip", "eigrp"} & set(listeners):
                capture_kw["include_raw"] = True

            # Ensure an asyncio event loop exists for pyshark (it uses asyncio
            # internally).  Previous tests or callers may have consumed/closed
            # the default loop, leaving the thread without one.
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                asyncio.set_event_loop(asyncio.new_event_loop())

            def _open_capture(use_ek: bool):
                if use_ek:
                    return _pyshark.FileCapture(self.pcap_file, use_ek=True, **capture_kw)
                # XML/PDML fallback: pyshark rejects include_raw unless use_ek or
                # use_json is set, and use_json switches to the JSON parser that
                # breaks the listeners' EK-mode field access. So drop raw capture
                # here -- the routing keyed-hash salt (ospf/rip/eigrp) is then
                # unavailable in XML mode, but the rest of the pipeline runs
                # instead of the whole scan aborting.
                xml_kw = {k: v for k, v in capture_kw.items() if k != "include_raw"}
                return _pyshark.FileCapture(self.pcap_file, **xml_kw)

            show_progress = bool(total_packets)

            def _consume(cap) -> None:
                """Run the per-packet dispatch loop, updating packet_count."""
                nonlocal packet_count
                for packet in cap:
                    packet_count += 1

                    if collect_stats:
                        self.stats.process_pyshark_packet(packet)

                    if collect_endpoints:
                        self._track_endpoint(packet)

                    # Layer-based dispatch: only call listeners whose layers match
                    matched_ids: set = set()
                    for layer in packet.layers:
                        for listener in layer_dispatch.get(layer.layer_name.lower(), ()):
                            lid = id(listener)
                            if lid not in matched_ids:
                                matched_ids.add(lid)
                                try:
                                    listener.feed_packet(packet)
                                except Exception as e:
                                    self.logger.debug("PyShark packet feed error: %s", e)
                    for listener in always_listeners:
                        try:
                            listener.feed_packet(packet)
                        except Exception as e:
                            self.logger.debug("PyShark packet feed error: %s", e)

                    if show_progress and packet_count % progress_interval == 0:
                        self.logger.progress(packet_count, total_packets)

            # EK mode: ~18x faster NDJSON parsing vs XML/PDML. Needs tshark 4.6+
            # EK fixes (upstream PRs #744/#743), shipped via the oida-pyshark
            # PyPI package. An EK-incapable tshark can fail EITHER at construction
            # OR only once iteration starts (it emits invalid EK/NDJSON), so fall
            # back to XML in both cases -- detecting the iteration failure before
            # any packet was processed so no listener/stats state is lost.
            use_ek = True
            try:
                capture = _open_capture(use_ek=True)
            except Exception as e:
                self.logger.debug("_run_pyshark_pipeline: EK construction failed, XML: %s", e)
                use_ek = False
                capture = _open_capture(use_ek=False)

            if show_progress:
                set_progress_active(True)

            try:
                _consume(capture)
            except Exception as e:
                if use_ek and packet_count == 0:
                    # EK unusable at iteration time -> re-open in XML and restart.
                    self.logger.debug(
                        "_run_pyshark_pipeline: EK iteration failed before any packet, "
                        "XML fallback: %s",
                        e,
                    )
                    self._kill_capture_processes(capture)
                    try:
                        capture.close()
                    except Exception as ce:
                        self.logger.debug("EK capture close before XML retry: %s", ce)
                    capture = _open_capture(use_ek=False)
                    _consume(capture)
                else:
                    raise

            if show_progress:
                set_progress_active(False)
                self.logger.progress(packet_count, total_packets, end="\n")

            # Close capture; tolerate tshark non-zero exit when packets were
            # already consumed (e.g. truncated pcap files exit with retcode 2
            # after successfully outputting all complete packets).
            try:
                capture.close()
            except Exception as close_err:
                if packet_count > 0:
                    self.logger.debug(
                        "_run_pyshark_pipeline: tshark exited non-zero on close "
                        "(truncated pcap?), %d packets already processed: %s",
                        packet_count,
                        close_err,
                    )
                else:
                    raise

            # Routing listeners (ospf/rip/eigrp) need the raw packet bytes as the
            # net-md5/eigrp salt, but pyshark cannot return EK fields AND raw
            # bytes in one pass. Fill the salts now via a small filtered JSON pass.
            self._fill_routing_salts(listeners)

            elapsed = time.time() - t0
            self.logger.debug(
                "_run_pyshark_pipeline: packet loop finished in %.2fs (%d packets, %.0f pkt/s)",
                elapsed,
                packet_count,
                packet_count / elapsed if elapsed > 0 else 0,
            )
            if packet_count == 0 and total_packets:
                self.logger.info(
                    f"0/{total_packets} packets matched active listeners "
                    f"(try --protocols to select specific protocols, or --list-listeners to see available)"
                )
            else:
                self.logger.success(f"Processed {packet_count} packets")

        except Exception as e:
            set_progress_active(False)
            err_msg = str(e).lower()
            is_crash = "crashed" in err_msg or "retcode" in err_msg
            is_truncated = "cut short" in err_msg or "truncated" in err_msg
            # Truncated pcap files cause tshark to exit non-zero after
            # successfully outputting all complete packets.  Don't discard the
            # intel already harvested from the valid prefix — fall through to the
            # harvest/export block below instead of re-raising.
            if is_crash and (packet_count > 0 or is_truncated):
                self.logger.debug(
                    "_run_pyshark_pipeline: tshark exited non-zero after %d packets "
                    "(truncated pcap?): %s",
                    packet_count,
                    e,
                )
                if is_truncated:
                    self.logger.info(
                        "PCAP file appears truncated — reporting intel from the valid prefix"
                    )
                # Suppress noisy __del__ exceptions from the orphaned capture
                # by killing subprocesses and clearing the process list.
                self._kill_capture_processes(capture)
            elif is_crash:
                # No packets processed — genuine crash, propagate for retry.
                # Kill subprocesses to suppress noisy __del__ asyncio errors.
                self._kill_capture_processes(capture)
                raise
            else:
                # Any other unexpected error (e.g. from process_pyshark_packet /
                # _track_endpoint / the generator). Previously this returned
                # without killing the tshark subprocess, orphaning it until GC
                # ran pyshark's __del__ and triggering the exact noisy asyncio
                # teardown the crash branches suppress. Clean up here too.
                self.logger.fail(f"PyShark pipeline error: {e}")
                self._kill_capture_processes(capture)
                return 0

        # Harvest protocol-specific data from all listeners via generic interface
        from oida.pcap.pyshark_base import PySharkListenerBase

        all_tables: List[Dict[str, Any]] = []
        all_interactions = []
        all_cred_rows: List[List[str]] = []
        proto_map: Dict[str, Any] = {}  # PROTOCOL_NAME.upper() -> listener

        for name, listener in listeners.items():
            try:
                # Collect interactions for unified table
                all_interactions.extend(listener.interactions)
                proto_map[listener.PROTOCOL_NAME.upper()] = listener

                # Collect credentials + hashes (normalized rows)
                all_cred_rows.extend(listener._collect_credentials())
                all_cred_rows.extend(listener._collect_hashes())

                # Harvest: returns only custom info tables + alerts
                harvest_data = listener.harvest()
                if not harvest_data:
                    continue

                # Display custom info tables (PLC identity, OPC UA endpoints, etc.)
                for table in harvest_data.get("tables", []):
                    export_data(
                        data=table["rows"],
                        headers=table["headers"],
                        output_format="console",
                        title=table.get("title"),
                        logger=self.logger,
                    )
                    all_tables.append(table)

                # Merge results
                for key, value in harvest_data.get("results", {}).items():
                    if key == "protocols_used_append":
                        for proto in value:
                            if proto not in self.results["protocols_used"]:
                                self.results["protocols_used"].append(proto)
                    elif key == "tls_certificates_merge":
                        # Merge certificates into the unified TLS results dict
                        if "tls" not in self.results:
                            self.results["tls"] = {
                                "certificates": {},
                                "connections": [],
                                "total_certificates": 0,
                                "total_connections": 0,
                            }
                        for thumb, cert_data in value.items():
                            self.results["tls"]["certificates"][thumb] = cert_data
                        self.results["tls"]["total_certificates"] = len(
                            self.results["tls"]["certificates"]
                        )
                    elif key == "tls_connections":
                        if "tls" not in self.results:
                            self.results["tls"] = {
                                "certificates": {},
                                "connections": [],
                                "total_certificates": 0,
                                "total_connections": 0,
                            }
                        self.results["tls"]["connections"] = value
                        self.results["tls"]["total_connections"] = len(value)
                    else:
                        self.results[key] = value

                # Log alerts (security warnings)
                for alert in harvest_data.get("alerts", []):
                    level = alert.get("level", "info")
                    msg = alert["message"]
                    getattr(self.logger, level, self.logger.info)(msg)

                # Log informational messages
                for log_msg in harvest_data.get("log_messages", []):
                    level = log_msg.get("level", "info")
                    msg = log_msg["message"]
                    getattr(self.logger, level, self.logger.info)(msg)
            except Exception as e:
                self.logger.debug("harvest failed for listener %s: %s", name, e)
                continue

        # --- Unified interaction table (central) ---
        if all_interactions:
            all_interactions.sort(key=lambda ix: ix.timestamp)
            rows = []
            json_rows = []
            for ix in all_interactions:
                listener_obj = proto_map.get(ix.protocol)
                if listener_obj:
                    details = listener_obj._format_details_string(ix)
                else:
                    details = ix.summary or ""
                src = PySharkListenerBase._format_ip_port(ix.src_ip, ix.src_port)
                dst = PySharkListenerBase._format_ip_port(ix.dst_ip, ix.dst_port)
                rows.append(
                    [
                        ix.stream_id,
                        ix.protocol,
                        src,
                        dst,
                        ix.operation,
                        details,
                    ]
                )
                # Structured row for JSON/CSV export — individual fields
                json_row = {
                    "#": ix.stream_id,
                    "Protocol": ix.protocol,
                    "Src": src,
                    "Dst": dst,
                    "Operation": ix.operation,
                }
                # Flatten ix.details into top-level keys
                for k, v in ix.details.items():
                    if v is None or v == "":
                        continue
                    if isinstance(v, list):
                        json_row[k] = v  # preserve lists (e.g. register values)
                    elif not isinstance(v, (dict, set)):
                        json_row[k] = v
                json_rows.append(json_row)
            title = f"Protocol Interactions ({len(rows)})"
            export_data(
                data=rows,
                headers=["#", "Protocol", "Src", "Dst", "Operation", "Details"],
                output_format="console",
                title=title,
                logger=self.logger,
            )
            all_tables.append(
                {
                    "headers": ["#", "Protocol", "Src", "Dst", "Operation", "Details"],
                    "rows": rows,
                    "json_rows": json_rows,
                    "title": title,
                }
            )

        # --- Unified credential table (central) ---
        if all_cred_rows:
            cred_headers = ["Protocol", "Type", "Username", "Server", "Client", "Secret"]
            cred_title = f"Credentials ({len(all_cred_rows)})"
            # Console shows only a secret preview (hashcat strings run to 400+
            # chars); the export table below keeps the full value so CSV/JSON
            # carry complete crackable material.
            SECRET_PREVIEW = 48
            display_rows = [
                (
                    row[:5]
                    + [
                        (
                            row[5][:SECRET_PREVIEW] + "…"
                            if len(row) > 5 and len(row[5] or "") > SECRET_PREVIEW
                            else (row[5] if len(row) > 5 else "")
                        )
                    ]
                )
                for row in all_cred_rows
            ]
            export_data(
                data=display_rows,
                headers=cred_headers,
                output_format="console",
                title=cred_title,
                logger=self.logger,
            )
            all_tables.append(
                {
                    "headers": cred_headers,
                    "rows": all_cred_rows,
                    "title": cred_title,
                }
            )

        # Merge device results from all listeners
        for name, listener in listeners.items():
            try:
                devices = listener.discovered_devices
                if devices:
                    self.logger.debug(
                        "_run_pyshark_pipeline: %s produced %d devices", name, len(devices)
                    )
                    self.discovered_devices.update(devices)
                    if name not in self.results["protocols_used"]:
                        self.results["protocols_used"].append(name)
                    self.logger.success(f"{name}: {len(devices)} devices")

                # Surface extracted credentials (SMTP, FTP, SNMP, etc.)
                creds = getattr(listener, "credentials", [])
                for cred in creds:
                    # Try multiple attribute names for username
                    username = getattr(cred, "username", "") or getattr(
                        cred, "community_or_username", ""
                    )
                    password = getattr(cred, "password", "")
                    method = getattr(cred, "auth_method", "")
                    cred_type = getattr(cred, "credential_type", "")
                    # Try multiple attribute names for server IP + port
                    server = getattr(cred, "server_ip", "") or getattr(cred, "dest_ip", "")
                    port = getattr(cred, "server_port", 0) or getattr(cred, "dest_port", 0)
                    server_str = f"{server}:{port}" if server and port else server
                    self.logger.debug(
                        "_run_pyshark_pipeline: credential from %s — type=%s method=%s user=%s server=%s",
                        name,
                        cred_type,
                        method,
                        username,
                        server_str,
                    )
                    # Treat "community" and "plaintext" both as plaintext display
                    if cred_type in ("plaintext", "community") and username:
                        self.logger.success(
                            f"{name} credential ({method}): {username}:{password} @ {server_str}",
                        )
                    elif cred_type == "hash" and username:
                        hashcat = getattr(cred, "hashcat_format", None)
                        if hashcat is not None:
                            # Modern decoder: hashcat_format is the source of truth.
                            # An empty string means the captured material is not
                            # crackable (e.g. NTLM without the Type 2 challenge, or a
                            # pgsql md5 with no salt). It is already surfaced as
                            # INCOMPLETE in the summary, so skip the line rather than
                            # printing a bare value that looks like a deliverable hash.
                            if hashcat:
                                self.logger.success(
                                    f"{name} hash ({method}): {username} @ {server_str} [{hashcat}]",
                                )
                        else:
                            # Legacy cred without a hashcat_format property.
                            hash_val = getattr(cred, "hash_value", "") or getattr(
                                cred, "password_hash", ""
                            )
                            if hash_val:
                                self.logger.success(
                                    f"{name} hash ({method}): {username} @ {server_str} [{hash_val}]",
                                )
                    elif username and cred_type:
                        hash_val = getattr(cred, "hashcat_format", "") or getattr(
                            cred, "hash_value", ""
                        )
                        if hash_val:
                            self.logger.success(
                                f"{name} hash ({method}): {username} @ {server_str} [{hash_val}]",
                            )
            except Exception as e:
                self.logger.debug("device merge failed for listener %s: %s", name, e)
                continue

        self._deduplicate_devices()

        # Store tables for per-file export (used by cli.py export_results)
        if all_tables:
            self.results["tables"] = all_tables

        # Hashcat export: collect crackable hashes from all listeners
        if self.args.get("hashcat"):
            self._export_hashcat(listeners)

        return packet_count

    def _deduplicate_devices(self) -> None:
        """Fold cross-listener duplicate devices into one entry.

        Each listener keys devices in its own namespace ({proto}:{ip},
        ssdp:{mac}, netbios:{ip}, ...), so one physical host seen by several
        listeners (ads + igmp + netbios + ssdp) appears once per key. Group by
        MAC address (fallback: IP address for MAC-less devices), keep the
        richest device as the primary, and merge_from() the rest.
        """
        from oida.protocols.discovery.core import normalize_ipv6

        devices = self.discovered_devices
        original_count = len(devices)
        if original_count <= 1:
            return

        # Union-find by MAC (first) and IP (second) so devices sharing either
        # identifier collapse into the same group.
        parent: Dict[str, str] = {}

        def find(k: str) -> str:
            while parent[k] != k:
                parent[k] = parent[parent[k]]
                k = parent[k]
            return k

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        groups: Dict[str, List[str]] = {}  # identity key -> [device keys]
        for key, dev in devices.items():
            parent[key] = key
            mac = dev.mac_address.lower()
            if mac:
                groups.setdefault(f"mac:{mac}", []).append(key)
            for ip in dev.ip_addresses:
                norm = normalize_ipv6(ip) if ":" in ip else ip
                if norm:
                    groups.setdefault(f"ip:{norm}", []).append(key)

        for members in groups.values():
            for other in members[1:]:
                union(members[0], other)

        clusters: Dict[str, List[str]] = {}
        for key in devices:
            clusters.setdefault(find(key), []).append(key)

        if len(clusters) == len(devices):
            return  # no duplicates

        for members in clusters.values():
            if len(members) == 1:
                continue

            # Primary = the device with the most non-empty fields (richest
            # protocol data); deterministically break ties by key order.
            def richness(k: str) -> tuple:
                d = devices[k]
                filled = sum(1 for v in vars(d).values() if v not in (None, "", [], {}, ()))
                return (filled, -members.index(k))

            primary = max(members, key=richness)
            for key in members:
                if key == primary:
                    continue
                other = devices[key]
                # Preserve the folded device's role ("NetBIOS Host", ...) in
                # discovery_reasons — merge_from only fills device_type when
                # the primary's is empty.
                if other.device_type and other.device_type not in (
                    devices[primary].device_type,
                    *devices[primary].discovery_reasons,
                ):
                    devices[primary].discovery_reasons.append(other.device_type)
                merged = devices[primary].merge_from(other)
                self.logger.debug("dedup: folded %s into %s (updated: %s)", key, primary, merged)
                del devices[key]

        self.logger.debug("dedup: %d devices after merge (was %d)", len(devices), original_count)

    def _fill_routing_salts(self, listeners: Dict[str, Any]) -> None:
        """Fill OSPF/RIP/EIGRP credential ``net_salt`` from raw packet bytes.

        The main pipeline runs in EK mode (field access), where pyshark does not
        populate raw layer bytes. The JtR net-md5/eigrp salt is the raw routing
        packet (minus the appended digest), so we do one extra filtered pass in
        JSON+include_raw mode and match each raw packet to a credential by its
        (unique) digest, which the EK pass already extracted.
        """
        routing = {n: listeners[n] for n in ("ospf", "rip", "eigrp") if n in listeners}
        if not routing or not getattr(self, "pcap_file", None):
            return
        # digest(hex) -> creds awaiting a salt
        need: Dict[str, List[Any]] = {}
        for listener in routing.values():
            for cred in getattr(listener, "credentials", []):
                dg = (getattr(cred, "auth_data", "") or "").replace(":", "").lower()
                if (
                    getattr(cred, "credential_type", "") == "hash"
                    and dg
                    and not getattr(cred, "net_salt", "")
                ):
                    need.setdefault(dg, []).append(cred)
        if not need:
            return
        try:
            cap = _pyshark.FileCapture(
                self.pcap_file,
                include_raw=True,
                use_json=True,
                keep_packets=False,
                display_filter="ospf || rip || eigrp",
            )
        except Exception as e:
            self.logger.debug("_fill_routing_salts: capture failed: %s", e)
            return
        try:
            for packet in cap:
                for attr in ("ospf_raw", "rip_raw", "eigrp_raw"):
                    raw_layer = getattr(packet, attr, None)
                    if raw_layer is None:
                        continue
                    raw = str(getattr(raw_layer, "value", "") or "").replace(":", "").lower()
                    if not raw:
                        continue
                    for dg, creds in need.items():
                        if len(raw) > len(dg) and raw.endswith(dg):
                            salt = raw[: -len(dg)]
                            for cred in creds:
                                if not cred.net_salt:
                                    cred.net_salt = salt
        except Exception as e:
            self.logger.debug("_fill_routing_salts: raw pass error: %s", e)
        finally:
            try:
                cap.close()
            except Exception:
                pass

    def _export_hashcat(self, listeners: Dict[str, Any]) -> None:
        """Collect and export hashcat-compatible hashes from all listeners."""
        # Protocol -> hashcat mode comment
        mode_comments = {
            "ntlm": "# NTLM — NTLMv1 (hashcat 5500), NTLMv2 (hashcat 5600)",
            "kerberos": "# Kerberos — AS-REQ (7500/19800/19900), AS-REP (18200/john), "
            "TGS-REP (13100/19600/19700)",
            "http": "# HTTP Digest — John the Ripper `hdaa` (no hashcat mode)",
            "sip": "# SIP Digest (hashcat 11400)",
            "vnc": "# VNC — John the Ripper `vnc` (no hashcat mode)",
            "ipmi": "# IPMI 2.0 RAKP — HMAC-SHA1 (hashcat 7300)",
            "mysql": "# MySQL CRAM (hashcat 11200)",
            "pgsql": "# PostgreSQL CRAM-MD5 (hashcat 11100)",
            "iscsi": "# iSCSI CHAP — MD5 (hashcat 4800)",
            "imap": "# CRAM-MD5 (hashcat 10200)",
            "smtp": "# CRAM-MD5 (hashcat 10200)",
            "tacacs": "# TACACS+ — encrypted AUTHEN, recovers shared secret (hashcat 16100)",
            "ospf": "# OSPF crypto-auth — John net-md5/net-sha1 (no hashcat mode)",
            "rip": "# RIPv2 keyed-auth — John net-md5/net-sha1 (no hashcat mode)",
            "radius": "# RADIUS — CHAP-Password (hashcat 4800), MS-CHAPv2 (hashcat 5500)",
        }

        all_hashes: List[str] = []
        for name, listener in sorted(listeners.items()):
            if not hasattr(listener, "get_hashcat_hashes"):
                continue
            try:
                hashes = listener.get_hashcat_hashes()
                if hashes:
                    comment = mode_comments.get(name, f"# {name}")
                    all_hashes.append(comment)
                    all_hashes.extend(hashes)
                    all_hashes.append("")  # blank line between protocols
            except Exception as e:
                self.logger.debug("_export_hashcat: %s failed: %s", name, e)

        if not all_hashes:
            return

        output_dir = self.args.get("output") or self.args.get("output_dir")
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            hashcat_path = get_export_path("hashcat", "txt")
            if not hashcat_path:
                hashcat_path = Path(output_dir) / "hashcat.txt"
            hashcat_path.write_text("\n".join(all_hashes) + "\n", encoding="utf-8")
            self.logger.success(f"Hashcat hashes written to {hashcat_path}")
        else:
            # Print to stdout
            for line in all_hashes:
                if line.startswith("#"):
                    self.logger.info(line)
                elif line:
                    self.logger.success(line)

        self.results["hashcat_hashes"] = [h for h in all_hashes if h and not h.startswith("#")]

    def _create_pyshark_listeners(self) -> Dict[str, Any]:
        """Create PyShark-based listeners via the listener registry."""
        if not _pyshark.is_available:
            self.logger.debug("_create_pyshark_listeners: pyshark not available")
            return {}

        from oida.protocols.pcap.listener_registry import create_listeners

        names = self._resolve_listener_names()
        listeners = create_listeners(names, logger=self.logger)

        # Propagate --x509 flag to listeners so _display_cert_info is gated
        x509_enabled = bool(self.args.get("x509"))
        for listener in listeners.values():
            listener._x509 = x509_enabled

        self.logger.debug(
            "_create_pyshark_listeners: created %d/%d listeners: %s",
            len(listeners),
            len(names),
            sorted(listeners.keys()),
        )
        return listeners

    def _run_file_extraction(self) -> None:
        """Extract files from PCAP using tshark export-objects."""
        if not _file_extraction.is_available:
            self.logger.info("File extraction module not available")
            return

        FileExtractor = _file_extraction.FileExtractor
        EXPORT_PROTOCOLS = _file_extraction.EXPORT_PROTOCOLS

        output_dir = self.args.get("extract_dir")
        protocols_str = self.args.get("extract_protocols", "http,smb,ftp-data,tftp,dicom,imf")
        protocols = [p.strip() for p in protocols_str.split(",") if p.strip() in EXPORT_PROTOCOLS]
        self.logger.debug("_run_file_extraction: protocols=%s output_dir=%s", protocols, output_dir)

        if not protocols:
            self.logger.info(f"No valid extraction protocols. Available: {EXPORT_PROTOCOLS}")
            return

        self.logger.info(f"Extracting files from PCAP: {protocols}")

        try:
            extractor = FileExtractor(
                pcap_file=self.pcap_file,
                output_dir=output_dir,
                protocols=protocols,
            )
            files = extractor.extract_all()
            self.logger.debug(
                "_run_file_extraction: extracted %d files", len(files) if files else 0
            )

            if files:
                self.logger.success(f"Extracted {len(files)} files")
                stats = extractor.get_statistics()
                for proto, info in stats.get("by_protocol", {}).items():
                    self.logger.debug(
                        "_run_file_extraction: %s — %d files, %d bytes",
                        proto,
                        info["count"],
                        info["bytes"],
                    )
                    self.logger.info(f"  {proto}: {info['count']} files ({info['bytes']} bytes)")
                self.logger.info(f"  Output: {extractor.output_dir}")
                self.results["extracted_files"] = extractor.get_files_summary()
                self.results["extraction_stats"] = stats
            else:
                self.logger.info("No files extracted from PCAP")

        except Exception as e:
            self.logger.fail(f"File extraction error: {e}")

    @staticmethod
    def _is_noise_endpoint(ip: str, mac: str) -> bool:
        """Return True if IP/MAC is broadcast, multicast, or otherwise noise."""
        if mac in ("ff:ff:ff:ff:ff:ff",) or mac.startswith(("33:33:", "01:00:5e:")):
            return True
        if ip in ("0.0.0.0", "::", "255.255.255.255"):
            return True
        # A .255 address is a directed broadcast only on a /24; a /16 host such
        # as 10.0.1.255 is a valid unicast endpoint. Treat .255 as broadcast
        # noise only when the MAC confirms it (broadcast, or absent/unknown where
        # the L2 address can't disambiguate) -- a real unicast MAC keeps the host.
        if ip.endswith(".255") and (not mac or mac == "ff:ff:ff:ff:ff:ff"):
            return True
        first_octet = ip.split(".")[0] if "." in ip else ""
        if first_octet.isdigit() and 224 <= int(first_octet) <= 239:
            return True
        # IPv6 multicast (ff00::/8)
        if ip.lower().startswith("ff"):
            return True
        return False

    def _track_endpoint(self, packet) -> None:
        """Extract IP→MAC mapping from a packet for endpoint discovery."""
        if not hasattr(packet, "eth"):
            return

        from oida.protocols.discovery.stats import _str

        src_mac = _str(getattr(packet.eth, "src", None)).lower()
        dst_mac = _str(getattr(packet.eth, "dst", None)).lower()

        # Resolve IP addresses (IPv4 or IPv6)
        src_ip = dst_ip = ""
        if hasattr(packet, "ip"):
            src_ip = _str(packet.ip.src)
            dst_ip = _str(packet.ip.dst)
        elif hasattr(packet, "ipv6"):
            src_ip = _str(packet.ipv6.src)
            dst_ip = _str(packet.ipv6.dst)

        for ip, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
            if not ip or not mac or ip in self._endpoints:
                continue
            if self._is_noise_endpoint(ip, mac):
                continue
            self._endpoints[ip] = mac

    def _report_assets(self) -> None:
        """Report discovered assets as a summary table (opt-in via --assets).

        Merges data from three sources into a unified inventory:
        1. Listener-created devices (rich protocol data)
        2. Endpoint tracker (IP→MAC from every packet)
        3. Stats open ports (per-IP service detection)
        """
        from oida.protocols.discovery.core import (
            DiscoveredDevice,
            build_device_description,
            lookup_mac_vendor,
        )

        # ── Merge stats IP→MAC into endpoint tracker ──
        # Stats collects IP→MAC from conversations; merge so endpoint tracker
        # has the most complete mapping.  Apply same broadcast/multicast filter.
        if hasattr(self, "stats") and self.stats._ip_to_mac:
            for ip, mac in self.stats._ip_to_mac.items():
                if not ip or not mac or ip in self._endpoints:
                    continue
                if self._is_noise_endpoint(ip, mac):
                    continue
                self._endpoints[ip] = mac

        # ── Merge endpoint-tracked IPs into discovered_devices ──
        # Build index of IPs already covered by listener-created devices.
        known_ips: Dict[str, Any] = {}  # ip -> device object
        for dev in self.discovered_devices.values():
            for addr in dev.ip_addresses:
                known_ips[addr] = dev

        for ip, mac in self._endpoints.items():
            if ip in known_ips:
                dev = known_ips[ip]
                if not dev.mac_address and mac:
                    dev.mac_address = mac
            else:
                self.discovered_devices[f"endpoint_{ip}"] = DiscoveredDevice(
                    ip_addresses=[ip],
                    mac_address=mac,
                    discovered_by=["endpoint"],
                )

        devices = self.discovered_devices
        if not devices:
            return

        # ── Build per-IP open ports index from stats ──
        ip_ports: Dict[str, List[str]] = {}  # ip -> ["tcp/445 (SMB)", ...]
        if hasattr(self, "stats"):
            for (ip, port, transport), op in self.stats.open_ports.items():
                label = f"{transport}/{port}"
                if op.service and not op.service.startswith(f"{transport}/"):
                    label = f"{port}/{op.service}"
                ip_ports.setdefault(ip, []).append(label)

        headers = ["MAC", "Vendor", "IP", "Ports", "Protocols", "Description"]
        table_data = []

        for device in devices.values():
            device_dict = {k: v for k, v in vars(device).items() if v not in (None, "", [], {}, ())}

            mac = device.mac_address or "(unknown)"

            # Show all IPs (IPv4 first, then IPv6)
            ips = device.ip_addresses or []
            ipv4s = [ip for ip in ips if ":" not in ip and ip and ip != "0.0.0.0"]
            ipv6s = [ip for ip in ips if ":" in ip and ip]
            ip_str = ", ".join(ipv4s + ipv6s) or ""

            # Collect open ports for all IPs of this device
            device_ports: List[str] = []
            for addr in ips:
                device_ports.extend(ip_ports.get(addr, []))
            ports_str = ", ".join(sorted(set(device_ports)))

            # Protocols that discovered this device
            protos = ", ".join(device.discovered_by) if device.discovered_by else ""

            # Rich description
            description = build_device_description(device_dict)

            # Vendor lookup
            vendor = device.manufacturer or ""
            if not vendor and mac != "(unknown)":
                vendor = lookup_mac_vendor(mac)

            table_data.append([mac, vendor[:15], ip_str, ports_str, protos, description])

        title = f"Discovered Assets ({len(table_data)})"
        export_data(
            data=table_data,
            headers=headers,
            output_format="console",
            title=title,
            logger=self.logger,
        )

        # Store table for file export
        if "tables" not in self.results:
            self.results["tables"] = []
        self.results["tables"].append(
            {"title": "Discovered Assets", "headers": headers, "rows": table_data}
        )

        self.logger.info(f"Discovered {len(table_data)} assets")

        # ── Write asset files (devices.csv, ipv4.txt, ipv6.txt) ──
        self._write_asset_files(devices)

    def _write_asset_files(self, devices: Dict[str, Any]) -> None:
        """Write asset inventory files: devices.csv, ipv4.txt, ipv6.txt.

        Only writes when -o / --output provides an output directory.
        Reuses the same format as the discovery scanner for consistency.
        """
        from oida.protocols.discovery.core import build_device_description, lookup_mac_vendor

        output_dir = self.args.get("output") or self.args.get("output_dir")
        if not output_dir:
            return

        os.makedirs(output_dir, exist_ok=True)

        # ── devices.csv ──
        try:
            headers = [
                "mac_address",
                "ip_addresses",
                "manufacturer",
                "name",
                "description",
                "discovered_by",
            ]
            rows = []
            for dev in devices.values():
                mac = dev.mac_address or ""
                vendor = dev.manufacturer or ""
                if not vendor and mac:
                    vendor = lookup_mac_vendor(mac)
                device_dict = {
                    k: v for k, v in vars(dev).items() if v not in (None, "", [], {}, ())
                }
                rows.append(
                    [
                        mac,
                        ",".join(dev.ip_addresses),
                        vendor,
                        dev.name or "",
                        build_device_description(device_dict),
                        ",".join(dev.discovered_by),
                    ]
                )
            export_data(
                rows,
                headers,
                output_format="csv",
                output_dir=output_dir,
                filename_prefix="devices",
                logger=self.logger,
            )
        except Exception as e:
            self.logger.debug("_write_asset_files: CSV write failed: %s", e)

        # ── Collect unique IPs ──
        ipv4_list: List[str] = []
        ipv6_list: List[str] = []
        for dev in devices.values():
            for ip in dev.ip_addresses:
                if not ip or ip == "0.0.0.0" or ip == "::":
                    continue
                if ":" in ip:
                    ipv6_list.append(ip)
                else:
                    ipv4_list.append(ip)

        # ── ipv4.txt ──
        if ipv4_list:
            ipv4_path = get_export_path("ipv4", "txt")
            if not ipv4_path:
                ipv4_path = Path(output_dir) / "ipv4.txt"
            try:
                unique_ips = sorted(set(ipv4_list))
                ipv4_path.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")
                self.logger.info(f"Wrote: {ipv4_path} ({len(unique_ips)} addresses)")
            except Exception as e:
                self.logger.debug("_write_asset_files: ipv4.txt write failed: %s", e)

        # ── ipv6.txt ──
        if ipv6_list:
            ipv6_path = get_export_path("ipv6", "txt")
            if not ipv6_path:
                ipv6_path = Path(output_dir) / "ipv6.txt"
            try:
                unique_ips = sorted(set(ipv6_list))
                ipv6_path.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")
                self.logger.info(f"Wrote: {ipv6_path} ({len(unique_ips)} addresses)")
            except Exception as e:
                self.logger.debug("_write_asset_files: ipv6.txt write failed: %s", e)


class pcap(SerialConnection):
    """NXC-style PCAP analysis (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "PCAP"
        self.default_port = None
        self._scan_results = None
        self._original_host = host
        super().__init__(args, db, host)

    def _resolve_host(self, host: str) -> str:
        """Return empty string — host is a file path, not a hostname."""
        self.logger.debug("pcap._resolve_host: %s -> (empty)", host)
        return ""

    def proto_logger(self):
        """Set logger host to basename only — no hostname column for file paths."""
        self.logger.extra["host"] = ""
        self.logger.extra["hostname"] = ""

    def proto_flow(self):
        """Main PCAP analysis workflow"""
        args_dict = self._convert_args_to_dict()
        self.logger.debug("pcap.proto_flow: args_dict keys=%s", list(args_dict.keys()))

        # Handle --list-listeners before file validation
        if args_dict.get("list_listeners"):
            scanner = PcapScanner("", args_dict)
            scanner.logger = self.logger
            scanner._print_listeners()
            return

        pcap_file = args_dict.get("target") or self._original_host
        self.logger.debug("pcap.proto_flow: resolved pcap_file=%s", pcap_file)
        if not pcap_file or not os.path.isfile(pcap_file):
            self.logger.fail(f"PCAP file not found: {pcap_file}")
            return

        self.scanner = PcapScanner(pcap_file, args_dict)
        self.scanner.logger = self.logger

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def create_conn_obj(self) -> bool:
        """No connection needed for offline analysis."""
        return True

    def enum_host_info(self) -> None:
        """No-op framework hook — run_scan owns enumeration/output for pcap.

        (The previous self.device_info dict had no reader: print_host_info is a
        no-op and get_results returns self._scan_results.)
        """

    def print_host_info(self) -> None:
        """Print host info — no-op, run_scan prints the analysis header."""

    def _execute_scan(self) -> None:
        """Execute PCAP analysis"""
        self.logger.debug("pcap._execute_scan: starting scan")
        t0 = time.time()
        try:
            self._scan_results = self.scanner.run_scan()
            self.logger.debug("pcap._execute_scan: scan completed in %.2fs", time.time() - t0)
        except Exception as e:
            self.logger.debug("pcap scan failed: %s", e)
            self.logger.fail(f"PCAP analysis error: {e}")

    def get_results(self) -> ScanResult:
        """Return scan results"""
        if self._scan_results:
            return {
                "host": self.host,
                "protocol": "pcap",
                "success": True,
                "data": self._scan_results,
            }
        return {
            "host": self.host,
            "protocol": "pcap",
            "success": False,
        }
