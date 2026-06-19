#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HART NXC-style callable class."""

from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import
from .scanner import HARTScanner, PhysicalSignaling
from .hartip import get_device_type_name

_hartip = lazy_import("hartip", "HART")


class hart(NetworkConnection):
    """
    NXC-style HART scanner (callable).

    Inherits from NetworkConnection and triggers scanning on instantiation.
    """

    def __init__(self, args, db, host):
        self.protocol_name = "HART"
        self.default_port = 5094
        self.scanner = None
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main HART scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = HARTScanner(args_dict)

        # Check for special modes that don't require initial connection
        scan_addresses = getattr(self.args, "scan_addresses", None)
        enumerate_commands = getattr(self.args, "enumerate_commands", False)
        security_analysis = getattr(self.args, "security_analysis", False)
        fuzz = getattr(self.args, "fuzz", False)

        # Poll address scanning mode
        if scan_addresses:
            self._handle_address_scan(scan_addresses)
            return

        # Normal connection-based scanning
        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        # Basic device enumeration
        self.enum_host_info()
        self.print_host_info()

        # Derive scan_mode from the --discover/--quick/--full shortcut flags
        # (mirrors bacnet). --discover stops after device ID; --full auto-runs
        # command enumeration + security analysis. --quick / no flag fall
        # through to the plain enumeration path.
        if getattr(self.args, "scan_mode", None):
            scan_mode = self.args.scan_mode
        elif getattr(self.args, "discover", False):
            scan_mode = "discovery"
        elif getattr(self.args, "full", False):
            scan_mode = "full"
        else:
            scan_mode = "enumeration"

        # Discovery mode stops after device identification — no further probing
        if scan_mode == "discovery" and not self._has_specific_action():
            return

        # Full mode auto-runs command enumeration + security analysis unless the
        # user already requested a specific action.
        if scan_mode == "full":
            if not enumerate_commands and not self._has_specific_action():
                enumerate_commands = True
            if not security_analysis and not self._has_specific_action():
                security_analysis = True

        # Targeted single-command reads (--read-id/-pv/-current/-tag/-output/-status)
        self._handle_targeted_reads()

        # Read process variables
        if getattr(self.args, "read_all_vars", False) or not self._has_specific_action():
            self._handle_read_variables()

        # Command enumeration
        if enumerate_commands:
            self._handle_enumerate_commands()

        # Device-specific command enumeration (128-253)
        if getattr(self.args, "enumerate_device_specific", False):
            self._handle_enumerate_device_specific()

        # Calibration / write command probes
        if getattr(self.args, "probe_calibration", False) or getattr(
            self.args, "probe_write", False
        ):
            self._handle_command_probes()

        # Security analysis
        if security_analysis:
            self._handle_security_analysis()

        # List sub-devices (WirelessHART gateway)
        if getattr(self.args, "list_sub_devices", False):
            self._handle_list_sub_devices()

        # Device lock operations
        if getattr(self.args, "check_lock", False):
            self._handle_check_lock()

        if getattr(self.args, "bruteforce_lock", None) is not None:
            self._handle_bruteforce_lock()

        # Fuzzing
        if fuzz:
            self._handle_fuzz()

        # Raw command
        if getattr(self.args, "raw_command", None) is not None:
            self._handle_raw_command()

        # Write operations (require --confirm)
        self._handle_write_operations()

        # Lock/unlock operations (require --confirm)
        self._handle_lock_operations()

    def _has_specific_action(self) -> bool:
        """Check if user requested specific actions"""
        actions = [
            "read_id",
            "read_pv",
            "read_current",
            "read_tag",
            "read_output",
            "read_status",
            "read_all_vars",
            "enumerate_commands",
            "enumerate_device_specific",
            "security_analysis",
            "probe_calibration",
            "probe_write",
            "fuzz",
            "write_poll_addr",
            "write_tag",
            "master_reset",
            "raw_command",
        ]
        return any(getattr(self.args, action, False) for action in actions)

    def create_conn_obj(self):
        """Create HART-IP connection"""
        port = getattr(self.args, "port", self.default_port)
        protocol = "tcp" if getattr(self.args, "tcp", False) else "udp"
        self.logger.info(f"Connecting to {self.host}:{port} ({protocol.upper()})")

        # Probe server version if requested
        if getattr(self.args, "probe_version", False):
            self.logger.debug("Probing HART-IP server version...")
            version = self.scanner.probe_version()
            if version:
                ver_name = "v2 (TLS)" if version == 2 else "v1 (plaintext)"
                self.logger.display(f"  Server version: HART-IP {ver_name}")
                self.results["data"]["server_version"] = version
            else:
                self.logger.debug("Version probe failed, continuing with v1")

        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(
                f"Connected to HART device at {self.host}:{port} ({protocol.upper()})"
            )
            # Record transport encryption state of the live connection. HART-IP
            # only carries TLS/DTLS when PSK credentials negotiated a v2 session;
            # a plaintext UDP/TCP session is unencrypted and must be flagged.
            tls_active = bool(getattr(self.scanner, "psk_identity", None)) and bool(
                getattr(self.scanner, "psk_key", None)
            )
            self.results["data"]["encryption_status"] = {
                "tls_supported": tls_active,
                "dtls_supported": False,
                "version": "HART-IP v2" if tls_active else "HART-IP v1",
                "cipher": getattr(self.scanner, "cipher_suite", None) if tls_active else "",
            }
        else:
            self.logger.fail(f"Connection failed to {self.host}:{port}")

    def enum_host_info(self):
        """Enumerate HART device information"""
        if not self.conn:
            return

        self.logger.debug("Reading device identification...")

        device_info = self.scanner.read_device_info()
        if device_info:
            device_info_dict = {
                "manufacturer_id": device_info.manufacturer_id,
                "manufacturer": device_info.manufacturer_name,
                "device_type": device_info.device_type,
                "device_type_name": get_device_type_name(device_info.device_type),
                "device_revision": device_info.device_revision,
                "protocol_revision": device_info.protocol_revision,
                "protocol_version": device_info.get_protocol_version_name(),
                "security_rating": device_info.get_security_rating(),
                "software_revision": device_info.software_revision,
                "hardware_revision": device_info.hardware_revision,
                "physical_signaling": device_info.get_signaling_name(),
                "unique_id": device_info.unique_id.hex() if device_info.unique_id else None,
                "tag": device_info.tag,
                "descriptor": device_info.descriptor,
                "date": device_info.date,
                "poll_address": device_info.poll_address,
                "write_protected": device_info.write_protected,
                "config_changed": device_info.config_changed,
            }

            # Detect WirelessHART
            if getattr(self.args, "detect_wireless", False) or getattr(
                self.args, "wireless_info", False
            ):
                self.logger.debug("Detecting WirelessHART capabilities...")
                wireless_info = self.scanner.detect_wirelesshart(device_info)
                if wireless_info.get("is_wireless"):
                    device_info_dict["is_wireless"] = True
                    device_info_dict["is_gateway"] = wireless_info.get("is_gateway", False)
                    device_info_dict["wireless_network_id"] = wireless_info.get("network_id")
                    device_info_dict["sub_device_count"] = wireless_info.get("sub_device_count", 0)
                    device_info_dict["long_tag"] = wireless_info.get("long_tag")
                    self.results["data"]["wireless_info"] = wireless_info
            else:
                if device_info.physical_signaling_code == PhysicalSignaling.WIRELESS_HART:
                    device_info_dict["is_wireless"] = True

            self.results["data"]["device_info"] = device_info_dict

    def print_host_info(self):
        """Display HART device information"""
        if hasattr(self.args, "quiet") and self.args.quiet:
            return

        device_info = self.results["data"].get("device_info", {})

        if device_info:
            mfr = device_info.get("manufacturer", "Unknown")
            dev_type = device_info.get("device_type", 0)
            tag = device_info.get("tag", "")
            unique_id = device_info.get("unique_id", "")
            protocol_rev = device_info.get("protocol_revision", 0)

            if protocol_rev <= 5:
                proto_ver = "HART 5"
            elif protocol_rev == 6:
                proto_ver = "HART 6"
            else:
                proto_ver = "HART 7"

            type_name = get_device_type_name(dev_type)
            is_wireless = device_info.get("is_wireless", False)

            if is_wireless:
                self.logger.success(f"WirelessHART Device: {mfr} {type_name}")
                self.logger.display(f"  Protocol: WirelessHART (Rev {protocol_rev})")
                if device_info.get("is_gateway"):
                    sub_count = device_info.get("sub_device_count", 0)
                    self.logger.display(f"  Type: Gateway ({sub_count} connected devices)")
                net_id = device_info.get("wireless_network_id")
                if net_id:
                    self.logger.display(f"  Network ID: 0x{net_id:04X}")
            else:
                self.logger.success(f"HART Device: {mfr} {type_name}")
                self.logger.display(f"  Protocol: {proto_ver} (Rev {protocol_rev})")

            if tag:
                self.logger.display(f"  Tag: {tag}")
            if unique_id:
                self.logger.display(f"  Unique ID: {unique_id}")

            write_protected = device_info.get("write_protected", False)
            if protocol_rev <= 5:
                self.logger.security_finding(
                    "Outdated protocol version",
                    f"HART rev {protocol_rev} - NO encryption or authentication",
                )
            elif protocol_rev == 6:
                self.logger.security_finding(
                    "Outdated protocol version", "HART 6 - No encryption, optional device lock"
                )

            if not write_protected:
                self.logger.security_finding(
                    "Writable access", "Write protection DISABLED - device is writable"
                )
        else:
            self.logger.warning("Could not retrieve device identification")

        # Display encryption status
        encryption_status = self.results["data"].get("encryption_status", {})
        if encryption_status:
            tls_supported = encryption_status.get("tls_supported", False)
            dtls_supported = encryption_status.get("dtls_supported", False)

            if tls_supported or dtls_supported:
                enc_types = []
                if tls_supported:
                    enc_types.append("TLS")
                if dtls_supported:
                    enc_types.append("DTLS")
                enc_str = "/".join(enc_types)

                version = encryption_status.get("version", "")
                cipher = encryption_status.get("cipher", "")

                if version and cipher:
                    self.logger.success(f"  Encryption: {enc_str} ({version}, {cipher})")
                else:
                    self.logger.success(f"  Encryption: {enc_str} supported")
            else:
                self.logger.fail("  [!] NO ENCRYPTION - plaintext HART-IP")
                self.logger.security_finding(
                    "No encryption",
                    "No TLS/DTLS - plaintext HART-IP (required for conformance since 2020)",
                )

        if device_info:
            descriptor = device_info.get("descriptor", "")
            hw_rev = device_info.get("hardware_revision", 0)
            sw_rev = device_info.get("software_revision", 0)
            write_protected = device_info.get("write_protected", False)

            if descriptor:
                self.logger.debug(f"  Descriptor: {descriptor}")
            self.logger.debug(f"  Hardware Rev: {hw_rev}, Software Rev: {sw_rev}")
            self.logger.debug(f"  Write Protected: {write_protected}")

    def _handle_read_variables(self):
        """Read and display process variables"""
        if not self.scanner:
            return

        variables = self.scanner.read_all_variables()
        if variables:
            self.results["data"]["variables"] = [
                {
                    "name": v.name,
                    "value": v.value,
                    "units": v.units_name,
                    "units_code": v.units_code,
                }
                for v in variables
            ]

            self.logger.display("Process Variables:")
            for v in variables:
                self.logger.display(f"  {v.name}: {v.value:.4f} {v.units_name}")

        output_info = self.scanner.read_output_info()
        if output_info:
            self.results["data"]["output_info"] = output_info
            self.logger.debug("Output Configuration:")
            self.logger.debug(
                f"  Range: {output_info.get('lower_range', 0):.2f} - "
                f"{output_info.get('upper_range', 0):.2f} {output_info.get('units_name', '')}"
            )
            self.logger.debug(f"  Damping: {output_info.get('damping_seconds', 0):.2f} sec")

    def _handle_targeted_reads(self):
        """Handle targeted single-command read flags.

        Wires --read-id/-pv/-current/-tag/-output/-status to their existing
        mixin methods. Device identity (--read-id/--read-tag) is already
        gathered by enum_host_info(); these flags surface it explicitly.
        """
        if not self.scanner:
            return

        device_info = self.results["data"].get("device_info", {})

        if getattr(self.args, "read_id", False):
            unique_id = device_info.get("unique_id", "")
            mfr_id = device_info.get("manufacturer_id", 0)
            dev_type = device_info.get("device_type", 0)
            self.logger.display(
                f"Unique ID: {unique_id or 'unknown'} (mfr {mfr_id}, type {dev_type})"
            )

        if getattr(self.args, "read_tag", False):
            tag = device_info.get("tag", "")
            descriptor = device_info.get("descriptor", "")
            date = device_info.get("date", "")
            self.logger.display(f"Tag: {tag or '(none)'}")
            if descriptor:
                self.logger.display(f"  Descriptor: {descriptor}")
            if date:
                self.logger.display(f"  Date: {date}")

        if getattr(self.args, "read_pv", False):
            pv = self.scanner.read_primary_variable()
            if pv:
                self.results["data"]["primary_variable"] = {
                    "name": pv.name,
                    "value": pv.value,
                    "units": pv.units_name,
                }
                self.logger.display(f"Primary Variable: {pv.value:.4f} {pv.units_name}")
            else:
                self.logger.warning("Could not read primary variable (Command 1)")

        if getattr(self.args, "read_current", False):
            current, percent = self.scanner.read_current_and_percent()
            self.results["data"]["loop_current"] = {"mA": current, "percent": percent}
            self.logger.display(f"Loop Current: {current:.3f} mA ({percent:.1f}% of range)")

        if getattr(self.args, "read_output", False):
            output_info = self.scanner.read_output_info()
            if output_info:
                self.results["data"]["output_info"] = output_info
                self.logger.display(
                    f"Output Range: {output_info.get('lower_range', 0):.2f} - "
                    f"{output_info.get('upper_range', 0):.2f} "
                    f"{output_info.get('units_name', '')}"
                )
                self.logger.display(f"  Damping: {output_info.get('damping_seconds', 0):.2f} sec")
            else:
                self.logger.warning("Could not read output info (Command 15)")

        if getattr(self.args, "read_status", False):
            status = self.scanner.read_additional_status()
            if status:
                self.results["data"]["additional_status"] = status
                decoded = status.get("extended_device_status_decoded", {})
                alerts = [k for k, v in decoded.items() if v]
                if alerts:
                    self.logger.warning(f"Active status flags: {', '.join(alerts)}")
                else:
                    self.logger.display("Additional status: no active flags")
            else:
                self.logger.warning("Could not read additional status (Command 48)")

    def _handle_enumerate_device_specific(self):
        """Enumerate device-specific commands (128-253)."""
        if not self.scanner:
            return

        cmd_range = getattr(self.args, "command_range", "128-253")
        if "-" in str(cmd_range):
            start, end = map(int, str(cmd_range).split("-"))
        else:
            start = end = int(cmd_range)
        start = max(128, start)
        end = min(253, end)

        self.logger.display(f"Enumerating device-specific commands ({start}-{end})...")
        supported = self.scanner.enumerate_device_specific_commands(start=start, end=end)
        self.results["data"]["device_specific_commands"] = supported

        if supported:
            self.logger.success(f"Device-specific commands supported: {len(supported)}")
            self.logger.debug(f"  {', '.join(map(str, supported))}")
        else:
            self.logger.display("No device-specific commands responded")

    def _handle_command_probes(self):
        """Probe calibration/write command accessibility via security analysis.

        --probe-calibration / --probe-write surface the write- and
        dangerous-command accessibility checks from security_analysis(), which
        are gated behind --confirm because they transmit real (empty-payload)
        write/calibration commands to the live device.
        """
        if not self.scanner:
            return

        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "--probe-calibration/--probe-write transmit write and "
                "calibration commands to the device — requires --confirm"
            )
            return

        self.logger.display("Probing write/calibration command accessibility...")
        findings = self.scanner.security_analysis()
        probe_findings = [f for f in findings if "command accessible" in f.get("issue", "").lower()]
        self.results["data"]["command_probes"] = probe_findings

        if probe_findings:
            for f in probe_findings:
                self.logger.warning(f"  [{f.get('severity', '').upper()}] {f.get('issue')}")
        else:
            self.logger.success("No accessible write/calibration commands detected")

    def _handle_address_scan(self, range_str: str):
        """Handle poll address scanning mode"""
        try:
            if "-" in range_str:
                start, end = map(int, range_str.split("-"))
            else:
                start = end = int(range_str)

            start = max(0, min(15, start))
            end = max(0, min(15, end))

            threads = getattr(self.args, "threads", 10)
            timeout = getattr(self.args, "timeout", 2)

            self.logger.display(f"Scanning poll addresses {start}-{end}...")

            results = self.scanner.scan_poll_addresses(start, end, threads, timeout)
            self.results["data"]["address_scan"] = results

            if results:
                self.logger.success(f"Found {len(results)} device(s):")
                for dev in results:
                    type_name = dev.get("device_type_name", f"Type {dev['device_type']}")
                    self.logger.display(
                        f"  Address {dev['address']}: {dev['manufacturer']} {type_name}"
                    )
            else:
                self.logger.warning("No devices found on polled addresses")

        except ValueError as e:
            self.logger.fail(f"Invalid address range: {range_str}")
            self.results["error"] = str(e)

    def _handle_enumerate_commands(self):
        """Handle command enumeration"""
        if not self.scanner:
            return

        cmd_range = getattr(self.args, "command_range", "0-48")
        self.logger.display(f"Enumerating HART commands ({cmd_range})...")

        results = self.scanner.enumerate_commands(cmd_range)
        self.results["data"]["command_enumeration"] = results

        supported = results.get("supported", [])
        unsupported = results.get("unsupported", [])

        self.logger.success(f"Supported commands: {len(supported)}")
        if supported:
            self.logger.debug(f"  {', '.join(map(str, supported))}")

        self.logger.display(f"Unsupported commands: {len(unsupported)}")

    def _handle_list_sub_devices(self):
        """Handle sub-device listing for WirelessHART gateways"""
        if not self.scanner:
            return

        self.logger.display("Listing sub-devices (WirelessHART gateway)...")

        sub_devices = self.scanner.list_sub_devices()
        self.results["data"]["sub_devices"] = sub_devices

        if sub_devices:
            self.logger.success(f"Found {len(sub_devices)} sub-device(s):")
            for dev in sub_devices:
                tag = dev.get("long_tag", "") or f"ID:{dev.get('device_id', 'unknown')}"
                type_name = dev.get("device_type_name", f"Type {dev.get('device_type', 0)}")
                mfr = dev.get("manufacturer", "Unknown")
                self.logger.display(f"  [{dev['index']}] {mfr} {type_name} - {tag}")
        else:
            self.logger.display("No sub-devices found (device may not be a gateway)")

    def _handle_security_analysis(self):
        """Handle security analysis"""
        if not self.scanner:
            return

        self.logger.display("Performing security analysis...")

        findings = self.scanner.security_analysis()
        self.results["data"]["security_findings"] = findings

        if findings:
            critical = sum(1 for f in findings if f.get("severity") == "critical")
            high = sum(1 for f in findings if f.get("severity") == "high")
            medium = sum(1 for f in findings if f.get("severity") == "medium")
            info = sum(1 for f in findings if f.get("severity") == "info")

            self.logger.display(f"Security Findings: {len(findings)} total")
            if critical:
                self.logger.fail(f"  Critical: {critical}")
            if high:
                self.logger.warning(f"  High: {high}")
            if medium:
                self.logger.display(f"  Medium: {medium}")
            if info:
                self.logger.display(f"  Info: {info}")

            for finding in findings:
                severity = finding.get("severity", "info").upper()
                issue = finding.get("issue", "")
                self.logger.debug(f"  [{severity}] {issue}")
        else:
            self.logger.success("No security issues detected")

    def _handle_fuzz(self):
        """Handle HART fuzzing"""
        if not self.scanner:
            return

        confirm = getattr(self.args, "confirm", False)
        if not confirm:
            self.logger.fail("--fuzz requires --confirm flag")
            return

        iterations = getattr(self.args, "fuzz_iterations", 20)
        fuzz_commands_str = getattr(self.args, "fuzz_commands", None)
        command_list = None
        if fuzz_commands_str:
            try:
                command_list = [int(c.strip()) for c in fuzz_commands_str.split(",")]
            except ValueError:
                self.logger.fail(f"Invalid --fuzz-commands value: {fuzz_commands_str}")
                return
        self.logger.display(f"Fuzzing HART commands ({iterations} iterations per command)...")

        results = self.scanner.fuzz_commands(iterations, command_list=command_list)
        self.results["data"]["fuzzing"] = results

        self.logger.display(f"Fuzzing complete: {results.get('tested', 0)} payloads tested")

        anomalies = results.get("anomalies", [])
        if anomalies:
            self.logger.warning(f"Anomalies detected: {len(anomalies)}")

    def _handle_raw_command(self):
        """Send raw HART command"""
        if not self.scanner:
            return

        command = getattr(self.args, "raw_command", None)
        if command is None:
            return

        # --raw-command can issue HART writes (6/17/18/19/41/42/53, etc.) —
        # named-write siblings in this file all gate on --confirm; the raw
        # path was wired around. Re-gated per safety-default policy.
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "--raw-command can issue arbitrary HART writes "
                "(6/17/18/19/41/42/53 etc.) — requires --confirm"
            )
            return

        data = b""
        raw_data = getattr(self.args, "raw_data", None)
        if raw_data:
            try:
                data = bytes.fromhex(raw_data.replace(" ", "").replace("0x", ""))
            except ValueError:
                self.logger.fail(f"Invalid hex data: {raw_data}")
                return

        self.logger.display(
            f"Sending raw command {command}" + (f" with {len(data)} bytes data" if data else "")
        )

        result = self.scanner.send_raw_command(command, data)
        self.results["data"]["raw_command"] = result

        if result.get("success"):
            self.logger.success(f"Command {command}: {result.get('response_code_name', 'OK')}")
            if result.get("payload"):
                self.logger.display(
                    f"  Response: {result['payload']} ({result['payload_length']} bytes)"
                )
        else:
            error = result.get("error", result.get("response_code_name", "Failed"))
            self.logger.fail(f"Command {command} failed: {error}")

    def _handle_check_lock(self):
        """Check device lock state"""
        if not self.scanner:
            return

        self.logger.display("Checking device lock state...")

        from .scanner import LockState

        lock_state = self.scanner.read_lock_state()
        self.results["data"]["lock_state"] = lock_state

        if lock_state == LockState.UNLOCKED:
            self.logger.security_finding(
                "No authentication", "Device is UNLOCKED - configuration writable"
            )
        elif lock_state == LockState.LOCKED:
            self.logger.success("Device is LOCKED - configuration protected")
        elif lock_state == LockState.PERMANENTLY_LOCKED:
            self.logger.success("Device is PERMANENTLY LOCKED")
        elif lock_state == LockState.NOT_SUPPORTED:
            self.logger.display("Device lock not supported (likely HART 5)")
        else:
            self.logger.display("Lock state: Unknown")

    def _handle_bruteforce_lock(self):
        """Handle device lock bruteforce"""
        if not self.scanner:
            return

        confirm = getattr(self.args, "confirm", False)
        if not confirm:
            self.logger.fail("--bruteforce-lock requires --confirm flag")
            return

        wordlist = getattr(self.args, "bruteforce_lock", None)
        delay = getattr(self.args, "bruteforce_delay", 0.1)

        from ...utils.login_scanner import format_wordlist_source

        self.logger.display(f"Bruteforcing lock codes from: {format_wordlist_source(wordlist)}")

        result = self.scanner.bruteforce_lock(wordlist=wordlist, delay=delay)
        self.results["data"]["bruteforce"] = result

        if result.get("success"):
            code = result.get("password", "")
            self.logger.security_finding("Weak password", f"Device lock code found: '{code}'")
        elif result.get("error"):
            self.logger.fail(f"Bruteforce failed: {result['error']}")
        else:
            self.logger.display(f"No valid code found after {result.get('tested', 0)} attempts")

    def _handle_lock_operations(self):
        """Handle lock/unlock operations (require --confirm)"""
        if not self.scanner:
            return

        confirm = getattr(self.args, "confirm", False)

        unlock_code = getattr(self.args, "unlock", None)
        if unlock_code is not None:
            if not confirm:
                self.logger.fail("--unlock requires --confirm flag")
            else:
                self.logger.display("Attempting to unlock device...")
                if self.scanner.try_unlock(unlock_code):
                    self.logger.success("Device unlocked successfully")
                else:
                    self.logger.fail(f"Failed to unlock device with code '{unlock_code}'")

        lock_code = getattr(self.args, "lock", None)
        if lock_code is not None:
            if not confirm:
                self.logger.fail("--lock requires --confirm flag")
            else:
                self.logger.display("Locking device...")
                if self.scanner.try_lock(lock_code):
                    self.logger.success("Device locked successfully")
                else:
                    self.logger.fail("Failed to lock device")

    def _handle_write_operations(self):
        """Handle write operations (require --confirm)"""
        if not self.scanner:
            return

        confirm = getattr(self.args, "confirm", False)

        new_addr = getattr(self.args, "write_poll_addr", None)
        if new_addr is not None:
            if not confirm:
                self.logger.fail("--write-poll-addr requires --confirm flag")
            else:
                self.logger.display(f"Writing new poll address: {new_addr}")
                if self.scanner.write_poll_address(new_addr):
                    self.logger.success(f"Poll address changed to {new_addr}")
                else:
                    self.logger.fail("Failed to write poll address")

        new_tag = getattr(self.args, "write_tag", None)
        if new_tag is not None:
            if not confirm:
                self.logger.fail("--write-tag requires --confirm flag")
            else:
                descriptor = getattr(self.args, "write_descriptor", "")
                self.logger.display(f"Writing tag: {new_tag}")
                if self.scanner.write_tag(new_tag, descriptor):
                    self.logger.success("Tag written successfully")
                else:
                    self.logger.fail("Failed to write tag")

        new_message = getattr(self.args, "write_message", None)
        if new_message is not None:
            if not confirm:
                self.logger.fail("--write-message requires --confirm flag")
            else:
                self.logger.display(f"Writing message: {new_message}")
                if self.scanner.write_message(new_message):
                    self.logger.success("Message written successfully")
                else:
                    self.logger.fail("Failed to write message")

        if getattr(self.args, "reset_config_flag", False):
            if not confirm:
                self.logger.fail("--reset-config-flag requires --confirm flag")
            else:
                self.logger.display("Resetting configuration changed flag...")
                if self.scanner.reset_config_flag():
                    self.logger.success("Configuration flag reset successfully")
                else:
                    self.logger.fail("Failed to reset configuration flag")

        if getattr(self.args, "self_test", False):
            if not confirm:
                self.logger.fail("--self-test requires --confirm flag")
            else:
                self.logger.display("Performing device self-test...")
                if self.scanner.perform_self_test():
                    self.logger.success("Self-test completed successfully")
                else:
                    self.logger.fail("Self-test failed")

        if getattr(self.args, "master_reset", False):
            if not confirm:
                self.logger.fail("--master-reset requires --confirm flag")
            else:
                self.logger.warning("Performing master reset...")
                if self.scanner.perform_master_reset():
                    self.logger.success("Device reset successfully")
                else:
                    self.logger.fail("Master reset failed")

    def cleanup(self):
        """Cleanup HART connection"""
        if self.conn and self.scanner:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("Connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if required dependencies are available"""
        return _hartip.is_available
