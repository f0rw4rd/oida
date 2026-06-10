"""PROFINET protocol scanner using profinet-py library."""

from typing import Any, Dict, Optional

from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import
from ...utils.permissions import check_raw_socket_capability
from .gsdml_parser import parse_gsdml, GSDMLDevice
from .models import ProfinetDevice
from .mixins import RPCMixin, EnumerationMixin, FuzzMixin, CyclicMixin

_profinet = lazy_import("profinet", "PROFINET")


class profinet(RPCMixin, EnumerationMixin, FuzzMixin, CyclicMixin, NetworkConnection):
    """PROFINET IO scanner with DCP discovery and RPC operations."""

    name = "PROFINET"
    protocol_name = "PROFINET"
    default_port = 0  # Layer 2 protocol

    def _arg(self, name: str, default: Any = None) -> Any:
        """Get argument value from args (namespace or dict)."""
        if hasattr(self.args, name):
            return getattr(self.args, name, default)
        if isinstance(self.args, dict):
            return self.args.get(name, default)
        return default

    @staticmethod
    def _parse_slot_arg(slot_str: str) -> tuple:
        """Parse slot argument: '1' or '1/1' or '1/0x8001'.

        Returns:
            (slot, subslot) tuple, or (slot, None) if no subslot specified
        """
        if not slot_str:
            return (None, None)

        parts = slot_str.split("/")
        try:
            slot = int(parts[0], 0)
            subslot = int(parts[1], 0) if len(parts) > 1 else None
            return (slot, subslot)
        except ValueError:
            return (None, None)

    def __init__(self, args, db, host):
        # Check if RPC-only mode (target is IP, not interface)
        self.rpc_only = (
            getattr(args, "rpc_only", False)
            if hasattr(args, "rpc_only")
            else args.get("rpc_only", False)
            if isinstance(args, dict)
            else False
        )

        if self.rpc_only:
            self.target_ip = host
            self.interface = None
        else:
            self.interface = host
            self.target_ip = None

        self.timeout = float(
            getattr(args, "timeout", 3.0)
            if hasattr(args, "timeout")
            else args.get("timeout", 3.0)
            if isinstance(args, dict)
            else 3.0
        )
        self.discovered_devices: Dict[str, ProfinetDevice] = {}
        self._my_mac = None
        self._gsdml: Optional[GSDMLDevice] = None

        # Load GSDML if provided
        gsdml_path = (
            getattr(args, "gsdml", None)
            if hasattr(args, "gsdml")
            else args.get("gsdml", None)
            if isinstance(args, dict)
            else None
        )
        if gsdml_path:
            self._gsdml = parse_gsdml(gsdml_path)

        # Call parent init (sets up args, db, host, conn, logger, and calls proto_flow)
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main protocol execution flow."""

        if not _profinet.is_available:
            self.logger.fail("profinet-py not installed (pip install profinet-py)")
            return

        if self.rpc_only:
            self._rpc_only_mode()
        else:
            # DCP discovery mode - needs raw socket
            has_cap, msg = check_raw_socket_capability()
            if not has_cap:
                self.logger.fail(msg)
                return

            self.create_conn_obj()
            if self.conn:
                self.enum_host_info()
                self.print_host_info()

    def create_conn_obj(self):
        """Validate interface for DCP operations."""
        try:
            profinet_mod = _profinet()
            sock = profinet_mod.ethernet_socket(self.interface, 0x8892)
            sock.close()
            self.conn = self.interface
            self.logger.success(f"DCP interface {self.interface} ready")
        except Exception as e:
            self.logger.fail(f"Failed to open interface {self.interface}: {e}")
            self.conn = None

    def _rpc_only_mode(self):
        """Direct RPC connection without DCP discovery (for routed networks)."""
        profinet_mod = _profinet()

        self.logger.display(f"Connecting to {self.target_ip} via RPC (no DCP discovery)")

        # Create a minimal device info for RPC
        vendor_id = self._arg("vendor_id", 0)
        device_id = self._arg("device_id", 0)

        device = ProfinetDevice(
            mac_address="00:00:00:00:00:00",
            ip_address=self.target_ip,
            vendor_id=vendor_id,
            device_id=device_id,
        )

        # For RPC-only mode, create a mock DCPDeviceDescription
        class MockDCPDesc:
            """Mock DCP description for RPC-only mode."""

            def __init__(self, ip, vendor, dev_id):
                self.ip = ip
                self.name = ""
                self.mac = "00:00:00:00:00:00"
                self.netmask = "255.255.255.0"
                self.gateway = "0.0.0.0"
                self.vendor_high = (vendor >> 8) & 0xFF
                self.vendor_low = vendor & 0xFF
                self.device_high = (dev_id >> 8) & 0xFF
                self.device_low = dev_id & 0xFF
                self.vendor_id = vendor
                self.device_id = dev_id
                self.device_type = ""
                self.device_roles = []
                self.vendor_name = ""

        mock_desc = MockDCPDesc(self.target_ip, vendor_id, device_id)
        device._dcp_desc = mock_desc

        if vendor_id == 0 or device_id == 0:
            self.logger.display(
                "Note: For AR establishment, you may need --vendor-id and --device-id"
            )

        read_im = self._arg("read_im", True)
        read_diag = self._arg("read_diagnosis", False)
        enum_idx = (
            self._arg("enum", False)
            or self._arg("enum_all", False)
            or self._arg("enum_smart", False)
            or self._arg("enum_range", None)
        )

        if not (read_im or read_diag or enum_idx):
            self.logger.display(
                "No RPC operations specified (use --read-im, --read-diagnosis, or --enum)"
            )
            return

        try:
            con = profinet_mod.RPCCon(mock_desc, timeout=self.timeout)

            # For RPC-only, try AR establishment with a locally-administered MAC
            fake_mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            try:
                con.connect(fake_mac)
                self.logger.success(f"RPC AR established to {self.target_ip}")
                use_implicit = False
            except Exception as e:
                self.logger.debug(f"AR establishment failed: {e}, falling back to implicit reads")
                use_implicit = True
                self.logger.success(f"RPC connection to {self.target_ip} (implicit mode)")
        except Exception as e:
            self.logger.fail(f"RPC connection failed: {e}")
            self._show_rpc_hint()
            return

        try:
            if read_im:
                if use_implicit:
                    self._read_im_data_implicit(device, con, profinet_mod)
                else:
                    self._read_im_data(device, con, profinet_mod)
            if read_diag:
                if use_implicit:
                    self._read_diagnosis_implicit(device, con, profinet_mod)
                else:
                    self._read_diagnosis(device, con, profinet_mod)
            if enum_idx:
                self._enumerate_indices(device, con)

            fuzz_mode = self._arg("fuzz", None)
            if fuzz_mode:
                self._handle_fuzz(device, con)
        finally:
            con.close()

        self.discovered_devices[device.ip_address] = device

    def enum_host_info(self):
        """Enumerate PROFINET devices via DCP discovery."""
        profinet_mod = _profinet()

        self.logger.display(f"DCP discovery on {self.interface}...")

        try:
            # Use library's scan() for high-level discovery
            from profinet import scan as pn_scan

            devices = []
            for pn_dev in pn_scan(self.interface, timeout=self.timeout):
                device = self._pn_device_to_oida(pn_dev, profinet_mod)
                devices.append(device)

            self._my_mac = profinet_mod.get_mac(self.interface)
            self.logger.display(f"DCP discovery completed ({len(devices)} device(s))")

        except Exception as e:
            self.logger.fail(f"DCP discovery failed: {e}")
            return

        if not devices:
            self.logger.fail("No PROFINET devices found")
            return

        no_rpc = self._arg("no_rpc", False)

        for device in devices:
            self._display_device(device)

            if not no_rpc and device.ip_address and device.ip_address != "0.0.0.0":
                self._rpc_operations(device, profinet_mod)

            self.discovered_devices[device.mac_address] = device

        # Store in results
        self.results["data"]["devices"] = [
            {
                "mac": d.mac_address,
                "name": d.name_of_station,
                "ip": d.ip_address,
                "vendor": d.vendor_name,
            }
            for d in self.discovered_devices.values()
        ]

        # DCP write operations (flash, set-name, set-ip, reset-factory)
        mac = self._arg("mac_address", None)
        if mac and self._arg("flash", False):
            self._flash_device(profinet_mod, mac)

        self._write_operations(profinet_mod)

    def _pn_device_to_oida(self, pn_dev, profinet_mod=None) -> ProfinetDevice:
        """Convert a profinet-py ProfinetDevice to OIDA ProfinetDevice.

        Args:
            pn_dev: profinet.ProfinetDevice from library scan()
            profinet_mod: The profinet module (optional, for vendor lookup)

        Returns:
            OIDA ProfinetDevice instance
        """
        from datetime import datetime
        from ...utils.vendor_maps import profinet_vendor_map

        info = pn_dev._info  # DCPDeviceDescription
        vendor_id = info.vendor_id
        device_id = info.device_id

        # Resolve vendor name
        vendor_name = profinet_vendor_map.get(vendor_id, f"Unknown (0x{vendor_id:04X})")
        if vendor_name.startswith("Unknown"):
            lib_vendor = getattr(info, "vendor_name", "")
            if lib_vendor and not lib_vendor.startswith("Unknown"):
                vendor_name = lib_vendor

        return ProfinetDevice(
            mac_address=pn_dev.mac,
            name_of_station=pn_dev.name,
            device_type=getattr(info, "device_type", ""),
            ip_address=pn_dev.ip,
            subnet_mask=getattr(info, "netmask", ""),
            gateway=getattr(info, "gateway", ""),
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            device_id=device_id,
            device_roles=getattr(info, "device_roles", []),
            device_instance=getattr(info, "device_instance", (0, 0)),
            alias_name=getattr(info, "alias_name", ""),
            supported_options=getattr(info, "supported_options", []),
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            _dcp_desc=info,
            _pn_device=pn_dev,
        )

    def print_host_info(self):
        """Print summary of discovered devices."""
        pass  # Summary already shown per-device

    def _display_device(self, device: ProfinetDevice):
        """Display device info in NXC style."""
        if device.ip_address and device.ip_address != "0.0.0.0":
            name_part = f" ({device.name_of_station})" if device.name_of_station else ""
            self.logger.success(f"{device.ip_address}{name_part} - {device.mac_address}")
        else:
            name_part = device.name_of_station if device.name_of_station else "unnamed"
            self.logger.success(f"{name_part} - {device.mac_address}")

        if device.device_type:
            self.logger.display(f"  Type: {device.device_type}")
        self.logger.display(f"  Vendor: {device.vendor_name} (0x{device.vendor_id:04X})")
        self.logger.display(f"  Device ID: 0x{device.device_id:04X}")
        if device.device_roles:
            self.logger.display(f"  Role: {', '.join(device.device_roles)}")
        if device.device_instance != (0, 0):
            self.logger.display(
                f"  Instance: {device.device_instance[0]}.{device.device_instance[1]}"
            )

    def _flash_device(self, profinet_mod, mac: str):
        """Flash device LED for identification."""
        self.logger.display(f"Flashing device LED: {mac}")
        try:
            sock = profinet_mod.ethernet_socket(self.interface, 0x8892)
            src_mac = profinet_mod.get_mac(self.interface)
            profinet_mod.signal_device(
                sock, src_mac, mac, duration_ms=3000, timeout_sec=int(self.timeout)
            )
            sock.close()
            self.logger.success(f"Flash signal sent to {mac}")
        except Exception as e:
            self.logger.fail(f"Failed to flash device: {e}")

    def _write_operations(self, profinet_mod):
        """Perform write operations via DCP Set (requires --confirm)."""
        mac = self._arg("mac_address", None)
        if not mac:
            return

        set_name = self._arg("set_name", None)
        set_ip = self._arg("set_ip", None)
        reset_factory = self._arg("reset_factory", False)

        if not (set_name or set_ip or reset_factory):
            return

        if not self._arg("confirm", False):
            self.logger.fail(
                "DCP write operations require --confirm (set-name, set-ip, reset-factory)"
            )
            return

        try:
            sock = profinet_mod.ethernet_socket(self.interface, 0x8892)
            src_mac = profinet_mod.get_mac(self.interface)
        except Exception as e:
            self.logger.fail(f"Failed to open interface for write operations: {e}")
            return

        try:
            if set_name:
                self.logger.display(f"Setting station name to: {set_name}")
                try:
                    profinet_mod.set_param(
                        sock,
                        src_mac,
                        mac,
                        "name",
                        set_name,
                        timeout_sec=int(self.timeout),
                    )
                    self.logger.success(f"Station name set to '{set_name}'")
                except Exception as e:
                    self.logger.fail(f"Failed to set station name: {e}")

            if set_ip:
                self.logger.display(f"Setting IP to: {set_ip}")
                try:
                    parts = set_ip.split("/")
                    ip = parts[0]
                    cidr = int(parts[1]) if len(parts) > 1 else 24
                    gateway = parts[2] if len(parts) > 2 else ".".join(ip.split(".")[:3]) + ".1"

                    mask_bits = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
                    mask = (
                        f"{(mask_bits >> 24) & 0xFF}."
                        f"{(mask_bits >> 16) & 0xFF}."
                        f"{(mask_bits >> 8) & 0xFF}."
                        f"{mask_bits & 0xFF}"
                    )

                    profinet_mod.set_ip(
                        sock,
                        src_mac,
                        mac,
                        ip,
                        mask,
                        gateway,
                        timeout_sec=int(self.timeout),
                    )
                    self.logger.success(f"IP set to {ip}/{mask}/{gateway}")
                except Exception as e:
                    self.logger.fail(f"Failed to set IP: {e}")

            if reset_factory:
                self.logger.display(f"Resetting device to factory defaults: {mac}")
                try:
                    # reset_to_factory(sock, src, target, mode=2, timeout_sec=5).
                    # The old (self.interface, mac) call raised TypeError
                    # (missing target) — reuse the opened sock + src_mac.
                    profinet_mod.reset_to_factory(
                        sock, src_mac, mac, timeout_sec=int(self.timeout)
                    )
                    self.logger.success(f"Factory reset sent to {mac}")
                except Exception as e:
                    self.logger.fail(f"Failed to reset device: {e}")
        finally:
            sock.close()
