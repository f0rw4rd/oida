"""
PROFINET Cyclic IO Mixin

Handles cyclic IO operations:
- Module topology discovery
- IOCR configuration building
- Cyclic frame exchange
- Statistics reporting
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from ....utils.lazy_import import lazy_import
from ..models import ProfinetDevice

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


# Lazy imports for PROFINET cyclic IO (optional submodules of profinet-py)
_profinet_cyclic = lazy_import("profinet.cyclic", "PROFINET")
_profinet_rpc = lazy_import("profinet.rpc", "PROFINET")
_profinet_rt = lazy_import("profinet.rt", "PROFINET")


class CyclicMixin(_ScannerBase):
    """Mixin providing PROFINET cyclic IO operations."""

    def _cyclic_io_test(
        self,
        device: ProfinetDevice,
        discovered_slots: Optional[list] = None,
    ) -> None:
        """Run cyclic IO test on a device.

        Performs the full PROFINET cyclic IO lifecycle:
        1. Discover module topology (or use pre-discovered slots)
        2. Build IOCRSetup from discovered/GSDML modules
        3. Connect with IOCR (new AR)
        4. PrmEnd -> ApplicationReady -> CyclicController
        5. Run for configured duration, report statistics
        """
        import time

        duration = self._arg("cyclic_duration", 5)
        cycle_ms = self._arg("cyclic_cycle_ms", 128)

        if cycle_ms < 8:
            self.logger.fail("Cyclic cycle time must be >= 8ms")
            return

        self.logger.display(f"  Cyclic IO test ({duration}s, {cycle_ms}ms cycle)...")

        # Check cyclic IO dependencies (lazy-loaded at module level)
        if (
            not _profinet_cyclic.is_available
            or not _profinet_rpc.is_available
            or not _profinet_rt.is_available
        ):
            self.logger.fail(
                "  Cyclic IO requires profinet-py with cyclic support: pip install oida[profinet]"
            )
            return

        CyclicController = _profinet_cyclic.CyclicController
        IOCRSetup = _profinet_rpc.IOCRSetup
        IOSlot = _profinet_rpc.IOSlot
        RPCCon = _profinet_rpc.RPCCon
        build_iocr_configs = _profinet_rt.build_iocr_configs

        # Determine source MAC
        if self.interface and self._my_mac:
            src_mac = self._my_mac
        else:
            src_mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])

        if not self.interface:
            self.logger.fail("  Cyclic IO requires a network interface (not RPC-only mode)")
            return

        # Step 1: Get module topology
        if discovered_slots:
            device_slots = discovered_slots
            self.logger.display(f"  Using {len(device_slots)} pre-discovered slot entries")
        else:
            self.logger.display("  Discovering module topology...")
            try:
                acyclic_con = RPCCon(device._dcp_desc, timeout=self.timeout)
                try:
                    acyclic_con.connect(src_mac)
                    raw_slots = acyclic_con.discover_slots()
                finally:
                    acyclic_con.close()
                time.sleep(1)  # Let device release AR
                device_slots = [
                    (
                        s.slot,
                        s.subslot,
                        s.module_ident,
                        s.submodule_ident,
                    )
                    for s in raw_slots
                ]
            except Exception as e:
                self.logger.fail(f"  Failed to discover slots: {e}")
                return

        self.logger.display(f"  Found {len(device_slots)} slot/subslot entries")

        # Step 2: Build IOSlot list
        io_slots: list = []
        try:
            cyclic_slot_specs = self._arg("cyclic_slot", None) or []
            if cyclic_slot_specs:
                io_slots = self._build_io_slots_from_specs(cyclic_slot_specs, device_slots, IOSlot)
                if io_slots is None:
                    return

            if not io_slots:
                io_slots = self._build_io_slots_from_gsdml(device_slots)

            io_modules = [
                s for s in io_slots if s.slot != 0 and (s.input_length > 0 or s.output_length > 0)
            ]

            if not io_modules:
                if not io_slots or all(
                    s.input_length == 0 and s.output_length == 0 for s in io_slots
                ):
                    self.logger.fail(
                        "  No IO modules with known data sizes. "
                        "Use --cyclic-slot SLOT/SUB:IN:OUT"
                        " or --gsdml FILE."
                    )
                    return
                self.logger.fail("  No IO modules found in device topology")
                return

        except Exception as e:
            self.logger.fail(f"  Failed to build IO slot configuration: {e}")
            return

        # Display IO module summary
        total_in = sum(s.input_length for s in io_modules)
        total_out = sum(s.output_length for s in io_modules)
        for s in io_modules:
            io_desc = []
            if s.input_length > 0:
                io_desc.append(f"{s.input_length}B in")
            if s.output_length > 0:
                io_desc.append(f"{s.output_length}B out")
            self.logger.display(f"    slot={s.slot} sub={s.subslot}: {', '.join(io_desc)}")
        self.logger.display(f"  Total: {total_in}B input, {total_out}B output")

        # Step 3: Connect with IOCR
        send_clock_factor = 32  # 1ms base
        # reduction_ratio must be a power of two in 1..512 (PROFINET spec). With
        # send_clock_factor=32 (1ms) cycle_ms maps 1:1 to the ratio, so a value
        # like 100/200 is out of spec -- snap to the nearest valid power of two
        # instead of sending an invalid ratio the device would reject.
        _valid_ratios = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
        reduction_ratio = min(_valid_ratios, key=lambda r: abs(r - cycle_ms))
        if reduction_ratio != cycle_ms:
            self.logger.warning(
                f"  cycle_ms={cycle_ms} is not a valid PROFINET reduction ratio "
                f"(must be a power of two, 1-512); using nearest valid {reduction_ratio}ms"
            )

        setup = IOCRSetup(
            slots=io_modules,
            send_clock_factor=send_clock_factor,
            reduction_ratio=reduction_ratio,
            watchdog_factor=6,
            data_hold_factor=6,
        )

        con = None
        try:
            con = RPCCon(device._dcp_desc, timeout=10.0)

            # Drain stale UDP packets from previous AR
            con._socket.settimeout(0.1)
            try:
                while True:
                    con._socket.recvfrom(4096)
            except (TimeoutError, OSError) as e:
                self.logger.debug(f"cyclic exchange loop error: {e}")
            con._socket.settimeout(con.timeout)

            result = con.connect(src_mac, with_alarm_cr=True, iocr_setup=setup)

            if not result or not result.has_cyclic:
                self.logger.fail("  Cyclic IO not established by device")
                con.close()
                return
        except Exception as e:
            self.logger.fail(f"  IOCR connect failed: {e}")
            if con is not None:
                con.close()
            return

        self.logger.success(
            f"  IOCR connected"
            f" (input=0x{result.input_frame_id:04X},"
            f" output=0x{result.output_frame_id:04X})"
        )

        # Step 4: PrmEnd -> ApplicationReady
        try:
            con.prm_end()
            self.logger.display("  PrmEnd OK")
        except Exception as e:
            self.logger.fail(f"  PrmEnd failed: {e}")
            con.close()
            return

        try:
            con.application_ready(timeout=30.0)
            self.logger.display("  ApplicationReady OK")
        except Exception as e:
            self.logger.fail(f"  ApplicationReady failed: {e}")
            con.close()
            return

        # Step 5: Build IOCRConfig objects and start CyclicController
        try:
            input_iocr, output_iocr = build_iocr_configs(
                slots=io_modules,
                input_frame_id=result.input_frame_id,
                output_frame_id=result.output_frame_id,
                send_clock_factor=send_clock_factor,
                reduction_ratio=reduction_ratio,
                watchdog_factor=6,
            )

            dst_mac = bytes.fromhex(device._dcp_desc.mac.replace(":", ""))

            cyclic = CyclicController(
                interface=self.interface,
                src_mac=src_mac,
                dst_mac=dst_mac,
                input_iocr=input_iocr,
                output_iocr=output_iocr,
                max_consecutive_timeouts=3,
            )

            for s in io_modules:
                if s.output_length > 0:
                    cyclic.set_output_data(s.slot, s.subslot, bytes(s.output_length))

            cyclic.start()

            self.logger.display(f"  Cyclic exchange running for {duration}s...")

            start_time = time.monotonic()
            try:
                while time.monotonic() - start_time < duration:
                    time.sleep(1.0)
                    elapsed = time.monotonic() - start_time
                    self.logger.progress(
                        int(elapsed),
                        duration,
                        end="" if elapsed < duration else "\n",
                    )
            except KeyboardInterrupt:
                self.logger.display("\n  Interrupted by user")

            cyclic.stop()
            stats = cyclic.stats
            self.logger.display("")  # End progress line

            elapsed_s = time.monotonic() - start_time
            tx_fps = stats.frames_sent / elapsed_s if elapsed_s > 0 else 0
            rx_fps = stats.frames_received / elapsed_s if elapsed_s > 0 else 0
            self.logger.success(
                f"  Cyclic IO complete ({cyclic.state.value}):"
                f" TX={stats.frames_sent} ({tx_fps:.1f}/s)"
                f" RX={stats.frames_received} ({rx_fps:.1f}/s)"
                f" missed={stats.frames_missed}"
            )
            timing_parts = []
            if stats._cycle_count > 0:
                timing_parts.append(f"min={stats.min_cycle_time_us}us")
                timing_parts.append(f"avg={stats.avg_cycle_time_us}us")
                timing_parts.append(f"max={stats.max_cycle_time_us}us")
            if stats.max_jitter_us > 0:
                timing_parts.append(f"jitter={stats.max_jitter_us}us")
            if timing_parts:
                self.logger.display(f"  Timing: {', '.join(timing_parts)}")
            if stats.frames_invalid > 0:
                self.logger.display(f"  Invalid frames: {stats.frames_invalid}")
            if stats.frames_duplicate > 0:
                self.logger.display(f"  Duplicate frames: {stats.frames_duplicate}")
            if stats.frames_out_of_order > 0:
                self.logger.display(f"  Out-of-order frames: {stats.frames_out_of_order}")

        except Exception as e:
            self.logger.fail(f"  Cyclic IO error: {e}")
        finally:
            try:
                con.close()
                self.logger.display("  Disconnected cleanly")
            except Exception:
                self.logger.display("  Disconnect failed (device may need recovery)")

    def _build_io_slots_from_specs(
        self,
        cyclic_slot_specs: list,
        device_slots: list,
        IOSlot,
    ) -> Optional[list]:
        """Build IOSlot list from manual --cyclic-slot specs."""
        ident_map: dict = {}
        for ds in device_slots:
            slot_n, subslot_n, mod_id, submod_id = (
                ds
                if isinstance(ds, tuple)
                else (
                    ds.slot,
                    ds.subslot,
                    ds.module_ident,
                    ds.submodule_ident,
                )
            )
            ident_map[(slot_n, subslot_n)] = (mod_id, submod_id)

        io_slots = []
        for spec in cyclic_slot_specs:
            try:
                slot_part, in_len, out_len = spec.split(":")
                sp = slot_part.split("/")
                s_num = int(sp[0], 0)
                ss_num = int(sp[1], 0) if len(sp) > 1 else 1
                mod_id, submod_id = ident_map.get((s_num, ss_num), (0, 0))
                io_slots.append(
                    IOSlot(
                        slot=s_num,
                        subslot=ss_num,
                        module_ident=mod_id,
                        submodule_ident=submod_id,
                        input_length=int(in_len),
                        output_length=int(out_len),
                    )
                )
            except ValueError:
                self.logger.fail(f"  Invalid --cyclic-slot format: {spec} (use SLOT/SUB:IN:OUT)")
                return None
        self.logger.display(f"  Using {len(io_slots)} manual IO slot spec(s)")
        return io_slots

    def _build_io_slots_from_gsdml(self, device_slots: list) -> list:
        """Build IOSlot list from GSDML if available."""
        gsdml_path = self._arg("gsdml", None)
        if not gsdml_path:
            return []

        try:
            from types import SimpleNamespace

            from profinet.gsdml import load_gsdml

            gsdml_device = load_gsdml(gsdml_path)
            slot_objs = [
                (
                    SimpleNamespace(
                        slot=ds[0],
                        subslot=ds[1],
                        module_ident=ds[2],
                        submodule_ident=ds[3],
                    )
                    if isinstance(ds, tuple)
                    else ds
                )
                for ds in device_slots
            ]
            io_slots = gsdml_device.build_io_slots_from_device(slot_objs)
            self.logger.display("  Using GSDML for IO data sizes")
            return io_slots
        except Exception as e:
            self.logger.debug(f"  GSDML load failed: {e}")
            return []
