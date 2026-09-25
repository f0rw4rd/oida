"""
BACnet/SC (Secure Connect) transport mixin.

BACnet/SC is the modern secure datalink (TLS 1.3 + X.509 over WebSocket,
ANSI/ASHRAE 135 Annex AB). It is NOT a separate protocol: the entire BACnet
application layer (objects/properties/call/state/...) is reused unchanged - only
the transport, the target format (``wss://host:port``), and a handful of TLS/PKI
CLI options differ.

This mixin layers the SC transport onto the ``bacnet`` connection class. It is
engaged by ``--sc`` (see ``bacnet.__init__`` / ``bacnet.proto_flow``); without
that flag none of these methods run and the classic BACnet/IP UDP path is used.

Automatic TLS posture checks run on every SC connection (no flag): TLS version,
cipher strength, server-certificate hygiene, and - most importantly -
MUTUAL-AUTH ENFORCEMENT (a device/hub that accepts a missing or rogue client
certificate is critically misconfigured, since mutual X.509 auth is the whole
point of BACnet/SC).

WARNING: server-certificate verification is PERMISSIVE by default (this is a
pentest tool that must connect to whatever is there). A supplied client cert is
always presented for mutual-auth testing.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import urlparse


def parse_sc_uri(target: str, default_port: int) -> tuple[str, int, str]:
    """Parse a wss:// (or ws://) target into (host, port, normalized_uri).

    Accepts a bare host:port too (treated as wss://host:port) so the tool is
    forgiving. Raises ValueError on an unusable target.
    """
    raw = (target or "").strip()
    if "://" not in raw:
        raw = f"wss://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in ("wss", "ws"):
        raise ValueError(f"BACnet/SC target must be a wss:// URI, got scheme '{parsed.scheme}'")
    host = parsed.hostname
    if not host:
        raise ValueError(f"BACnet/SC target has no host: {target!r}")
    port = parsed.port or default_port
    normalized = f"{parsed.scheme}://{host}:{port}"
    return host, port, normalized


class SCMixin:
    """BACnet/SC transport methods, mixed into the ``bacnet`` connection class."""

    # BACnet/IP-only datalink recon flags (attr name -> CLI label) that have no
    # meaning over the SC point-to-point tunnel. Failed loud in _sc_proto_flow.
    _SC_UNSUPPORTED_FLAGS = (
        ("enum_bbmd", "--enum-bbmd"),
        ("enum_fdt", "--enum-fdt"),
        ("enum_routers", "--enum-routers"),
        ("who_has", "--who-has"),
        ("networks", "--networks"),
        ("scan_network", "--scan-network"),
        ("scan_all_networks", "--scan-all-networks"),
        ("test_bbmd_injection", "--test-bbmd-injection"),
    )

    # --- init-time transport setup ------------------------------------------

    def _sc_init(self, args: Any, host: str) -> str:
        """Parse the wss:// target and stash SC transport state.

        Runs from ``bacnet.__init__`` BEFORE ``NetworkConnection.__init__``
        resolves the host: rewrites ``host`` to the bare hostname (so DNS
        resolution + the logger work) and stashes the normalized URI + port on
        ``args``. Returns the bare host for the base initializer.
        """
        default_port = 47808
        try:
            parsed_host, parsed_port, normalized = parse_sc_uri(host, default_port)
        except ValueError:
            # Defer the error to proto_flow so the standard scan-failure path
            # logs it; keep host as-is for the logger.
            parsed_host, parsed_port, normalized = host, default_port, host
            self._sc_uri_error = True
        else:
            self._sc_uri_error = False

        # Let the wss:// URI's explicit port win over the (default) --port.
        if getattr(args, "port", None) in (None, default_port):
            args.port = parsed_port

        self._sc_uri = normalized
        self.default_port = parsed_port
        return parsed_host

    # --- transport-specific flow --------------------------------------------

    def _sc_proto_flow(self):
        """BACnet/SC scanning workflow (SC transport, inherited actions)."""
        from oida.protocols.bacnet.constants import _load_bacpypes3

        _load_bacpypes3()
        self._apply_shortcuts()

        if getattr(self.args, "list_services", False):
            self._handle_list_services()
            return

        if self._sc_uri_error:
            self.logger.fail(f"Invalid BACnet/SC target '{self.host}': expected wss://host:port")
            self.results["success"] = False
            return

        # --monitor / --diff are BAC0-only; not supported over SC.
        if getattr(self.args, "monitor", False):
            self.logger.fail("--monitor is not supported over BACnet/SC")
        if getattr(self.args, "diff", None):
            self.logger.fail("--diff is not supported over BACnet/SC")

        # BACnet/IP datalink-layer recon (BBMD/FDT/foreign-device tables, local
        # broadcast Who-Has, remote-network discovery) is meaningless over SC:
        # the SC link is a point-to-point TLS tunnel with no IP broadcast domain,
        # and the inherited handlers would emit GlobalBroadcast PDUs that the SC
        # link flattens to a unicast to the single peer. Fail loud rather than
        # silently no-op so the operator isn't misled by empty results.
        for flag, label in self._SC_UNSUPPORTED_FLAGS:
            present = getattr(self.args, flag, None)
            # scan_network takes an int (0 is valid), so test against None.
            if present not in (None, False):
                self.logger.fail(f"{label} is not supported over BACnet/SC")

        asyncio.run(self._async_sc_scan())

    async def _async_sc_scan(self):
        """Build the SC app, run automatic TLS checks, dispatch inherited actions."""
        from oida.protocols.bacnet.constants import _load_bacpypes3
        from oida.protocols.bacnet.sc_link import SCConnection
        from oida.protocols.bacnet import sc_tls

        timeout = getattr(self.args, "timeout", 10.0) or 10.0
        device_id = getattr(self.args, "device_id", None)

        hub_uri = getattr(self.args, "sc_hub_uri", None)
        # --hub-uri routes via an SC hub; --direct (sc_direct) connects straight
        # to the target. They are mutually exclusive and direct is the default
        # when neither is given, so --direct explicitly wins if both are set.
        direct = getattr(self.args, "sc_direct", False)
        use_hub = bool(hub_uri) and not direct
        uri = hub_uri if use_hub else self._sc_uri
        topology = "hub" if use_hub else "direct"

        ca = getattr(self.args, "sc_ca", None)
        cert = getattr(self.args, "sc_cert", None)
        key = getattr(self.args, "sc_key", None)

        self.logger.display(f"Connecting to BACnet/SC ({topology}) {uri} ...")
        if cert and key:
            self.logger.debug("BACnet/SC: presenting client certificate (mutual auth)")
        else:
            self.logger.warning(
                "BACnet/SC: no client cert supplied (--cert/--key); "
                "mutual-auth attempt will be anonymous"
            )

        # --- ACTIVE TLS posture probes FIRST -------------------------------
        # The mutual-auth / downgrade probes each open their OWN fresh SC
        # connection. They run BEFORE the persistent scan connection because
        # some SC servers (e.g. bacnet-stack's single-threaded libwebsockets
        # backend) serve one connection at a time - a probe opened while the
        # scan link is held would be reset, producing a false negative.
        if not getattr(self.args, "sc_no_tls_checks", False):
            try:
                await self._probe_mutual_auth(uri, use_hub)
                await self._probe_tls_downgrade(uri, use_hub)
            except Exception as e:
                self.logger.debug(f"BACnet/SC active TLS probes error: {e}")

        # --- persistent scan connection ------------------------------------
        ctx = sc_tls.build_client_context(ca, cert, key)
        sc_conn = SCConnection(uri, ctx, hub=use_hub, timeout=timeout)
        try:
            peer_vmac = await sc_conn.open()
        except Exception as e:
            # open() may bring the websocket up before the BVLC-SC handshake
            # fails (recv timeout / non-Connect-Accept / decode error). Close it
            # so the socket + reader task don't leak; close() is a no-op when the
            # websocket was never established.
            await sc_conn.close()
            self.logger.fail(f"BACnet/SC connection failed: {e}")
            self.results["success"] = False
            return

        cipher = sc_conn.peer_cipher()
        ver = cipher[1] if cipher else "?"
        self.logger.success(f"Connected to BACnet/SC {uri} (TLS {ver}, peer VMAC {peer_vmac})")

        # --- PASSIVE TLS checks on the live connection ---------------------
        if not getattr(self.args, "sc_no_tls_checks", False):
            try:
                sc_tls.audit_tls_version(cipher, self.logger)
                sc_tls.audit_cipher(cipher, self.logger)
                sc_tls.audit_server_cert(sc_conn.peer_cert_der(), self.host, self.logger)
            except Exception as e:
                self.logger.debug(f"BACnet/SC passive TLS checks error: {e}")

        # --- build the bacpypes3 app over the SC link ------------------------
        types = _load_bacpypes3()
        DeviceObject = types["DeviceObject"]
        from bacpypes3.app import Application

        local_dev = DeviceObject(
            objectIdentifier=("device", 599999),
            objectName="OIDA-SC-Scanner",
            vendorIdentifier=999,
            vendorName="OIDA",
            modelName="BACnet/SC Scanner",
        )
        app = Application.from_object_list([local_dev])
        link = sc_conn.make_link_layer(logger=self.logger)
        app.nsap.bind(link, address=sc_conn.local_vmac)

        target_addr = peer_vmac  # address the device by its negotiated VMAC
        try:
            await self._bacpypes3_run_actions(app, target_addr, device_id, timeout)
        finally:
            try:
                app.close()
            except Exception:
                pass
            await link.close()
            await sc_conn.close()

        self._bacnet_response_gate()
        self.enum_host_info()
        self._export_results()

    # --- automatic TLS posture probes ---------------------------------------

    async def _sc_handshake_succeeds(self, ctx, uri, use_hub, timeout=6.0) -> bool:
        """True iff a fresh SC connect+handshake completes with this context.

        A completed handshake => the server ACCEPTED this credential/version
        (the finding condition). A clean TLS/SC rejection => not accepted (no
        finding). A transient ConnectionReset (single-threaded SC servers serve
        one socket at a time) is retried a couple of times so contention does
        not mask a real "accepted" result with a false negative.

        Exception classification matters here: ``ssl.SSLError`` is a SUBCLASS of
        ``OSError``, so a TLS-layer rejection (the server sending a fatal alert
        because we presented no/invalid client cert - exactly the secure-device
        case) must be caught BEFORE the OSError retry arm, otherwise an enforced
        control would burn 3×1s retries before (correctly, but slowly and with a
        misleading "inconclusive" log) concluding not-accepted. Only genuine
        transport resets are retried.
        """
        import ssl as _ssl

        from websockets.exceptions import InvalidHandshake

        from oida.protocols.bacnet.sc_link import SCConnection

        last_exc = None
        for attempt in range(3):
            probe = SCConnection(uri, ctx, hub=use_hub, timeout=timeout)
            try:
                await probe.open()
                return True
            except (_ssl.SSLError, InvalidHandshake) as e:
                # TLS alert / rejected WebSocket upgrade: the server REFUSED this
                # credential/version. Definite rejection - not accepted, no retry.
                self.logger.debug(f"SC probe TLS-rejected: {type(e).__name__}: {e}")
                return False
            except (ConnectionResetError, ConnectionAbortedError) as e:
                # Transient contention (single-threaded server busy): retry.
                last_exc = e
                await asyncio.sleep(1.0)
            except OSError as e:
                # Connection refused / host unreachable / other transport error:
                # not accepted. Don't loop (retrying won't change the verdict).
                self.logger.debug(f"SC probe transport error: {type(e).__name__}: {e}")
                return False
            except Exception as e:
                # A definite rejection (SC NACK, timeout, decode error): not accepted.
                self.logger.debug(f"SC probe rejected: {type(e).__name__}: {e}")
                return False
            finally:
                await probe.close()
        self.logger.debug(f"SC probe inconclusive after retries: {last_exc}")
        return False

    async def _probe_mutual_auth(self, uri, use_hub):
        """A device/hub that accepts a missing or rogue client cert is broken."""

        from oida.protocols.bacnet import sc_tls

        timeout = getattr(self.args, "timeout", 6.0) or 6.0

        # Probe 1: NO client certificate.
        anon_ctx = sc_tls.build_client_context(getattr(self.args, "sc_ca", None), None, None)
        if await self._sc_handshake_succeeds(anon_ctx, uri, use_hub, timeout):
            self.logger.security_finding(
                "BACnet/SC mutual auth NOT enforced (anonymous client accepted)",
                "Device/hub completed the SC handshake with NO client "
                "certificate. BACnet/SC requires mutual X.509 authentication; "
                "an anonymous peer must be rejected.",
            )

        # Probe 2: ROGUE self-signed client certificate.
        try:
            rogue_cert, rogue_key = sc_tls.make_rogue_cert_files()
        except Exception as e:
            self.logger.debug(f"rogue-cert probe skipped (no cryptography?): {e}")
            return
        try:
            rogue_ctx = sc_tls.build_client_context(
                getattr(self.args, "sc_ca", None), rogue_cert, rogue_key
            )
            if await self._sc_handshake_succeeds(rogue_ctx, uri, use_hub, timeout):
                self.logger.security_finding(
                    "BACnet/SC mutual auth NOT enforced (rogue client cert accepted)",
                    "Device/hub completed the SC handshake with a self-signed "
                    "client certificate not chaining to its issuer CA. Any "
                    "attacker can connect.",
                )
        finally:
            for p in (rogue_cert, rogue_key):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    async def _probe_tls_downgrade(self, uri, use_hub):
        """A device that completes a TLS 1.2 handshake violates the SC mandate."""
        import ssl as _ssl

        from oida.protocols.bacnet import sc_tls

        timeout = getattr(self.args, "timeout", 6.0) or 6.0
        ctx12 = sc_tls.build_client_context(
            getattr(self.args, "sc_ca", None),
            getattr(self.args, "sc_cert", None),
            getattr(self.args, "sc_key", None),
            max_version=_ssl.TLSVersion.TLSv1_2,
        )
        if await self._sc_handshake_succeeds(ctx12, uri, use_hub, timeout):
            self.logger.security_finding(
                "BACnet/SC accepts TLS 1.2 (downgrade)",
                "Device/hub completed a handshake pinned to TLS 1.2. BACnet/SC "
                "mandates TLS 1.3; accepting 1.2 is a downgrade exposure.",
            )

    def _sc_print_host_info(self):
        """SC-mode variant of print_host_info (keyed off the wss:// URI)."""
        if getattr(self.args, "quiet", False):
            return
        if self.devices:
            self.logger.success(f"BACnet/SC: {self._sc_uri}")
            self.logger.display(f"    Devices Found: {len(self.devices)}")
        else:
            self.logger.display(f"BACnet/SC: {self._sc_uri}")
