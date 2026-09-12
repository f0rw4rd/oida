#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CoAP NXC-style callable class."""

import time as _time

from ...connection import NetworkConnection
from ...utils.payload import resolve_file_payload

from .scanner import CoAPScanner
from .helpers import (
    parse_payload,
    coap_request,
    try_dtls_psk,
    try_dtls_cert,
    try_dtls_rpk,
    run_async,
)
from .constants import (
    CONTENT_FORMATS,
    CONTENT_FORMAT_ALIASES,
    DEFAULT_DTLS_PORT,
)

from ...utils.lazy_import import lazy_import

_aiocoap = lazy_import("aiocoap", "CoAP")
# DTLSSocket is deliberately NOT a declared dependency of the `coap` extra
# (dropped in 5c5b890 — it is painful to build and most CoAP scans never use
# DTLS). aiocoap's tinydtls transport imports it at handshake time, so every
# DTLS path (--dtls/--psk/--dtls-cert/--dtls-rpk) requires the operator to
# install it manually. Probe via importlib rather than a lazy_import guard so
# the requested-but-unavailable case fails loudly with an explicit message
# instead of silently falling back to a cleartext scan.
_DTLS_PIP_HINT = "pip install 'DTLSSocket; sys_platform != \"win32\"'"


def _dtls_available() -> bool:
    """True when the optional DTLSSocket backend can actually be imported."""
    import importlib.util

    return importlib.util.find_spec("DTLSSocket") is not None


class coap(NetworkConnection):
    """NXC-style CoAP scanner (callable)."""

    name = "CoAP"
    protocol_name = "CoAP"
    default_port = 5683

    def __init__(self, args, db, host):
        self.scanner = None
        self._scan_results = None
        # Capture the user-supplied port (None when -p is omitted) BEFORE
        # super().__init__() — NetworkConnection.__init__ clobbers args.port
        # with self.default_port (5683) whenever it is falsy, which would
        # otherwise make every DTLS `... or DEFAULT_DTLS_PORT` fallback dead.
        self._user_port = getattr(args, "port", None)
        # Set port before super().__init__() which calls proto_flow()
        self.port = self._user_port or self.default_port
        super().__init__(args, db, host)

    def _resolve_dtls_port(self):
        """Effective DTLS port: explicit -p wins, else DEFAULT_DTLS_PORT (5684).

        ``_user_port`` is the port the user actually passed (None when -p is
        omitted), captured in __init__ before NetworkConnection clobbers
        args.port. Fall back to args.port for instances built without __init__.
        """
        _missing = object()
        user_port = getattr(self, "_user_port", _missing)
        if user_port is _missing:
            # Instance built without __init__ (e.g. unit-test mocks): fall back
            # to args.port, which such tests set explicitly.
            user_port = getattr(getattr(self, "args", None), "port", None)
        return user_port or DEFAULT_DTLS_PORT

    def proto_flow(self):
        """Main CoAP scanning workflow."""
        self.logger.debug("proto_flow: host=%s, port=%s", self.host, self.port)

        args_dict = self._convert_args_to_dict()
        self.scanner = CoAPScanner(args_dict)

        dtls_cert = getattr(self.args, "dtls_cert", None)
        dtls_key = getattr(self.args, "dtls_key", None)
        dtls_ca = getattr(self.args, "dtls_ca", None)
        dtls_rpk = getattr(self.args, "dtls_rpk", None)
        psk_arg = getattr(self.args, "psk", None)
        psk_id_arg = getattr(self.args, "psk_identity", None)
        dtls_requested = (
            getattr(self.args, "dtls", False) or dtls_cert or dtls_rpk or psk_arg or psk_id_arg
        )

        if dtls_requested and not _dtls_available():
            # DTLS was explicitly requested but the optional DTLSSocket backend
            # is not installed. Abort loudly rather than silently downgrading to
            # a cleartext CoAP scan — a user asking for DTLS-PSK/cert auth must
            # never have their credentials/probes shipped over plaintext UDP.
            self.logger.fail(
                "DTLS support is unavailable: the DTLSSocket backend is not "
                "installed (it was removed from the 'coap' extra). Install it "
                "manually with: %s",
                _DTLS_PIP_HINT,
            )
            self.results["success"] = False
            self.results["error"] = "DTLS unavailable: DTLSSocket not installed"
            return

        # Bare -D/--dtls (no PSK/cert/RPK) can never establish a session:
        # DTLS has no anonymous/NoSec mode, so there is no key material for a
        # handshake to authenticate with -- none of the _try_dtls_*/bruteforce
        # branches below even run without one. Reject explicitly here instead
        # of silently falling through to the generic "DTLS connection failed"
        # hard-fail further down, which implies a handshake was attempted
        # when none ever ran.
        dtls_has_credentials = bool(dtls_cert or dtls_rpk or psk_arg or psk_id_arg)
        if dtls_requested and not dtls_has_credentials:
            self.logger.fail(
                "--dtls requires credentials: pass --psk/--psk-identity (PSK), "
                "--dtls-cert/--dtls-key (certificate), or --dtls-rpk (raw "
                "public key). DTLS has no anonymous mode to probe with -D alone."
            )
            self.results["success"] = False
            self.results["error"] = "DTLS requires --psk, --dtls-cert, or --dtls-rpk"
            return

        # Reject the cert/key XOR explicitly. Cert-without-key passes the
        # presence check above but the `dtls_cert and dtls_key` branch is False,
        # so no handshake runs yet the run hard-fails "DTLS connection failed"
        # (implying one was attempted); key-without-cert silently downgrades to
        # plaintext, ignoring the key. Name the missing flag instead.
        if bool(dtls_cert) != bool(dtls_key):
            missing = "--dtls-key" if dtls_cert else "--dtls-cert"
            self.logger.fail(
                f"DTLS certificate auth requires BOTH --dtls-cert and --dtls-key; "
                f"{missing} is missing."
            )
            self.results["success"] = False
            self.results["error"] = f"DTLS certificate auth missing {missing}"
            return

        if dtls_cert and dtls_key:
            self.logger.debug("DTLS certificate authentication requested")
            dtls_ok = self._try_dtls_cert(dtls_cert, dtls_key, dtls_ca)
            if dtls_ok:
                self.logger.debug("DTLS certificate connection established")
                self._activate_dtls_scheme()
            else:
                self.logger.debug("DTLS certificate auth failed, falling back")

        # DTLS RPK auth (if --dtls-rpk provided)
        if not self.conn and dtls_rpk:
            self.logger.debug("DTLS RPK authentication requested")
            dtls_ok = self._try_dtls_rpk(dtls_rpk)
            if dtls_ok:
                self.logger.debug("DTLS RPK connection established")
                self._activate_dtls_scheme()
            else:
                self.logger.debug("DTLS RPK auth failed, falling back")

        # DTLS-PSK bruteforce (if --psk or --psk-identity provided)
        if not self.conn and (psk_arg or psk_id_arg):
            self.logger.debug("PSK/DTLS authentication requested")
            dtls_ok = self._bruteforce_dtls_psk(psk_arg, psk_id_arg)
            if dtls_ok:
                self.logger.debug("DTLS-PSK connection established, proceeding with scan")
                self._activate_dtls_scheme()
            else:
                self.logger.debug("DTLS-PSK failed, falling back to plain CoAP")

        # Show connection status if DTLS succeeded
        if self.conn:
            self.logger.success("CoAPs (DTLS) server responding")

        # If DTLS was requested but didn't connect, hard fail
        if not self.conn and dtls_requested:
            self.logger.fail("DTLS connection failed")
            self.results["success"] = False
            self.results["error"] = "DTLS connection failed"
            return

        # Plain CoAP connection (only when DTLS was not requested)
        if not self.conn:
            t0 = _time.monotonic()
            self.create_conn_obj()
            elapsed = _time.monotonic() - t0
            self.logger.debug("Plain CoAP connection took %.2fs", elapsed)
            if not self.conn:
                self.logger.fail("Connection failed: CoAP endpoint not reachable")
                self.results["success"] = False
                self.results["error"] = "Connection failed"
                return

        self.logger.debug("Starting resource enumeration")
        self.enum_host_info()
        self.print_host_info()
        self._execute_features()

        self.logger.debug("proto_flow: completed successfully")

    def _activate_dtls_scheme(self):
        """Switch the scanner to coaps:// and point it at the DTLS port.

        Without explicit -p, the scanner's port comes from
        ``get_target_info()`` = ``rport or port or default`` = 5683, but the
        DTLS handshake (and thus the live session) is on ``DEFAULT_DTLS_PORT``
        (5684). Inject ``rport`` so post-handshake discovery/writes build
        ``coaps://host:<dtls_port>/...`` against the negotiated session
        instead of silently failing against cleartext 5683.
        """
        self.scanner._scheme = "coaps"
        dtls_port = self._resolve_dtls_port()
        self.scanner.args["rport"] = dtls_port
        self.port = dtls_port

    def create_conn_obj(self):
        """Create CoAP connection (aiocoap context)."""
        self.logger.info("Connecting via UDP")
        try:
            self.conn = self.scanner.connect()
            if self.conn:
                transport = "CoAPs (DTLS)" if self.scanner._scheme == "coaps" else "CoAP"
                self.logger.success("%s server responding", transport)
            else:
                self.logger.fail("No CoAP response")
        except Exception as e:
            self.logger.fail("Connection error: %s", e)
            self.conn = None

    def enum_host_info(self):
        """Enumerate CoAP device information via discovery."""
        if not self.conn:
            return

        self.logger.debug("Enumerating CoAP resources...")
        confirm = getattr(self.args, "confirm", False)
        try:
            scan_results = self.scanner.discover(self.conn, confirm=confirm)
            self._scan_results = scan_results
            self.results["data"]["scan_results"] = scan_results
        except Exception as e:
            self.logger.warning("Discovery failed: %s", e)
            self._scan_results = {}

    def print_host_info(self):
        """Display discovered CoAP device information."""
        if getattr(self.args, "quiet", False):
            return

        if not self._scan_results:
            return

        # Display DTLS status (only when -D was passed and DTLS is active)
        security = self._scan_results.get("security", {})
        dtls = security.get("dtls_available")
        dtls_port = security.get("dtls_port", self.port)
        if dtls is True:
            self.logger.display("DTLS: server responding on port %d", dtls_port)

        # Display resources
        resources = self._scan_results.get("resources", [])
        if resources:
            self.logger.success("Resources: %d discovered via /.well-known/core", len(resources))
            for res in resources:
                path = res.get("path", "?")
                extras = []
                if res.get("obs"):
                    extras.append("observable")
                if res.get("rt"):
                    extras.append("rt=%s" % res["rt"])
                if res.get("ct") is not None:
                    ct_val = res["ct"]
                    ct_name = CONTENT_FORMATS.get(ct_val, str(ct_val))
                    extras.append("ct=%s" % ct_name)
                suffix = " (%s)" % ", ".join(extras) if extras else ""
                self.logger.display("  %s%s", path, suffix)

        # Display LwM2M info
        lwm2m = self._scan_results.get("lwm2m", {})
        if lwm2m:
            parts = []
            if lwm2m.get("manufacturer"):
                parts.append(lwm2m["manufacturer"])
            if lwm2m.get("model"):
                parts.append(lwm2m["model"])
            fw = lwm2m.get("firmware", "")
            if parts:
                label = " ".join(parts)
                if fw:
                    label += " (FW: %s)" % fw
                self.logger.success("LwM2M Device: %s", label)
            if lwm2m.get("serial"):
                self.logger.display("  Serial: %s", lwm2m["serial"])
        else:
            self.logger.display("LwM2M: not supported")

        # Display security findings
        if security:
            sec_mode = security.get("lwm2m_security_mode")
            if sec_mode:
                self.logger.display("LwM2M Security Mode: %s", sec_mode)

            if security.get("nosec"):
                if dtls:
                    self.logger.security_finding(
                        "NoSec mode (DTLS available)",
                        detail="LwM2M /0/0/2 = NoSec but DTLS responded on port %d -- "
                        "device may not be using DTLS for its LwM2M session" % dtls_port,
                    )
                else:
                    self.logger.security_finding(
                        "NoSec mode",
                        detail="No transport security (LwM2M /0/0/2 = NoSec)",
                    )
                self.logger.security_finding(
                    "No authentication",
                    detail="NoSec mode has no client/server authentication "
                    "(no PSK, RPK, or Certificate configured in LwM2M /0/0/2)",
                )

            unauth = security.get("unauthenticated_writes", [])
            if unauth:
                self.logger.security_finding(
                    "Unauthenticated writes",
                    detail="PUT accepted without auth: %s" % ", ".join(unauth),
                )

    def _execute_features(self):
        """Dispatch additional features based on CLI flags."""
        if not self.conn:
            return

        # Probe paths: bare --probe-paths flag or --probe-paths <wordlist>
        probe_paths = getattr(self.args, "probe_paths", False)
        if probe_paths:
            if isinstance(probe_paths, str):
                # Wordlist file provided
                self.logger.debug("Probing paths from wordlist: %s", probe_paths)
                wordlist_results = self._probe_paths_wordlist(probe_paths)
                if wordlist_results:
                    self.results["data"]["probe_paths"] = wordlist_results
                    self.scanner._resources.extend(wordlist_results)
            else:
                # Bare flag: probe built-in common paths
                self.logger.display("Probing common IoT paths...")
                common_results = self.scanner._probe_common_paths(self.conn)
                if common_results:
                    self.results["data"]["probe_paths"] = common_results
                    self.scanner._resources.extend(common_results)

        # Full LwM2M enumeration
        if getattr(self.args, "lwm2m_full", False):
            self.logger.display("Enumerating all LwM2M objects...")
            objects = self.scanner._enumerate_lwm2m_objects(self.conn)
            self.results["data"]["lwm2m_objects"] = {str(k): v for k, v in objects.items()}
            if objects:
                for obj_id, obj_info in objects.items():
                    name = obj_info.get("name", "Unknown")
                    n_res = len(obj_info.get("resources", {}))
                    self.logger.display("  /%d (%s): %d resources", obj_id, name, n_res)
                    for rname, rval in obj_info.get("resources", {}).items():
                        self.logger.display("    %s: %s", rname, rval)

        # Basic LwM2M (if not already done in discover and explicitly requested)
        elif getattr(self.args, "lwm2m", False):
            if "lwm2m" not in (self._scan_results or {}):
                lwm2m = self.scanner._fingerprint_lwm2m(self.conn)
                self.results["data"]["lwm2m"] = lwm2m

        # Method testing — safe-by-default. GET/FETCH always; write methods
        # (PUT/POST/DELETE/PATCH/IPATCH) require --confirm because DELETE on
        # a live actuator can wipe physical state.
        if getattr(self.args, "methods", False):
            resources = self.scanner._resources
            if resources:
                _confirm = getattr(self.args, "confirm", False)
                if _confirm:
                    self.logger.display("Testing CoAP methods (read + write, --confirm passed)...")
                else:
                    self.logger.display(
                        "Testing CoAP read methods (GET/FETCH). "
                        "Pass --confirm to also probe PUT/POST/DELETE/PATCH/IPATCH."
                    )
                matrix = self.scanner._test_methods(self.conn, resources, confirm=_confirm)
                self.results["data"]["method_matrix"] = matrix
                for path, methods in matrix.items():
                    allowed = [
                        m for m, c in methods.items() if isinstance(c, str) and c.startswith("2.")
                    ]
                    if allowed:
                        self.logger.display("  %s: %s", path, ", ".join(allowed))

        # Observe subscriptions
        if getattr(self.args, "observe", False):
            resources = self.scanner._resources
            count = getattr(self.args, "observe_count", 5) or 5
            self.logger.display(
                "Subscribing to observable resources (max %d notifications)...", count
            )
            obs = self.scanner._observe_resources(self.conn, resources, max_notifications=count)
            self.results["data"]["observations"] = obs
            for notif in obs:
                self.logger.display(
                    "  [%s] seq=%d: %s",
                    notif["path"],
                    notif["seq"],
                    notif["payload"][:80],
                )

        # Write operations (require --confirm)
        confirm = getattr(self.args, "confirm", False)

        put_args = getattr(self.args, "put", None)
        if put_args:
            if not confirm:
                self.logger.fail("--put requires --confirm flag")
            else:
                path, value = put_args
                self._do_write("PUT", path, value)

        post_args = getattr(self.args, "post", None)
        if post_args:
            if not confirm:
                self.logger.fail("--post requires --confirm flag")
            else:
                path, value = post_args
                self._do_write("POST", path, value)

        delete_path = getattr(self.args, "delete", None)
        if delete_path:
            if not confirm:
                self.logger.fail("--delete requires --confirm flag")
            else:
                self._do_write("DELETE", delete_path, "")

        # FETCH (RFC 8132) -- read-only, does not require --confirm
        fetch_args = getattr(self.args, "fetch", None)
        if fetch_args:
            path = fetch_args[0]
            payload = fetch_args[1] if len(fetch_args) > 1 else ""
            self._do_write("FETCH", path, payload)

        # PATCH (RFC 8132) -- requires --confirm
        patch_args = getattr(self.args, "patch", None)
        if patch_args:
            if not confirm:
                self.logger.fail("--patch requires --confirm flag")
            else:
                path, value = patch_args
                self._do_write("PATCH", path, value)

        # iPATCH (RFC 8132) -- requires --confirm
        ipatch_args = getattr(self.args, "ipatch", None)
        if ipatch_args:
            if not confirm:
                self.logger.fail("--ipatch requires --confirm flag")
            else:
                path, value = ipatch_args
                self._do_write("IPATCH", path, value)

    def _try_dtls_cert(self, cert_path, key_path, ca_path):
        """Attempt DTLS connection with certificate authentication."""
        dtls_port = self._resolve_dtls_port()
        timeout = getattr(self.args, "timeout", 5) or 5

        self.logger.info("Trying DTLS certificate authentication")
        ok, ctx, detail = run_async(
            try_dtls_cert(self.host, dtls_port, cert_path, key_path, ca_path, timeout=timeout)
        )

        if ok:
            self.logger.success("DTLS certificate auth success (%s)", detail)
            self.conn = ctx
            self.results["data"]["dtls_cert"] = {
                "cert": cert_path,
                "response": detail,
            }
            return True
        else:
            self.logger.fail("DTLS certificate auth failed: %s", detail)
            return False

    def _try_dtls_rpk(self, rpk_path):
        """Attempt DTLS connection with Raw Public Key authentication."""
        dtls_port = self._resolve_dtls_port()
        timeout = getattr(self.args, "timeout", 5) or 5

        self.logger.info("Trying DTLS RPK authentication")
        ok, ctx, detail = run_async(try_dtls_rpk(self.host, dtls_port, rpk_path, timeout=timeout))

        if ok:
            self.logger.success("DTLS RPK auth success (%s)", detail)
            self.conn = ctx
            self.results["data"]["dtls_rpk"] = {
                "rpk": rpk_path,
                "response": detail,
            }
            return True
        else:
            self.logger.fail("DTLS RPK auth failed: %s", detail)
            return False

    def _bruteforce_dtls_psk(self, psk_arg, psk_id_arg):
        """Attempt DTLS-PSK connection, supporting wordlist bruteforce."""
        from ...utils.default_credentials import parse_credential_input

        # Parse inputs -- auto-detect files
        keys, k_is_file = parse_credential_input(psk_arg) if psk_arg else ([], False)
        identities, i_is_file = parse_credential_input(psk_id_arg) if psk_id_arg else ([], False)

        if k_is_file:
            self.logger.info("Loaded %d PSK keys from wordlist", len(keys))
        if i_is_file:
            self.logger.info("Loaded %d PSK identities from wordlist", len(identities))

        # Default identity if none given
        if not identities:
            identities = [""]

        # Default key if none given (can't do DTLS without a key)
        if not keys:
            self.logger.debug("No PSK key provided, skipping DTLS bruteforce")
            return False

        dtls_port = self._resolve_dtls_port()
        timeout = getattr(self.args, "timeout", 5) or 5

        combinations = [(ident, key) for ident in identities for key in keys]
        total = len(combinations)
        success_count = 0
        fail_count = 0

        if total > 1:
            self.logger.info("Starting DTLS-PSK bruteforce: %d combinations", total)
        else:
            self.logger.info("Trying DTLS-PSK authentication")

        for idx, (identity, key) in enumerate(combinations, 1):
            self.logger.debug("Trying PSK identity=%s key=%s", identity, key)

            if total > 1:
                self.logger.progress(idx, total, success=success_count, failed=fail_count)

            ok, ctx, detail = run_async(
                try_dtls_psk(self.host, dtls_port, identity, key, timeout=timeout)
            )

            if ok:
                success_count += 1
                self.logger.success(
                    "DTLS-PSK success: identity=%s key=%s (%s)",
                    identity,
                    key,
                    detail,
                )
                self.conn = ctx
                self.results["data"]["dtls_psk"] = {
                    "identity": identity,
                    "key": key,
                    "response": detail,
                }
                if total > 1:
                    self.logger.progress(
                        idx, total, success=success_count, failed=fail_count, end="\n"
                    )
                return True
            else:
                fail_count += 1
                self.logger.debug(
                    "DTLS-PSK failed: identity=%s key=%s reason=%s",
                    identity,
                    key,
                    detail,
                )

        if total > 1:
            self.logger.progress(total, total, success=success_count, failed=fail_count, end="\n")
        self.logger.fail("DTLS-PSK bruteforce exhausted: %d/%d failed", fail_count, total)
        return False

    def _probe_paths_wordlist(self, wordlist_path):
        """Probe paths loaded from a wordlist file."""
        from ...utils.default_credentials import parse_credential_input
        from ...utils.login_scanner import format_wordlist_source

        paths, is_file = parse_credential_input(wordlist_path)
        # Use the basename for log output so an engagement-sensitive path
        # like /home/pentester/clients/acme/coap-paths.txt doesn't end up
        # in --json-log or copy-pasted screenshots. Full path stays
        # internal for the actual file open above.
        safe_label = format_wordlist_source(wordlist_path)
        if not is_file:
            self.logger.warning("Wordlist file not found: %s", safe_label)
            return []

        self.logger.info("Loaded %d paths from wordlist: %s", len(paths), safe_label)

        host, port = self.scanner.get_target_info()
        found = []

        for idx, path in enumerate(paths, 1):
            # Ensure path starts with /
            if not path.startswith("/"):
                path = "/" + path

            self.logger.debug("Probing path %d/%d: %s", idx, len(paths), path)
            # Use the scheme established in create_conn_obj — coap:// vs
            # coaps:// — so DTLS-negotiated sessions don't silently downgrade
            # to cleartext UDP/5683 when the wordlist prober ships requests.
            uri = "%s://%s:%s%s" % (self.scanner._scheme, host, port, path)
            result = run_async(coap_request(self.conn, "GET", uri, timeout=self.scanner.timeout))

            code_str = result.get("code", "")
            success = result.get("success", False)

            if success:
                entry = {"path": path, "code": code_str}
                if result.get("payload"):
                    entry["size"] = len(result["payload"])
                found.append(entry)
                self.logger.success("Found resource: %s (%s)", path, code_str)
            else:
                self.logger.debug("Path not found: %s (%s)", path, code_str)

            if len(paths) > 10:
                self.logger.progress(idx, len(paths), success=len(found), failed=idx - len(found))

        if len(paths) > 10:
            self.logger.progress(
                len(paths), len(paths), success=len(found), failed=len(paths) - len(found), end="\n"
            )

        self.logger.info("Path probe complete: %d/%d found", len(found), len(paths))
        return found

    def _resolve_content_format(self):
        """Resolve --content-format arg to a numeric CoAP Content-Format ID."""
        cf_arg = getattr(self.args, "content_format", None)
        if cf_arg is None:
            return None
        # Try numeric ID first
        try:
            cf_id = int(cf_arg)
            if cf_id in CONTENT_FORMATS:
                return cf_id
            self.logger.warning("Unknown Content-Format ID %d, using anyway", cf_id)
            return cf_id
        except ValueError as e:
            self.logger.debug(f"Failed to get cf_id: {e}")
        # Try alias name
        cf_id = CONTENT_FORMAT_ALIASES.get(cf_arg.lower())
        if cf_id is not None:
            return cf_id
        self.logger.fail(
            "Unknown content format '%s'. Use: %s or a numeric ID",
            cf_arg,
            ", ".join(sorted(CONTENT_FORMAT_ALIASES)),
        )
        return None

    @staticmethod
    def _resolve_payload(value: str) -> bytes:
        """Resolve a value string to payload bytes."""
        if not value:
            return b""

        # File reference: @path/to/file (consistent with modbus/dnp3)
        data, _path = resolve_file_payload(value)
        if data is not None:
            return data

        return value.encode("utf-8")

    def _do_write(self, method: str, path: str, value: str):
        """Execute a write/read operation (PUT/POST/DELETE/FETCH/PATCH/IPATCH)."""
        host, port = self.scanner.get_target_info()
        # Use the scheme established in create_conn_obj — coap:// vs coaps:// —
        # so writes against a DTLS-negotiated session don't ship the payload
        # in cleartext over UDP/5683.
        uri = "%s://%s:%s%s" % (self.scanner._scheme, host, port, path)
        payload = self._resolve_payload(value)
        if value and value.startswith("@"):
            self.logger.display("Loaded %d bytes from %s", len(payload), value[1:])
        content_format = self._resolve_content_format()

        if content_format is not None:
            cf_name = CONTENT_FORMATS.get(content_format, content_format)
            self.logger.display("Sending %s to %s (Content-Format: %s)", method, path, cf_name)
        else:
            self.logger.display("Sending %s to %s", method, path)
        result = run_async(
            coap_request(
                self.conn,
                method,
                uri,
                payload=payload,
                timeout=self.scanner.timeout,
                content_format=content_format,
            )
        )
        if result["success"]:
            self.logger.success("%s %s: %s", method, path, result["code"])
        else:
            self.logger.fail("%s %s: %s", method, path, result["code"])

        entry = {
            "method": method,
            "path": path,
            "code": result["code"],
            "success": result["success"],
        }

        # Parse response payload if present
        resp_payload = result.get("payload", b"")
        if resp_payload:
            parsed = parse_payload(resp_payload, content_format=result.get("content_format"))
            entry["response_parsed"] = parsed
            if parsed.get("type") not in ("binary", "empty"):
                self.logger.display("  Response: %s", str(parsed["value"])[:200])

        self.results["data"].setdefault("write_results", []).append(entry)

    def cleanup(self):
        """Cleanup CoAP connection."""
        if self.conn and self.scanner:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("Connection closed")
            except Exception as e:
                self.logger.debug("Error closing connection: %s", e)
            self.conn = None

    @staticmethod
    def check_dependencies() -> bool:
        """Check if CoAP dependencies are available."""
        return _aiocoap.is_available
