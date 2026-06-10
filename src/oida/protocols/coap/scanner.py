"""CoAP protocol scanner implementation.

Provides the CoAPScanner class for scanning CoAP/LwM2M IoT and ICS devices.
"""

import time as _time
from typing import Any, Dict, List

from ...utils import (
    create_protocol_module,
    register_protocol,
    NetworkScanner,
)
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

from .constants import (
    DEFAULT_PORT,
    COMMON_PATHS,
    LWM2M_OBJECTS,
    LWM2M_SEC_MODES,
    WRITE_METHODS,
    protocol_options,
)
from .helpers import (
    _get_aiocoap,
    coap_ping,
    coap_get,
    coap_get_blockwise,
    coap_request,
    create_context,
    shutdown_context,
    parse_link_format,
    parse_payload,
    run_async,
)

logger = get_module_logger(__name__)

_aiocoap = lazy_import("aiocoap", "CoAP")


@register_protocol(
    name="CoAP Scanner",
    description="CoAP IoT/ICS device scanner with LwM2M fingerprinting",
    default_port=DEFAULT_PORT,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://tools.ietf.org/html/rfc7252"},
        {"type": "url", "ref": "https://tools.ietf.org/html/rfc6690"},
    ],
    protocol_options=protocol_options,
)
class CoAPScanner(NetworkScanner):
    """Scanner for CoAP (Constrained Application Protocol) devices.

    Supports resource discovery via /.well-known/core, LwM2M device
    fingerprinting, method testing, observe subscriptions, and
    basic security assessment (NoSec, DTLS availability).
    """

    def __init__(self, args: Dict[str, Any]):
        self._ctx = None
        self._resources: List[Dict[str, Any]] = []
        self._block_size: int = args.get("block_size", 512)
        self._scheme: str = "coaps" if args.get("dtls") else "coap"
        super().__init__(args)

    def get_protocol_name(self) -> str:
        return "CoAP"

    def get_default_port(self) -> int:
        return DEFAULT_PORT

    def check_dependencies(self) -> bool:
        return _aiocoap.is_available

    def connect(self) -> Any:
        """Ping the CoAP endpoint, then create an aiocoap client context.

        Returns the aiocoap context on success, None if the target is unreachable.
        """
        host, port = self.get_target_info()
        timeout = self.timeout

        self.logger.debug("Connecting to %s:%d (timeout=%ds)", host, port, timeout)
        t0 = _time.monotonic()

        alive = coap_ping(host, port, timeout=timeout)
        ping_elapsed = _time.monotonic() - t0
        self.logger.debug(
            "CoAP ping to %s:%d took %.2fs, alive=%s", host, port, ping_elapsed, alive
        )

        if not alive:
            self.logger.debug(
                "CoAP ping got no response from %s:%s, trying GET fallback", host, port
            )
            # Try a real GET as fallback — some devices ignore empty CON
            try:
                ctx = run_async(create_context())
                uri = f"{self._scheme}://{host}:{port}/.well-known/core"
                code, _ = run_async(coap_get(ctx, uri, timeout=timeout))
                self.logger.debug("Fallback GET to %s returned %s", uri, code)
                if code.startswith("2.") or code.startswith("4."):
                    # Got a real CoAP response — server is alive
                    self._ctx = ctx
                    elapsed = _time.monotonic() - t0
                    self.logger.debug("Connection established via GET fallback in %.2fs", elapsed)
                    return ctx
                # No usable response — shut down and fail
                run_async(shutdown_context(ctx))
            except Exception as e:
                self.logger.debug("Fallback GET failed: %s", e)
            self.logger.debug("Connection failed after %.2fs", _time.monotonic() - t0)
            return None

        ctx = run_async(create_context())
        self._ctx = ctx
        elapsed = _time.monotonic() - t0
        self.logger.debug("aiocoap context created in %.2fs", elapsed)
        return ctx

    def disconnect(self, connection: Any) -> None:
        """Shutdown the aiocoap context."""
        self.logger.debug("Disconnecting aiocoap context")
        if connection is not None:
            run_async(shutdown_context(connection))
        self._ctx = None
        self.logger.debug("Disconnected")

    # ------------------------------------------------------------------
    # Discovery orchestration
    # ------------------------------------------------------------------

    def discover(self, connection: Any, confirm: bool = False) -> Dict[str, Any]:
        """Orchestrate resource discovery, LwM2M fingerprinting, and security checks.

        Args:
            connection: aiocoap client context.
            confirm: If True, enables write probes in security checks.
        """
        results: Dict[str, Any] = {}
        t0 = _time.monotonic()

        # 1. Resource discovery via /.well-known/core only.
        # Common-path probing is opt-in via --probe-paths to keep default scans fast.
        self.logger.debug("Phase 1: Resource discovery via /.well-known/core")
        resources = self._discover_resources(connection)
        self._resources = resources
        results["resources"] = resources
        self.logger.debug(
            "Discovery found %d resources in %.2fs", len(resources), _time.monotonic() - t0
        )

        # 2. LwM2M fingerprinting
        t1 = _time.monotonic()
        self.logger.debug("Phase 2: LwM2M fingerprinting")
        lwm2m = self._fingerprint_lwm2m(connection)
        if lwm2m:
            results["lwm2m"] = lwm2m
        self.logger.debug(
            "LwM2M fingerprinting took %.2fs, found %d fields", _time.monotonic() - t1, len(lwm2m)
        )

        # 3. Security assessment (write probes gated behind confirm)
        t2 = _time.monotonic()
        self.logger.debug("Phase 3: Security assessment (confirm=%s)", confirm)
        security = self._check_security(connection, resources, confirm=confirm)
        if security:
            results["security"] = security
        self.logger.debug("Security check took %.2fs", _time.monotonic() - t2)

        total = _time.monotonic() - t0
        self.logger.debug("Full discovery completed in %.2fs", total)
        return results

    # ------------------------------------------------------------------
    # Resource discovery
    # ------------------------------------------------------------------

    def _discover_resources(self, ctx) -> List[Dict[str, Any]]:
        """GET /.well-known/core and parse CoRE Link Format.

        Uses block-wise transfer (RFC 7959) when the response indicates
        that the payload is larger than a single block.
        """
        host, port = self.get_target_info()
        uri = f"{self._scheme}://{host}:{port}/.well-known/core"
        block_size = getattr(self, "_block_size", 512)

        self.logger.debug("GET %s", uri)
        code, payload = run_async(coap_get(ctx, uri, timeout=self.timeout))

        # If the server returns 4.13 (Request Entity Too Large) or the
        # response has a block2 option, retry with explicit block-wise GET
        if code == "4.13" or (code.startswith("2.") and len(payload) >= block_size):
            self.logger.debug(
                "Retrying /.well-known/core with block-wise GET (block_size=%d)", block_size
            )
            code, payload = run_async(
                coap_get_blockwise(ctx, uri, block_size=block_size, timeout=self.timeout)
            )

        if not code.startswith("2."):
            self.logger.debug("/.well-known/core returned %s", code)
            return []

        self.logger.debug("/.well-known/core payload: %d bytes", len(payload))
        text = payload.decode("utf-8", errors="replace")
        resources = parse_link_format(text)
        self.logger.info("Discovered %d resources via /.well-known/core", len(resources))
        for res in resources:
            self.logger.debug("  Resource: %s (obs=%s)", res.get("path"), res.get("obs", False))
        return resources

    def _probe_common_paths(self, ctx) -> List[Dict[str, Any]]:
        """Probe COMMON_PATHS when .well-known/core yields nothing."""
        host, port = self.get_target_info()
        found: List[Dict[str, Any]] = []

        self.logger.debug("Probing %d common IoT paths", len(COMMON_PATHS))
        for idx, path in enumerate(COMMON_PATHS, 1):
            uri = f"{self._scheme}://{host}:{port}{path}"
            self.logger.debug("Probing path %d/%d: %s", idx, len(COMMON_PATHS), path)
            result = run_async(coap_request(ctx, "GET", uri, timeout=self.timeout))
            code = result["code"]
            if code.startswith("2."):
                entry: Dict[str, Any] = {"path": path}
                payload = result.get("payload", b"")
                if payload:
                    entry["size"] = len(payload)
                    parsed = parse_payload(payload, content_format=result.get("content_format"))
                    entry["parsed"] = parsed
                found.append(entry)
                self.logger.info("Found resource: %s (%s)", path, code)
            else:
                self.logger.debug("Path not found: %s (%s)", path, code)

        self.logger.debug("Common path probe: %d/%d found", len(found), len(COMMON_PATHS))
        return found

    # ------------------------------------------------------------------
    # LwM2M fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint_lwm2m(self, ctx) -> Dict[str, Any]:
        """Probe LwM2M Device Object /3/0 for manufacturer/model/serial/firmware."""
        host, port = self.get_target_info()
        info: Dict[str, Any] = {}

        resource_map = {0: "manufacturer", 1: "model", 2: "serial", 3: "firmware"}
        self.logger.debug("Probing LwM2M Device Object /3/0 (%d resources)", len(resource_map))
        for rid, label in resource_map.items():
            uri = f"{self._scheme}://{host}:{port}/3/0/{rid}"
            self.logger.debug("GET %s (%s)", uri, label)
            code, payload = run_async(coap_get(ctx, uri, timeout=self.timeout))
            if code.startswith("2.") and payload:
                value = payload.decode("utf-8", errors="replace").strip()
                if value:
                    info[label] = value
                    self.logger.info("LwM2M Device /3/0/%d (%s): %s", rid, label, value)
            else:
                self.logger.debug("LwM2M /3/0/%d (%s): %s", rid, label, code)

        return info

    def _enumerate_lwm2m_objects(self, ctx) -> Dict[int, Dict[str, Any]]:
        """Scan all object IDs from LWM2M_OBJECTS to find accessible ones."""
        host, port = self.get_target_info()
        found: Dict[int, Dict[str, Any]] = {}

        self.logger.debug("Enumerating %d LwM2M object types", len(LWM2M_OBJECTS))
        for obj_id, obj_def in LWM2M_OBJECTS.items():
            uri = f"{self._scheme}://{host}:{port}/{obj_id}/0"
            self.logger.debug("Probing LwM2M object /%d (%s)", obj_id, obj_def["name"])
            code, payload = run_async(coap_get(ctx, uri, timeout=self.timeout))
            if code.startswith("2."):
                obj_info: Dict[str, Any] = {
                    "name": obj_def["name"],
                    "accessible": True,
                }
                # Try to read individual resources
                resources_read: Dict[str, str] = {}
                for rid, rname in obj_def.get("resources", {}).items():
                    ruri = f"{self._scheme}://{host}:{port}/{obj_id}/0/{rid}"
                    rcode, rpayload = run_async(coap_get(ctx, ruri, timeout=self.timeout))
                    if rcode.startswith("2.") and rpayload:
                        value = rpayload.decode("utf-8", errors="replace").strip()
                        resources_read[rname] = value

                if resources_read:
                    obj_info["resources"] = resources_read
                found[obj_id] = obj_info
                self.logger.info(
                    "LwM2M Object /%d (%s): %d resources readable",
                    obj_id,
                    obj_def["name"],
                    len(resources_read),
                )
            elif code != "4.04" and not code.startswith("error") and code != "timeout":
                self.logger.debug("LwM2M Object /%d: %s", obj_id, code)

        return found

    # ------------------------------------------------------------------
    # Method testing
    # ------------------------------------------------------------------

    def _test_methods(
        self, ctx, resources: List[Dict[str, Any]], confirm: bool = False
    ) -> Dict[str, Dict[str, str]]:
        """Build an access matrix by probing CoAP methods per resource.

        Always tests the read-only methods (GET / FETCH / OBSERVE).
        Tests the write methods (PUT / POST / DELETE / PATCH / IPATCH)
        only when ``confirm`` is True — DELETE on a live actuator can
        wipe physical state, so unattended scans must stop at reads.

        When ``confirm`` is False the matrix entries for write methods
        carry the string "not-tested-without-confirm" so the operator
        can see what was skipped.
        """
        host, port = self.get_target_info()
        matrix: Dict[str, Dict[str, str]] = {}
        read_methods = ["GET", "FETCH"]
        write_methods = ["PUT", "POST", "DELETE", "PATCH", "IPATCH"]
        active_methods = read_methods + (write_methods if confirm else [])

        self.logger.debug(
            "Testing %d methods on %d resources (confirm=%s)",
            len(active_methods),
            len(resources),
            confirm,
        )
        for res in resources:
            path = res.get("path", "")
            if not path:
                continue
            uri = f"{self._scheme}://{host}:{port}{path}"
            path_results: Dict[str, str] = {}

            for method in active_methods:
                if method in WRITE_METHODS:
                    # Empty payload for write probes
                    result = run_async(
                        coap_request(ctx, method, uri, payload=b"", timeout=self.timeout)
                    )
                else:
                    result = run_async(coap_request(ctx, method, uri, timeout=self.timeout))
                path_results[method] = result["code"]

            if not confirm:
                for m in write_methods:
                    path_results[m] = "not-tested-without-confirm"

            matrix[path] = path_results
            self.logger.debug("Method test %s: %s", path, path_results)

        return matrix

    # ------------------------------------------------------------------
    # Security assessment
    # ------------------------------------------------------------------

    def _check_security(
        self, ctx, resources: List[Dict[str, Any]], confirm: bool = False
    ) -> Dict[str, Any]:
        """Check for NoSec mode, unauthenticated writes, and DTLS availability.

        Write probes (PUT to actuators) are only sent when *confirm* is True.
        """
        host, port = self.get_target_info()
        findings: Dict[str, Any] = {}

        # DTLS: simply reflect whether we're using coaps:// scheme
        findings["dtls_available"] = self._scheme == "coaps"
        findings["dtls_port"] = port

        # Check LwM2M Security Object /0/0/2 for security mode
        uri = f"{self._scheme}://{host}:{port}/0/0/2"
        code, payload = run_async(coap_get(ctx, uri, timeout=self.timeout))
        if code.startswith("2.") and payload:
            try:
                mode_val = int(payload.decode("utf-8", errors="replace").strip())
                mode_name = LWM2M_SEC_MODES.get(mode_val, f"Unknown({mode_val})")
                findings["lwm2m_security_mode"] = mode_name
                self.logger.info("LwM2M Security Mode: %s", mode_name)
                if mode_val == 3:
                    findings["nosec"] = True
            except (ValueError, UnicodeDecodeError) as e:
                self.logger.debug(f"Failed to get mode_val: {e}")

        # Probe for unauthenticated write — only with --confirm (sends actual PUT)
        if confirm:
            writable_candidates = [
                r["path"] for r in resources if r.get("path", "").startswith("/actuator")
            ]
            if not writable_candidates:
                writable_candidates = [r["path"] for r in resources if r.get("path")][:1]

            self.logger.debug(
                "Testing unauthenticated writes on %d candidates", len(writable_candidates[:3])
            )
            unauth_writes: List[str] = []
            for path in writable_candidates[:3]:
                uri = f"{self._scheme}://{host}:{port}{path}"
                self.logger.debug("PUT %s (unauthenticated write test)", uri)
                result = run_async(
                    coap_request(ctx, "PUT", uri, payload=b"1", timeout=self.timeout)
                )
                if result["success"]:
                    unauth_writes.append(path)
                    self.logger.debug("Unauthenticated write succeeded: %s", path)
                else:
                    self.logger.debug("Unauthenticated write denied: %s (%s)", path, result["code"])

            if unauth_writes:
                findings["unauthenticated_writes"] = unauth_writes
        else:
            self.logger.debug("Skipping write probes (--confirm not set)")

        return findings

    # ------------------------------------------------------------------
    # Observe (subscribe to notifications)
    # ------------------------------------------------------------------

    def _observe_resources(
        self, ctx, resources: List[Dict[str, Any]], max_notifications: int = 5
    ) -> List[Dict[str, Any]]:
        """Subscribe to observable resources and collect notifications."""
        import asyncio

        host, port = self.get_target_info()
        observable = [r for r in resources if r.get("obs")]
        self.logger.debug(
            "Observe: %d/%d resources are observable (max_notifications=%d)",
            len(observable),
            len(resources),
            max_notifications,
        )
        if not observable:
            self.logger.info("No observable resources found")
            return []

        observations: List[Dict[str, Any]] = []

        async def _observe_one(path: str):
            aiocoap = _get_aiocoap()
            uri = f"{self._scheme}://{host}:{port}{path}"
            request = aiocoap.Message(code=aiocoap.GET, uri=uri, observe=0)
            collected: List[Dict[str, Any]] = []
            try:
                pr = ctx.request(request)
                resp = await asyncio.wait_for(pr.response, timeout=self.timeout)
                if not str(resp.code).startswith("2."):
                    return collected

                collected.append(
                    {
                        "path": path,
                        "seq": 0,
                        "code": str(resp.code),
                        "payload": resp.payload.decode("utf-8", errors="replace"),
                    }
                )

                for i in range(1, max_notifications):
                    try:
                        resp = await asyncio.wait_for(
                            pr.observation.__aiter__().__anext__(), timeout=self.timeout
                        )
                        collected.append(
                            {
                                "path": path,
                                "seq": i,
                                "code": str(resp.code),
                                "payload": resp.payload.decode("utf-8", errors="replace"),
                            }
                        )
                    except (asyncio.TimeoutError, StopAsyncIteration):
                        break

                # Cancel observation
                pr.observation.cancel()
            except (asyncio.TimeoutError, Exception) as e:
                self.logger.debug("Observe %s failed: %s", path, e)

            return collected

        for res in observable:
            path = res.get("path", "")
            if not path:
                continue
            notifs = run_async(_observe_one(path))
            if notifs:
                observations.extend(notifs)
                self.logger.info("Observed %d notifications from %s", len(notifs), path)

        return observations


# Module-level exports
metadata, run = create_protocol_module(CoAPScanner, lambda: not _aiocoap.is_available)
