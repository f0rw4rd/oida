"""CoAP lazy imports and utility functions.

Centralizes lazy imports and provides async wrappers, CoRE link-format
parsing, and the sync/async bridge used by the scanner.
"""

import asyncio
import importlib
import inspect
import json
import re
import socket
import threading
from typing import Any, Dict, List, Optional, Tuple

from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import
from .constants import BLOCK_SIZES, DEFAULT_TIMEOUT

logger = get_module_logger(__name__)

_aiocoap = lazy_import("aiocoap", "CoAP")
_cbor2 = lazy_import("cbor2", "CoAP", install_hint="pip install oida-ics[coap]")


def is_aiocoap_available() -> bool:
    """Check if aiocoap is installed."""
    return _aiocoap.is_available


def _get_aiocoap():
    """Return the aiocoap module, loading it once via the lazy_import proxy.

    Use this instead of ``import aiocoap`` inside every function so that the
    module is resolved through the project's lazy_import() mechanism and
    cached after the first call.
    """
    return _aiocoap()


class _EventLoopHolder:
    """Thread-local holder for the persistent asyncio event loop.

    CoAP scans run under a ThreadPoolExecutor, so each worker thread
    needs its own loop: a single shared loop would raise "This event
    loop is already running" and corrupt aiocoap context state when two
    threads call ``run_until_complete`` concurrently. ``threading.local``
    gives every thread an isolated loop that persists across calls so
    aiocoap contexts created on that thread stay valid.
    """

    _local = threading.local()

    @classmethod
    def get(cls) -> asyncio.AbstractEventLoop:
        loop = getattr(cls._local, "loop", None)
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            cls._local.loop = loop
        return loop


def run_async(coro):
    """Run an async coroutine from synchronous code.

    Reuses a per-thread persistent event loop so that aiocoap contexts
    remain valid across calls within a thread while concurrent scan
    threads never share (and thus never collide on) a loop.
    """
    return _EventLoopHolder.get().run_until_complete(coro)


async def create_context():
    """Create an aiocoap client Context."""
    aiocoap = _get_aiocoap()
    return await aiocoap.Context.create_client_context()


async def shutdown_context(ctx):
    """Shut down an aiocoap Context."""
    if ctx is not None:
        await ctx.shutdown()


def coap_ping(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Send an empty CON message to test CoAP responsiveness over cleartext UDP.

    Uses raw UDP to avoid aiocoap overhead for a simple plaintext ping.
    This cannot probe a DTLS endpoint (no handshake), so callers must
    skip it for coaps:// scans and use a scheme-aware probe instead.
    """
    # CoAP empty CON: Ver=1, Type=CON(0), TKL=0, Code=0.00, MID=0x0001
    ping_msg = b"\x40\x00\x00\x01"
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(ping_msg, (host, port))
        data, _ = sock.recvfrom(64)
        if len(data) < 4:
            return False
        # Validate this is actually a CoAP reply to OUR ping, not arbitrary
        # UDP noise: version must be 1 (top 2 bits of byte 0) and the
        # message ID must echo the one we sent (bytes 2-3). A garbage or
        # wrong-protocol UDP responder that merely echoes bytes back must
        # not be mistaken for "CoAP server responding".
        version_ok = (data[0] >> 6) == 1
        mid_ok = data[2:4] == ping_msg[2:4]
        return version_ok and mid_ok
    except OSError as e:
        logger.debug(f"CoAP ping socket send/recv failed: {e}")
        return False
    finally:
        if sock:
            try:
                sock.close()
            except OSError as e:
                logger.debug(f"sock.close(): {e}")


async def coap_get(ctx, uri: str, timeout: float = DEFAULT_TIMEOUT) -> Tuple[str, bytes]:
    """GET a CoAP resource.

    Returns (response_code_string, payload_bytes).
    On error returns (error_string, b"").
    """
    aiocoap = _get_aiocoap()
    try:
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        code_str = str(response.code)
        return code_str, response.payload
    except asyncio.TimeoutError as e:
        logger.debug(f"Failed to get request: {e}")
        return "timeout", b""
    except Exception as e:
        logger.debug("coap_get %s failed: %s", uri, e)
        return f"error:{e}", b""


async def coap_get_checked(
    ctx, uri: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[str, bytes, bool]:
    """GET a CoAP resource, also reporting whether it is a truncated block-wise transfer.

    aiocoap's default ``ctx.request()`` already negotiates and reassembles
    Block2 (RFC 7959) transfers transparently, so by the time this returns
    the payload is normally already complete and ``response.opt.block2`` is
    cleared. This still checks the option explicitly (rather than inferring
    truncation from payload size, which false-positives on any legitimately
    large single response >= the configured block size) so callers can
    decide whether an additional explicit block-wise GET is actually
    warranted.

    Returns (response_code_string, payload_bytes, block2_more).
    On error returns (error_string, b"", False).
    """
    aiocoap = _get_aiocoap()
    try:
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        code_str = str(response.code)
        block2 = getattr(response.opt, "block2", None)
        more = bool(block2 is not None and block2.more)
        return code_str, response.payload, more
    except asyncio.TimeoutError as e:
        logger.debug(f"Failed to get request: {e}")
        return "timeout", b"", False
    except Exception as e:
        logger.debug("coap_get_checked %s failed: %s", uri, e)
        return f"error:{e}", b"", False


_method_map_cache: Dict[str, Dict[str, Any]] = {}


def _get_method_map() -> Dict[str, Any]:
    """Return the CoAP method code map, built once and cached."""
    if "map" in _method_map_cache:
        return _method_map_cache["map"]
    aiocoap = _get_aiocoap()
    m: Dict[str, Any] = {
        "GET": aiocoap.GET,
        "POST": aiocoap.POST,
        "PUT": aiocoap.PUT,
        "DELETE": aiocoap.DELETE,
    }
    # Extended methods (RFC 8132)
    if hasattr(aiocoap, "FETCH"):
        m["FETCH"] = aiocoap.FETCH
    if hasattr(aiocoap, "PATCH"):
        m["PATCH"] = aiocoap.PATCH
    ipatch = getattr(aiocoap, "iPATCH", None) or getattr(aiocoap.numbers.codes.Code, "iPATCH", None)
    if ipatch is not None:
        m["IPATCH"] = ipatch
    _method_map_cache["map"] = m
    return m


async def coap_request(
    ctx,
    method: str,
    uri: str,
    payload: bytes = b"",
    timeout: float = DEFAULT_TIMEOUT,
    content_format: Optional[int] = None,
) -> Dict[str, Any]:
    """Generic CoAP request.

    Returns dict with keys: code, payload, content_format, success.
    """
    aiocoap = _get_aiocoap()
    method_map = _get_method_map()
    code = method_map.get(method.upper())
    if code is None:
        return {"code": "unsupported", "payload": b"", "success": False}

    try:
        request = aiocoap.Message(code=code, uri=uri, payload=payload)
        if content_format is not None:
            request.opt.content_format = content_format
        response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        code_str = str(response.code)
        cf = getattr(response.opt, "content_format", None)
        return {
            "code": code_str,
            "payload": response.payload,
            "content_format": cf,
            "success": code_str.startswith("2."),
        }
    except asyncio.TimeoutError as e:
        logger.debug(f"Failed to get request: {e}")
        return {"code": "timeout", "payload": b"", "success": False}
    except Exception as e:
        logger.debug("coap_request %s %s failed: %s", method, uri, e)
        return {"code": f"error:{e}", "payload": b"", "success": False}


def parse_link_format(payload: str) -> List[Dict[str, Any]]:
    """Parse RFC 6690 CoRE Link Format from /.well-known/core.

    Input example:
        </sensor/temperature>;obs;rt="temperature";ct=0,
        </actuator/led>;rt="led";if="actuator"

    Returns list of dicts with keys: path, obs, rt, if, ct, title, sz, etc.
    """
    resources = []
    if not payload or not payload.strip():
        return resources

    # Split on commas that separate entries (outside quoted attribute values).
    # A comma only starts a new entry when it is immediately followed by '<'
    # and we are not currently inside a quoted string.
    entries = []
    start = 0
    in_quotes = False
    text = payload.strip()
    for i, ch in enumerate(text):
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes and text[i + 1 : i + 2] == "<":
            entries.append(text[start:i])
            start = i + 1
    entries.append(text[start:])
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue

        resource: Dict[str, Any] = {}

        # Extract path from <path>
        path_match = re.match(r"<([^>]+)>", entry)
        if not path_match:
            continue
        resource["path"] = path_match.group(1)

        # Parse attributes after the path
        attrs_str = entry[path_match.end() :]
        # Obs flag (no value)
        if ";obs" in attrs_str.lower():
            resource["obs"] = True

        # Key-value attributes: ;key="value" (quoted-string, may contain ; or ,)
        # or ;key=value (bare token, stops at the next ;)
        for attr_match in re.finditer(r';(\w+)(?:="([^"]*)"|=([^";]*))?', attrs_str):
            key = attr_match.group(1).lower()
            value = attr_match.group(2) if attr_match.group(2) is not None else attr_match.group(3)
            if key == "obs":
                resource["obs"] = True
            elif key == "ct":
                try:
                    resource["ct"] = int(value) if value else 0
                except (ValueError, TypeError):
                    resource["ct"] = value
            elif key == "sz":
                try:
                    resource["sz"] = int(value) if value else 0
                except (ValueError, TypeError):
                    resource["sz"] = value
            elif value is not None:
                resource[key] = value

        resources.append(resource)

    return resources


MAX_BLOCKWISE_PAYLOAD = 64 * 1024 * 1024  # 64 MiB OOM ceiling
MAX_BLOCKWISE_BLOCKS = 65536  # NUM is 23-bit per RFC 7959 but cap before that


async def coap_get_blockwise(
    ctx,
    uri: str,
    block_size: int = 512,
    timeout: float = DEFAULT_TIMEOUT,
    max_payload: int = MAX_BLOCKWISE_PAYLOAD,
) -> Tuple[str, bytes]:
    """GET a CoAP resource with Block2 reassembly (RFC 7959).

    Handles large payloads that exceed a single CoAP datagram by
    iterating over Block2 option responses until the transfer is
    complete.

    aiocoap may handle block-wise automatically for simple cases,
    but this explicit implementation gives us logging visibility and
    control over the block size.

    Hard caps the assembled payload at `max_payload` bytes
    (default 64 MiB) so a hostile server that keeps setting M=1
    indefinitely can't drive the scanner to OOM.

    Returns (response_code_string, reassembled_payload_bytes).
    """
    aiocoap = _get_aiocoap()

    szx = BLOCK_SIZES.get(block_size, 5)  # default SZX=5 (512 bytes)
    assembled = bytearray()
    block_num = 0
    # Local loop counter, independent of the server-controlled block number.
    # A hostile server that keeps replying block_number=0/more=True/empty
    # payload would otherwise pin block_num at 1 forever (neither the block-count
    # nor the payload-size guard trips), hanging the scan thread indefinitely.
    iterations = 0

    logger.debug("Block2 GET %s (block_size=%d, szx=%d)", uri, block_size, szx)

    while True:
        if iterations >= MAX_BLOCKWISE_BLOCKS:
            logger.warning(
                "Block2 GET aborted: exceeded %d iterations without completing",
                MAX_BLOCKWISE_BLOCKS,
            )
            return "aborted:too-many-blocks", bytes(assembled)
        iterations += 1
        prev_block_num = block_num
        prev_assembled_len = len(assembled)
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        # Set Block2 option: NUM=block_num, M=0 (we're requesting), SZX=szx
        request.opt.block2 = aiocoap.optiontypes.BlockOption.BlockwiseTuple(block_num, False, szx)

        try:
            response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        except asyncio.TimeoutError:
            logger.debug("Block2 GET timeout at block %d", block_num)
            return "timeout", bytes(assembled)
        except Exception as e:
            logger.debug("Block2 GET error at block %d: %s", block_num, e)
            return f"error:{e}", bytes(assembled)

        code_str = str(response.code)
        if not code_str.startswith("2."):
            logger.debug("Block2 GET non-success at block %d: %s", block_num, code_str)
            return code_str, bytes(assembled)

        assembled.extend(response.payload)
        logger.debug(
            "Block2 block %d: %d bytes (total %d)",
            block_num,
            len(response.payload),
            len(assembled),
        )

        if len(assembled) > max_payload:
            logger.warning(
                "Block2 GET aborted: assembled payload exceeded %d bytes (cap=%d, latest block=%d)",
                len(assembled),
                max_payload,
                block_num,
            )
            return "aborted:payload-too-large", bytes(assembled[:max_payload])
        if block_num >= MAX_BLOCKWISE_BLOCKS:
            logger.warning("Block2 GET aborted: block count exceeded %d", MAX_BLOCKWISE_BLOCKS)
            return "aborted:too-many-blocks", bytes(assembled)

        block2 = response.opt.block2
        if block2 is None or not block2.more:
            # No more blocks
            break

        block_num = block2.block_number + 1
        szx = block2.size_exponent  # Server may negotiate a different SZX

        # Bail if the server advanced neither the block number nor the payload:
        # a well-behaved server always moves at least one of them forward, so
        # standing still means it is stalling us (self-DoS guard).
        if block_num <= prev_block_num and len(assembled) == prev_assembled_len:
            logger.warning(
                "Block2 GET aborted: server made no progress at block %d (no new payload)",
                prev_block_num,
            )
            return "aborted:no-progress", bytes(assembled)

    logger.debug("Block2 GET complete: %d bytes total", len(assembled))
    return code_str, bytes(assembled)


async def try_dtls_psk(
    host: str,
    port: int,
    identity: str,
    psk_key: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[bool, Optional[Any], str]:
    """Attempt a CoAP DTLS-PSK connection with given credentials.

    Creates an aiocoap DTLS context with the provided PSK identity/key
    and tries to GET /.well-known/core. Returns (success, context, detail).

    On success the context is returned open (caller must shut it down).
    On failure the context is closed and None is returned.
    """
    ctx = None
    try:
        aiocoap = _get_aiocoap()
        aiocoap_creds = importlib.import_module("aiocoap.credentials")

        # Build credentials map for aiocoap's DTLS-PSK support
        client_creds = aiocoap_creds.CredentialsMap()

        # Encode PSK key as bytes (hex string or raw)
        try:
            psk_bytes = bytes.fromhex(psk_key)
        except ValueError:
            psk_bytes = psk_key.encode("utf-8")

        # Register PSK for the target host
        target_uri = f"coaps://{host}:{port}/*"
        client_creds[target_uri] = aiocoap_creds.DTLS(
            psk=psk_bytes,
            client_identity=identity.encode("utf-8") if identity else b"",
        )

        ctx = await aiocoap.Context.create_client_context()
        ctx.client_credentials = client_creds

        # Try a GET to verify the connection works
        uri = f"coaps://{host}:{port}/.well-known/core"
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        code_str = str(response.code)

        if code_str.startswith("2.") or code_str.startswith("4."):
            # Got a real CoAP response — DTLS handshake succeeded
            return True, ctx, code_str

        # Unexpected response code — close and report
        await ctx.shutdown()
        return False, None, f"unexpected response: {code_str}"

    except asyncio.TimeoutError:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-PSK cleanup error after timeout: %s", exc)
        return False, None, "timeout"
    except Exception as e:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-PSK cleanup error: %s", exc)
        return False, None, str(e)


def _dtls_supports_kwargs(aiocoap_creds: Any, *kwargs: str) -> bool:
    """Return True if aiocoap's DTLS credential accepts all of ``kwargs``.

    The pinned aiocoap DTLS credential only takes ``psk`` / ``client_identity``
    (PSK mode); certificate and RPK kwargs are rejected. We inspect the
    constructor signature so callers can detect an unsupported auth mode before
    touching the filesystem, rather than masking it behind a later error.
    """
    dtls_cls = getattr(aiocoap_creds, "DTLS", None)
    if dtls_cls is None:
        return False
    try:
        params = inspect.signature(dtls_cls.__init__).parameters
    except (TypeError, ValueError):
        # Signature not introspectable -- fall back to attempting the call.
        try:
            dtls_cls(**{k: b"" for k in kwargs})
            return True
        except TypeError:
            return False
        except Exception:
            return True
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return True
    return all(k in params for k in kwargs)


async def try_dtls_cert(
    host: str,
    port: int,
    cert_path: str,
    key_path: str,
    ca_path: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[bool, Optional[Any], str]:
    """Attempt a CoAP DTLS connection with certificate-based authentication.

    Creates an aiocoap DTLS context using X.509 certificates and tries to
    GET /.well-known/core. Returns (success, context, detail).

    On success the context is returned open (caller must shut it down).
    On failure the context is closed and None is returned.

    Note: Certificate-based DTLS requires a DTLS backend that supports it
    (e.g. the OpenSSL-based tinydtls or python-dtls). If the installed
    aiocoap backend does not support certificates, this will fail with a
    descriptive error message.
    """
    ctx = None
    try:
        aiocoap = _get_aiocoap()
        aiocoap_creds = importlib.import_module("aiocoap.credentials")

        client_creds = aiocoap_creds.CredentialsMap()
        target_uri = f"coaps://{host}:{port}/*"

        # aiocoap supports certificate DTLS via the DTLS credential type
        # with client_cert / server_cert parameters (backend-dependent).
        if not hasattr(aiocoap_creds, "DTLS"):
            return False, None, "aiocoap credentials module missing DTLS class"

        # Probe whether the installed DTLS credential even accepts certificate
        # kwargs BEFORE touching the filesystem. The pinned aiocoap DTLS
        # credential (tinydtls backend) only supports PSK, so cert auth is
        # not supported -- report that honestly instead of failing later on a
        # missing file and masking the real reason.
        if not _dtls_supports_kwargs(aiocoap_creds, "client_cert", "private_key"):
            return (
                False,
                None,
                (
                    "certificate authentication is not supported by the installed "
                    "aiocoap DTLS backend (likely tinydtls), which only supports PSK "
                    "mode. Certificate auth requires an OpenSSL-based DTLS backend."
                ),
            )

        # Read cert and key files now that we know cert auth is usable.
        cred_kwargs = {}
        with open(cert_path, "rb") as f:
            cred_kwargs["client_cert"] = f.read()
        with open(key_path, "rb") as f:
            cred_kwargs["private_key"] = f.read()
        if ca_path:
            with open(ca_path, "rb") as f:
                cred_kwargs["ca_certs"] = f.read()

        client_creds[target_uri] = aiocoap_creds.DTLS(**cred_kwargs)

        ctx = await aiocoap.Context.create_client_context()
        ctx.client_credentials = client_creds

        uri = f"coaps://{host}:{port}/.well-known/core"
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        code_str = str(response.code)

        if code_str.startswith("2.") or code_str.startswith("4."):
            return True, ctx, code_str

        await ctx.shutdown()
        return False, None, f"unexpected response: {code_str}"

    except FileNotFoundError as e:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-cert cleanup error after FileNotFoundError: %s", exc)
        return False, None, f"certificate file not found: {e}"
    except asyncio.TimeoutError:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-cert cleanup error after timeout: %s", exc)
        return False, None, "timeout"
    except Exception as e:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-cert cleanup error: %s", exc)
        return False, None, str(e)


async def try_dtls_rpk(
    host: str,
    port: int,
    rpk_path: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[bool, Optional[Any], str]:
    """Attempt a CoAP DTLS connection with Raw Public Key (RPK) authentication.

    RPK (RFC 7250) uses raw public keys instead of X.509 certificates,
    reducing overhead for constrained devices.

    Note: RPK support depends on the aiocoap DTLS backend. Most backends
    (tinydtls, mbedtls) have limited or no RPK support. This function
    will return a descriptive error if RPK is not supported.

    Returns (success, context, detail).
    """
    ctx = None
    try:
        aiocoap = _get_aiocoap()
        aiocoap_creds = importlib.import_module("aiocoap.credentials")

        client_creds = aiocoap_creds.CredentialsMap()
        target_uri = f"coaps://{host}:{port}/*"

        # Probe RPK support BEFORE reading the key file so an unsupported
        # backend is reported honestly rather than masked by a missing file.
        if not hasattr(aiocoap_creds, "DTLS") or not _dtls_supports_kwargs(
            aiocoap_creds, "raw_public_key"
        ):
            return (
                False,
                None,
                (
                    "Raw Public Key (RPK) authentication is not supported by the "
                    "installed aiocoap DTLS backend. RPK (RFC 7250) requires a DTLS "
                    "backend with RPK support; the installed backend likely only "
                    "supports PSK mode."
                ),
            )

        with open(rpk_path, "rb") as f:
            rpk_data = f.read()

        client_creds[target_uri] = aiocoap_creds.DTLS(raw_public_key=rpk_data)

        ctx = await aiocoap.Context.create_client_context()
        ctx.client_credentials = client_creds

        uri = f"coaps://{host}:{port}/.well-known/core"
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        response = await asyncio.wait_for(ctx.request(request).response, timeout=timeout)
        code_str = str(response.code)

        if code_str.startswith("2.") or code_str.startswith("4."):
            return True, ctx, code_str

        await ctx.shutdown()
        return False, None, f"unexpected response: {code_str}"

    except FileNotFoundError as e:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-RPK cleanup error after FileNotFoundError: %s", exc)
        return False, None, f"RPK file not found: {e}"
    except asyncio.TimeoutError:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-RPK cleanup error after timeout: %s", exc)
        return False, None, "timeout"
    except Exception as e:
        if ctx:
            try:
                await ctx.shutdown()
            except Exception as exc:
                logger.debug("DTLS-RPK cleanup error: %s", exc)
        return False, None, str(e)


# ------------------------------------------------------------------
# Payload parsing
# ------------------------------------------------------------------


def parse_payload(
    payload: bytes,
    content_format: Optional[int] = None,
) -> Dict[str, Any]:
    """Auto-detect and parse a CoAP response payload.

    Returns a dict with keys:
        - ``type``: detected format name (e.g. ``"json"``, ``"cbor"``, ``"text"``, ``"binary"``)
        - ``value``: parsed Python object (dict/list/str) or hex string for binary
        - ``raw_size``: original payload length in bytes

    Content-Format detection order:
        1. Explicit *content_format* option number (if provided).
        2. Heuristic: try JSON, then UTF-8, then hex dump.

    cbor2 is optional -- if not installed, CBOR payloads are returned as hex.
    """
    result: Dict[str, Any] = {"raw_size": len(payload)}

    if not payload:
        result["type"] = "empty"
        result["value"] = ""
        return result

    # --- Dispatch on explicit content-format ---
    if content_format is not None:
        # JSON variants
        if content_format in (50, 11543, 110):
            return _parse_json_payload(payload, result, content_format)

        # CBOR
        if content_format == 60:
            return _parse_cbor_payload(payload, result)

        # LwM2M TLV
        if content_format == 11542:
            return _parse_lwm2m_tlv(payload, result)

        # text/plain or link-format -- decode as UTF-8
        if content_format in (0, 40):
            return _parse_text_payload(payload, result)

    # --- Heuristic: no content-format header ---
    # Try JSON first (very common for IoT APIs)
    stripped = payload.lstrip()
    if stripped and stripped[0:1] in (b"{", b"["):
        try:
            result["value"] = json.loads(payload.decode("utf-8"))
            result["type"] = "json"
            return result
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
            # RecursionError: json.loads() blows the stack on deeply nested
            # input, and ~1000 nested brackets fit in one CoAP datagram.
            logger.debug(f"JSON decode of CoAP payload failed: {e}")

    # Try UTF-8
    try:
        text = payload.decode("utf-8")
        # Only accept if no control chars other than common whitespace
        if all(c >= " " or c in "\t\n\r" for c in text):
            result["type"] = "text"
            result["value"] = text
            return result
    except UnicodeDecodeError as e:
        logger.debug(f"CoAP payload UTF-8 decode failed: {e}")

    # Fallback: hex dump
    result["type"] = "binary"
    result["value"] = payload.hex()
    return result


def _parse_text_payload(payload: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
    """Decode payload as UTF-8 text."""
    try:
        result["value"] = payload.decode("utf-8")
        result["type"] = "text"
    except UnicodeDecodeError:
        result["type"] = "binary"
        result["value"] = payload.hex()
    return result


def _parse_json_payload(
    payload: bytes, result: Dict[str, Any], content_format: int
) -> Dict[str, Any]:
    """Parse a JSON-based payload (plain JSON, LwM2M JSON, SenML JSON)."""
    format_names = {50: "json", 11543: "lwm2m_json", 110: "senml_json"}
    try:
        result["value"] = json.loads(payload.decode("utf-8"))
        result["type"] = format_names.get(content_format, "json")
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        # RecursionError: deeply nested arrays/objects from a hostile server
        # exceed the interpreter recursion limit inside json.loads().
        logger.debug("JSON parse failed (cf=%d): %s", content_format, exc)
        result["type"] = "binary"
        result["value"] = payload.hex()
    return result


def _parse_cbor_payload(payload: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a CBOR payload if cbor2 is available, otherwise hex dump."""
    if not _cbor2.is_available:
        logger.debug("cbor2 not installed, returning hex dump for CBOR payload")
        result["type"] = "cbor_hex"
        result["value"] = payload.hex()
        return result
    try:
        result["value"] = _cbor2.loads(payload)
        result["type"] = "cbor"
    except Exception as exc:
        logger.debug("CBOR decode failed: %s", exc)
        result["type"] = "binary"
        result["value"] = payload.hex()
    return result


def _parse_lwm2m_tlv(payload: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
    """Basic TLV parsing for LwM2M application/vnd.oma.lwm2m+tlv.

    TLV format (OMA-TS-LightweightM2M):
        Byte 0: type/identifier/length flags
        Bytes 1..n: identifier (8 or 16 bit)
        Bytes n+1..m: length (0/8/16/24 bit inline)
        Remaining: value
    """
    records: list = []
    offset = 0
    try:
        while offset < len(payload):
            type_byte = payload[offset]
            offset += 1

            # Type field (bits 7-6)
            tlv_type = (type_byte >> 6) & 0x03

            # Identifier length (bit 5): 0 = 8-bit, 1 = 16-bit
            if type_byte & 0x20:
                if offset + 2 > len(payload):
                    break
                identifier = int.from_bytes(payload[offset : offset + 2], "big")
                offset += 2
            else:
                if offset >= len(payload):
                    break
                identifier = payload[offset]
                offset += 1

            # Length (bits 4-3)
            len_type = (type_byte >> 3) & 0x03
            if len_type == 0:
                # Length in bits 2-0
                value_len = type_byte & 0x07
            elif len_type == 1:
                if offset >= len(payload):
                    break
                value_len = payload[offset]
                offset += 1
            elif len_type == 2:
                if offset + 2 > len(payload):
                    break
                value_len = int.from_bytes(payload[offset : offset + 2], "big")
                offset += 2
            else:
                if offset + 3 > len(payload):
                    break
                value_len = int.from_bytes(payload[offset : offset + 3], "big")
                offset += 3

            value = payload[offset : offset + value_len]
            offset += value_len

            type_names = {
                0: "object_instance",
                1: "resource_instance",
                2: "multiple",
                3: "resource",
            }
            record = {
                "type": type_names.get(tlv_type, str(tlv_type)),
                "id": identifier,
            }
            # Try to decode value as UTF-8 text
            try:
                record["value"] = value.decode("utf-8")
            except UnicodeDecodeError:
                record["value"] = value.hex()

            records.append(record)

        result["type"] = "lwm2m_tlv"
        result["value"] = records
    except Exception as exc:
        logger.debug("LwM2M TLV parse failed: %s", exc)
        result["type"] = "binary"
        result["value"] = payload.hex()
    return result
