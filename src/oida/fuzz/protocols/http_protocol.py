"""HTTP Protocol Fuzzer"""

import socket
from typing import Any, Dict, List, Optional, Set

from boofuzz import Block, Delim, Group, Request, Size, Static

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.config import FuzzerConfig
from oida.utils.ics_logger import get_logger
from oida.fuzz.core.connections import TCPSocketConnection
from oida.fuzz.primitives.dynamic import SmartString
from oida.fuzz.primitives.smart_string import StringContext
from oida.fuzz.primitives.transformers import (
    Base64Transformer,
    BasicAuthTransformer,
    GzipTransformer,
    JWTTransformer,
    TransformerChain,
    URLEncodeTransformer,
)

import logging

logger = logging.getLogger(__name__)


class HTTPFuzzer(BaseFuzzer):
    """HTTP/HTTPS Protocol Fuzzer for web server security testing"""

    # Protocol-specific monitor: HTTP GET check every 50 tests
    DEFAULT_MONITORS = "http:50"

    # WebDAV methods that should only be fuzzed if WebDAV is detected
    WEBDAV_METHODS = {
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
    }

    PROTOCOL_OPTIONS = {
        "use_capability_detection": {
            "type": bool,
            "default": True,
            "description": "Probe server to detect supported methods before fuzzing",
        },
        "methods": {
            "type": str,
            "default": None,
            "description": "Comma-separated list of HTTP methods to fuzz (overrides detection)",
        },
        "webdav": {
            "type": bool,
            "default": None,
            "description": "Force WebDAV fuzzing on/off (overrides detection)",
        },
        "url": {
            "type": str,
            "default": None,
            "description": "Custom URL path to use for fuzzing (e.g., /api/v1/endpoint)",
        },
        "headers_file": {
            "type": str,
            "default": None,
            "description": "Path to file with custom headers (one per line: Header-Name: value)",
            "example": "/path/to/headers.txt",
        },
        "header": {
            "type": str,
            "default": None,
            "description": "Custom header to add (format: Name:Value). Use multiple -O header=... for multiple headers",
            "example": "Authorization:Bearer token123",
        },
        "cookie": {
            "type": str,
            "default": None,
            "description": "Cookie header value to add to requests",
            "example": "session=abc123; user=admin",
        },
        "auth_bearer": {
            "type": str,
            "default": None,
            "description": "Bearer token for Authorization header",
            "example": "eyJhbGciOiJIUzI1NiIs...",
        },
        "auth_basic": {
            "type": str,
            "default": None,
            "description": "Basic auth credentials (format: username:password)",
            "example": "admin:password123",
        },
    }

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # Create logger early so we can log before super().__init__()
        protocol = getattr(config, "protocol", "FUZZ").upper()
        verbose = getattr(config, "console_output", False)
        self.log = get_logger(
            f"FUZZ-{protocol}", config.target_ip, config.target_port, verbose=verbose
        )

        # Capability detection flag
        self.use_capability_detection = config.get_option("use_capability_detection", True)

        # Custom URL path override (e.g., -O url=/api/v1/endpoint)
        self.custom_url = config.get_option("url", None)

        # Load custom headers from various sources
        self.custom_headers: List[tuple] = []
        self._load_custom_headers(config)

        # Check for user method override (log BEFORE super().__init__ applies QuietFilter)
        user_methods = config.get_option("methods", None)
        user_webdav = config.get_option("webdav", None)

        if user_methods:
            methods_set = {m.strip().upper() for m in user_methods.split(",")}
            self.log.display(f"User override - fuzzing methods: {', '.join(sorted(methods_set))}")
            if user_webdav is True:
                self.log.display("WebDAV fuzzing forced ON")
            elif user_webdav is False:
                self.log.display("WebDAV fuzzing forced OFF")

        if self.custom_url:
            self.log.display(f"User override - using custom URL path: {self.custom_url}")

        if self.custom_headers:
            self.log.display(f"Custom headers: {len(self.custom_headers)} header(s) configured")
            for name, value in self.custom_headers:
                # Truncate long values for logging
                display_value = value[:50] + "..." if len(value) > 50 else value
                self.log.display(f"  {name}: {display_value}")

        # Call parent __init__ which handles enumeration via _enumerate_capabilities()
        super().__init__(config, connection_factory)

    def _load_custom_headers(self, config: FuzzerConfig) -> None:
        """Load custom headers from config options.

        Supports multiple sources:
        - headers_file: Path to file with headers (one per line)
        - header: Single header (can use multiple -O header=...)
        - cookie: Cookie header value
        - auth_bearer: Bearer token for Authorization header
        - auth_basic: Basic auth credentials (username:password)

        Args:
            config: Fuzzer configuration
        """
        import base64
        import os

        # 1. Load from headers file
        headers_file = config.get_option("headers_file", None)
        if headers_file:
            if os.path.exists(headers_file):
                try:
                    with open(headers_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            # Skip empty lines and comments
                            if not line or line.startswith("#"):
                                continue
                            # Parse "Header-Name: value" format
                            if ":" in line:
                                name, value = line.split(":", 1)
                                self.custom_headers.append((name.strip(), value.strip()))
                    self.log.display(
                        f"Loaded {len(self.custom_headers)} headers from {headers_file}"
                    )
                except Exception as e:
                    self.log.warning(f"Failed to read headers file {headers_file}: {e}")
            else:
                self.log.warning(f"Headers file not found: {headers_file}")

        # 2. Load inline header option(s)
        # Note: config.get_option returns the last value if multiple -O header=... used
        # For multiple headers, users should use the file or comma-separated format
        header_opt = config.get_option("header", None)
        if header_opt:
            # Support comma-separated headers: "Header1:Value1,Header2:Value2"
            for header_spec in header_opt.split(","):
                header_spec = header_spec.strip()
                if ":" in header_spec:
                    name, value = header_spec.split(":", 1)
                    self.custom_headers.append((name.strip(), value.strip()))

        # 3. Cookie shorthand
        cookie = config.get_option("cookie", None)
        if cookie:
            self.custom_headers.append(("Cookie", cookie))

        # 4. Bearer token shorthand
        auth_bearer = config.get_option("auth_bearer", None)
        if auth_bearer:
            self.custom_headers.append(("Authorization", f"Bearer {auth_bearer}"))

        # 5. Basic auth shorthand
        auth_basic = config.get_option("auth_basic", None)
        if auth_basic:
            # Encode as base64
            encoded = base64.b64encode(auth_basic.encode()).decode()
            self.custom_headers.append(("Authorization", f"Basic {encoded}"))

    def _build_custom_headers_children(self) -> tuple:
        """Build boofuzz Block children for custom headers.

        Returns:
            Tuple of Block children for custom headers, or empty tuple if none
        """
        if not self.custom_headers:
            return ()

        children = []
        for i, (name, value) in enumerate(self.custom_headers):
            children.append(
                Block(
                    f"Custom-Header-{i}",
                    children=(
                        Static(f"Custom-{i}-Key", f"{name}: "),
                        Static(f"Custom-{i}-Value", value),
                        Static(f"Custom-{i}-CRLF", "\r\n"),
                    ),
                )
            )
        return tuple(children)

    def _get_url_path(self, default: str = "/") -> str:
        """Get URL path for fuzzing - custom if set, else default.

        Args:
            default: Default path to use if custom_url not set

        Returns:
            URL path string (custom_url or default)
        """
        return self.custom_url if self.custom_url else default

    def _enumerate_capabilities(self) -> Optional[Dict[str, Any]]:
        """Probe HTTP server capabilities before fuzzing.

        Uses the generic enumeration framework from BaseFuzzer.
        Called automatically when config.enumerate=True.

        Returns:
            Dictionary with detected capabilities (methods, webdav, server)
        """
        if not self.use_capability_detection:
            return {}

        return self._probe_server_capabilities(self.config)

    def _probe_server_capabilities(self, config: FuzzerConfig) -> Dict[str, Any]:
        """Probe server to detect supported HTTP methods and features.

        Strategy:
        1. Try OPTIONS first to get Allow header
        2. If OPTIONS fails/unsupported, probe each method individually
        3. Try PROPFIND to detect WebDAV

        Args:
            config: Fuzzer configuration with target info

        Returns:
            Dictionary with detected capabilities
        """
        capabilities = {
            "methods": set(),
            "webdav": False,
            "server": None,
            "allow_header": None,
        }

        self.log.display(
            f"Probing server capabilities on {config.target_ip}:{config.target_port}..."
        )

        try:
            # 1. Try OPTIONS first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            try:
                sock.connect((config.target_ip, config.target_port))

                options_request = (
                    f"OPTIONS / HTTP/1.1\r\nHost: {config.target_ip}\r\nConnection: close\r\n\r\n"
                )
                sock.send(options_request.encode())
                response = sock.recv(4096).decode("utf-8", errors="ignore")
            finally:
                sock.close()

            # Parse response
            capabilities = self._parse_http_response(response, capabilities)

            # Check if OPTIONS was supported (2xx response with Allow header)
            options_supported = (
                capabilities.get("allow_header") is not None
                and response.startswith("HTTP/1.")
                and (" 200 " in response[:50] or " 204 " in response[:50])
            )

            # 2. If OPTIONS didn't work, probe each method individually
            if not options_supported or not capabilities["methods"]:
                self.log.display("OPTIONS not supported, probing methods individually...")
                capabilities["methods"] = self._probe_methods_individually(config, capabilities)

            # 3. Try PROPFIND to detect WebDAV (if not already detected)
            if not capabilities["webdav"]:
                capabilities["webdav"] = self._probe_webdav(config)

            # Logging is handled by _log_capabilities() called from BaseFuzzer.__init__

        except socket.timeout:
            self.log.warning("Probe timed out, fuzzing all methods")
        except ConnectionRefusedError:
            self.log.warning("Connection refused")
        except Exception as e:
            self.log.warning(f"Probe failed ({e}), fuzzing all methods")

        return capabilities

    def _probe_methods_individually(self, config: FuzzerConfig, capabilities: Dict) -> Set[str]:
        """Probe each HTTP method with a minimal request.

        Args:
            config: Fuzzer configuration
            capabilities: Existing capabilities dict (may have server info)

        Returns:
            Set of supported method names
        """
        supported = set()

        # Methods to probe (most common first for efficiency)
        methods_to_probe = [
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "TRACE",
            "CONNECT",
        ]

        for method in methods_to_probe:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                try:
                    sock.connect((config.target_ip, config.target_port))

                    # Minimal request for this method
                    if method in ("POST", "PUT", "PATCH"):
                        request = (
                            f"{method} / HTTP/1.1\r\n"
                            f"Host: {config.target_ip}\r\n"
                            f"Content-Length: 0\r\n"
                            f"Connection: close\r\n"
                            f"\r\n"
                        )
                    else:
                        request = (
                            f"{method} / HTTP/1.1\r\n"
                            f"Host: {config.target_ip}\r\n"
                            f"Connection: close\r\n"
                            f"\r\n"
                        )

                    sock.send(request.encode())
                    response = sock.recv(1024).decode("utf-8", errors="ignore")
                finally:
                    sock.close()

                # Parse status code
                status = self._get_status_code(response)

                # Method is supported if we get anything other than 501/405
                # 501 = Not Implemented, 405 = Method Not Allowed
                if status and status not in (501, 405):
                    supported.add(method)
                    # Capture server header if we don't have it
                    if not capabilities.get("server"):
                        self._parse_http_response(response, capabilities)

            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                logger.debug(f"Operation failed: {e}")
                continue

        return supported

    def _probe_webdav(self, config: FuzzerConfig) -> bool:
        """Probe for WebDAV support using PROPFIND.

        Returns:
            True if WebDAV is supported
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            try:
                sock.connect((config.target_ip, config.target_port))

                propfind_request = (
                    f"PROPFIND / HTTP/1.1\r\n"
                    f"Host: {config.target_ip}\r\n"
                    f"Depth: 0\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                sock.send(propfind_request.encode())
                response = sock.recv(1024).decode("utf-8", errors="ignore")
            finally:
                sock.close()

            status = self._get_status_code(response)

            # WebDAV: 207 Multi-Status, or PROPFIND accepted (not 501/405)
            if status == 207:
                return True
            if status and status not in (501, 405, 400, 404):
                return True

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self.log.debug(f"WebDAV probe failed: {e}")

        return False

    def _get_status_code(self, response: str) -> Optional[int]:
        """Extract HTTP status code from response.

        Args:
            response: Raw HTTP response string

        Returns:
            Status code as int, or None if not parseable
        """
        if not response or not response.startswith("HTTP/"):
            return None
        try:
            # HTTP/1.1 200 OK -> extract 200
            parts = response.split(" ", 2)
            if len(parts) >= 2:
                return int(parts[1])
        except (ValueError, IndexError) as e:
            self.log.debug(f"Failed to parse HTTP status: {e}")
        return None

    def _parse_http_response(self, response: str, capabilities: Dict) -> Dict:
        """Parse HTTP response to extract capabilities.

        Args:
            response: Raw HTTP response string
            capabilities: Dictionary to update with parsed values

        Returns:
            Updated capabilities dictionary
        """
        for line in response.split("\r\n"):
            line_lower = line.lower()

            # Parse Server header
            if line_lower.startswith("server:"):
                capabilities["server"] = line.split(":", 1)[1].strip()

            # Parse Allow header
            elif line_lower.startswith("allow:"):
                allow_value = line.split(":", 1)[1].strip()
                capabilities["allow_header"] = allow_value
                methods = {m.strip().upper() for m in allow_value.split(",")}
                capabilities["methods"].update(methods)

                # Check for WebDAV methods in Allow header
                if capabilities["methods"] & self.WEBDAV_METHODS:
                    capabilities["webdav"] = True
                    self.log.display("WebDAV detected (methods in Allow header)")

            # Check for DAV header (WebDAV indicator)
            elif line_lower.startswith("dav:"):
                capabilities["webdav"] = True
                self.log.display("WebDAV detected (DAV header present)")

        return capabilities

    def _supports_method(self, method: str) -> bool:
        """Check if server supports a specific HTTP method.

        Args:
            method: HTTP method to check (e.g., 'GET', 'PROPFIND')

        Returns:
            True if method is supported or capability detection is disabled/failed
        """
        # If capability detection disabled, assume all methods supported
        if not self.use_capability_detection or not self.config.enumerate:
            return True

        # If no methods detected, assume all supported
        if not self.capabilities.get("methods"):
            return True

        return method.upper() in self.capabilities["methods"]

    def _supports_webdav(self) -> bool:
        """Check if server supports WebDAV.

        Returns:
            True if WebDAV is supported or capability detection is disabled/failed
        """
        if not self.use_capability_detection or not self.config.enumerate:
            return True

        return self.capabilities.get("webdav", True)

    def _log_capabilities(self) -> None:
        """Log probed server capabilities."""
        if not self.use_capability_detection or not self.config.enumerate:
            return

        if not self.capabilities:
            return

        fuzz_log = self._get_fuzz_logger()

        # Display summary
        server = self.capabilities.get("server")
        methods = self.capabilities.get("methods", set())
        webdav = self.capabilities.get("webdav", False)

        if server:
            fuzz_log.display(f"Server: {server}")

        if methods:
            # Categorize detected methods
            all_standard = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"}
            all_special = {"CONNECT", "TRACE", "SEARCH"}
            all_webdav = {
                "PROPFIND",
                "PROPPATCH",
                "MKCOL",
                "COPY",
                "MOVE",
                "LOCK",
                "UNLOCK",
            }

            # (methods & all_standard / & all_special were dead bare expressions
            # here - only the webdav set is actually consumed below.)
            detected_webdav = methods & all_webdav

            skipped_standard = all_standard - methods
            skipped_special = all_special - methods

            fuzz_log.display(f"Allowed methods: {', '.join(sorted(methods))}")

            if skipped_standard or skipped_special:
                skipped_all = skipped_standard | skipped_special
                fuzz_log.display(f"Skipping: {', '.join(sorted(skipped_all))}")

            if not webdav and not detected_webdav:
                fuzz_log.display("WebDAV: not detected")
        else:
            fuzz_log.display("Methods: unknown (fuzzing all)")

        fuzz_log.display("Tip: --no-enumerate to fuzz all, or -O methods=GET,POST,PUT to override")

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        HTTP state machine has 6 states:
        - DISCONNECTED: No connection
        - CONNECTED: TCP connection established
        - REQUEST_SENT: HTTP request transmitted
        - RESPONSE_RECEIVED: Server responded
        - PERSISTENT: Keep-alive connection active
        - AUTHENTICATED: For auth-required resources
        """
        return [
            # Baseline tests - just need TCP connection
            RequestInfo(
                "HTTP_Baseline",
                "Simple GET / baseline test",
                "baseline",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "HTTP_Unified_Standard",
                "Core HTTP methods + headers fuzzing (7 methods x 123 headers)",
                "core",
                requires_state="CONNECTED",
            ),
            # Common requests - need basic connection
            RequestInfo(
                "POST_Multipart",
                "Multipart form/file upload testing",
                "common",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "JSON_Request",
                "JSON API request testing",
                "common",
                requires_state="CONNECTED",
            ),
            # Special methods - need basic connection
            RequestInfo(
                "HTTP_Special_Methods",
                "CONNECT, TRACE, SEARCH methods",
                "methods",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "WebDAV_Methods",
                "WebDAV operations (PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK)",
                "webdav",
                requires_state="CONNECTED",
            ),
            # Edge cases - chunked/pipelining depend on response handling
            RequestInfo(
                "HTTP_Chunked_Encoding",
                "Chunked transfer encoding (smuggling tests)",
                "edge_cases",
                requires_state="RESPONSE_RECEIVED",
            ),
            RequestInfo(
                "Pipeline_Request",
                "HTTP request pipelining",
                "edge_cases",
                requires_state="PERSISTENT",
            ),
            RequestInfo(
                "HTTP_Duplicate_Headers",
                "Duplicate header testing",
                "edge_cases",
                slow=True,
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "HTTP_Delimiter_Fuzzing",
                "Malformed delimiter edge cases",
                "edge_cases",
                slow=True,
                requires_state="CONNECTED",
            ),
            # Legacy protocol - just needs connection
            RequestInfo(
                "HTTP_0_9_GET",
                "HTTP/0.9 legacy protocol",
                "legacy",
                requires_state="CONNECTED",
            ),
            # Auth transformers - require authenticated state
            RequestInfo(
                "BasicAuth_Transformer",
                "Basic authentication testing",
                "transformers",
                requires_state="AUTHENTICATED",
            ),
            RequestInfo(
                "JWT_Transformer",
                "JWT token testing",
                "transformers",
                requires_state="AUTHENTICATED",
            ),
            # Body transformers - just need connection
            RequestInfo(
                "Gzip_Transformer",
                "Gzip compressed body testing",
                "transformers",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "TransformerChain_Example",
                "Gzip + Base64 chained transformers",
                "transformers",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "URLEncoded_Transformer",
                "URL-encoded query parameters",
                "transformers",
                requires_state="CONNECTED",
            ),
            # Header fuzzing - just needs connection
            RequestInfo(
                "Cookie_Fuzzing",
                "Cookie header with attributes (name, value, Path, Domain, SameSite)",
                "headers",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "UserAgent_Fuzzing",
                "User-Agent with browser fingerprint patterns",
                "headers",
                requires_state="CONNECTED",
            ),
        ]

    def _create_socket(self):
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            **self._timeout_overrides(),
        )

    def _define_protocol(self) -> None:
        # ==================== HEADER AND METHOD GROUPS ====================
        # Common HTTP methods for unified fuzzing
        ALL_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"]
        ALL_SPECIAL_METHODS = ["CONNECT", "TRACE", "SEARCH"]
        ALL_WEBDAV_METHODS = [
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
        ]

        # Check for user-specified method override
        user_methods_str = self.config.get_option("methods", None)
        user_webdav = self.config.get_option("webdav", None)

        if user_methods_str:
            # User explicitly specified methods - use those
            user_methods = {m.strip().upper() for m in user_methods_str.split(",")}
            HTTP_METHODS = [m for m in ALL_HTTP_METHODS if m in user_methods]
            SPECIAL_METHODS = [m for m in ALL_SPECIAL_METHODS if m in user_methods]
            WEBDAV_METHODS = [m for m in ALL_WEBDAV_METHODS if m in user_methods]
        else:
            # Filter methods based on probed capabilities
            detected_methods = self.capabilities.get("methods", set())
            if detected_methods and self.use_capability_detection and self.config.enumerate:
                # Filter to only detected methods (always include GET as baseline)
                HTTP_METHODS = [m for m in ALL_HTTP_METHODS if m in detected_methods or m == "GET"]
                SPECIAL_METHODS = [m for m in ALL_SPECIAL_METHODS if m in detected_methods]
                WEBDAV_METHODS = [m for m in ALL_WEBDAV_METHODS if m in detected_methods]

                # Log what's being skipped
                skipped_standard = set(ALL_HTTP_METHODS) - set(HTTP_METHODS)
                skipped_special = set(ALL_SPECIAL_METHODS) - set(SPECIAL_METHODS)
                if skipped_standard:
                    self.log.display(
                        f"Skipping unsupported standard methods: {', '.join(sorted(skipped_standard))}"
                    )
                if skipped_special:
                    self.log.display(
                        f"Skipping unsupported special methods: {', '.join(sorted(skipped_special))}"
                    )
                if not SPECIAL_METHODS:
                    self.log.display("No special methods supported (CONNECT, TRACE, SEARCH)")
            else:
                # No detection or disabled - use all methods
                HTTP_METHODS = ALL_HTTP_METHODS
                SPECIAL_METHODS = ALL_SPECIAL_METHODS
                WEBDAV_METHODS = ALL_WEBDAV_METHODS

        # Allow user to override WebDAV detection
        if user_webdav is not None:
            if user_webdav:
                WEBDAV_METHODS = ALL_WEBDAV_METHODS
                self.log.display("WebDAV fuzzing forced ON by user")
            else:
                WEBDAV_METHODS = []
                self.log.display("WebDAV fuzzing forced OFF by user")

        # Store active methods for filtering POST/PUT-specific requests
        self.http_methods = set(HTTP_METHODS)

        # Common headers (seen in 80%+ of web traffic) - 25 headers
        COMMON_HEADERS = [
            "Accept",
            "Accept-Charset",
            "Accept-Encoding",
            "Accept-Language",
            "Authorization",
            "Cache-Control",
            "Connection",
            "Content-Encoding",
            "Content-Language",
            "Content-Length",
            "Content-Type",
            "Cookie",
            "Host",
            "If-Match",
            "If-Modified-Since",
            "If-None-Match",
            "If-Range",
            "Origin",
            "Pragma",
            "Referer",
            "Transfer-Encoding",
            "User-Agent",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Requested-With",
        ]

        # Rare/specialized headers (uncommon, specific use cases) - 98 headers
        RARE_HEADERS = [
            "A-IM",
            "Accept-Datetime",
            "Access-Control-Request-Headers",
            "Access-Control-Request-Method",
            "Alt-Used",
            "CF-Connecting-IP",
            "CF-IPCountry",
            "CF-RAY",
            "CF-Visitor",
            "Content-DPR",
            "Content-Disposition",
            "Content-Range",
            "Content-Security-Policy",
            "DNT",
            "DPR",
            "Date",
            "Device-Memory",
            "Digest",
            "Downlink",
            "Duplicate-Header",
            "ECT",
            "Early-Data",
            "Expect",
            "Fastly-Client-IP",
            "Forwarded",
            "From",
            "Front-End-Https",
            "If-Schedule-Tag-Match",
            "If-Unmodified-Since",
            "Keep-Alive",
            "Max-Forwards",
            "Prefer",
            "Priority",
            "Proxy-Authorization",
            "Proxy-Connection",
            "RTT",
            "Range",
            "Save-Data",
            "Sec-CH-Prefers-Color-Scheme",
            "Sec-CH-Prefers-Reduced-Motion",
            "Sec-CH-UA",
            "Sec-CH-UA-Arch",
            "Sec-CH-UA-Bitness",
            "Sec-CH-UA-Full-Version",
            "Sec-CH-UA-Full-Version-List",
            "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Model",
            "Sec-CH-UA-Platform",
            "Sec-CH-UA-Platform-Version",
            "Sec-CH-UA-WoW64",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Sec-WebSocket-Extensions",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Version",
            "Service-Worker",
            "Service-Worker-Navigation-Preload",
            "TE",
            "Trailer",
            "True-Client-IP",
            "Upgrade",
            "Upgrade-Insecure-Requests",
            "Via",
            "Viewport-Width",
            "WWW-Authenticate",
            "Want-Digest",
            "Warning",
            "Width",
            "X-API-Key",
            "X-ATT-DeviceId",
            "X-Azure-ClientIP",
            "X-Azure-SocketIP",
            "X-CSRF-Token",
            "X-Client-IP",
            "X-Content-Type-Options",
            "X-Correlation-ID",
            "X-Custom-Header",
            "X-Do-Not-Track",
            "X-Forwarded-Host",
            "X-Forwarded-Port",
            "X-Forwarded-Proto",
            "X-Forwarded-Server",
            "X-Frame-Options",
            "X-HTTP-Method-Override",
            "X-Http-Method-Override",
            "X-Long-Header",
            "X-Moz",
            "X-Original-Forwarded-For",
            "X-ProxyUser-Ip",
            "X-Purpose",
            "X-Request-ID",
            "X-Scheme",
            "X-UIDH",
            "X-Wap-Profile",
            "X-XSS-Protection",
        ]

        # ==================== BASELINE REQUEST ====================
        # Simple GET / request to verify HTTP service responds before complex fuzzing
        # This minimal test catches basic connectivity issues immediately
        baseline_headers_children = [
            Block(
                "Host",
                children=(
                    Static("Host-Key", "Host: "),
                    Static("Host-Value", self.config.target_ip),
                    Static("CRLF", "\r\n"),
                ),
            ),
        ]
        # Add custom headers (Cookie, Authorization, etc.)
        baseline_headers_children.extend(self._build_custom_headers_children())

        baseline_request = Request(
            "HTTP_Baseline",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "GET"),
                        Delim("space-1", " "),
                        Static("URI-Path", "/"),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=tuple(baseline_headers_children),
                ),
                Static("Headers-End", "\r\n"),
            ),
        )

        # ==================== CONDENSED UNIFIED REQUEST ====================
        # Replaces: HTTP_Standard, DELETE_Request, PUT_Request, HEAD_Request,
        # patch_request, cors_preflight, range_request, and other standard method requests

        # Build unified request headers with custom headers injected after Host
        unified_headers_children = [
            # Host is mandatory, always included
            Block(
                "Host",
                children=(
                    Static("Host-Key", "Host: "),
                    SmartString(
                        "Host-Value",
                        self.config.target_ip,
                        max_len=256,
                        fuzzable=True,
                        context=StringContext.HOSTNAME,
                    ),
                    Static("CRLF", "\r\n"),
                ),
            ),
        ]
        # Add custom headers (Cookie, Authorization, etc.)
        unified_headers_children.extend(self._build_custom_headers_children())
        # Add standard fuzzable headers
        unified_headers_children.extend(
            [
                # Common headers (25 headers) - single block for fast core fuzzing
                Block(
                    "CommonHeaders",
                    children=(
                        Group("CommonHeaderName", values=COMMON_HEADERS),
                        Delim("common-colon", ": "),
                        SmartString(
                            "CommonHeaderValue",
                            "test-value",
                            max_len=4096,
                            fuzzable=True,
                        ),
                        Static("common-CRLF", "\r\n"),
                    ),
                ),
                # Rare/specialized headers (98 headers) - single block for fast core fuzzing
                Block(
                    "RareHeaders",
                    children=(
                        Group("RareHeaderName", values=RARE_HEADERS),
                        Delim("rare-colon", ": "),
                        SmartString(
                            "RareHeaderValue",
                            "rare-value",
                            max_len=4096,
                            fuzzable=True,
                        ),
                        Static("rare-CRLF", "\r\n"),
                    ),
                ),
                # Content-Length for body
                Block(
                    "Content-Length",
                    children=(
                        Static("Content-Length-Key", "Content-Length: "),
                        Size("Body-Size", "Body", output_format="ascii"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
            ]
        )

        unified_request = Request(
            "HTTP_Unified_Standard",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Group("Method", values=HTTP_METHODS),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            "/",
                            max_len=2000,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        # Query parameters - multiple for parameter pollution testing
                        # Delimiters are STATIC for clean, well-formed requests
                        Delim("query-start", "?"),
                        SmartString("Query-Param1-Name", "param", max_len=100, fuzzable=True),
                        Delim("equals1", "="),
                        SmartString("Query-Param1-Value", "value1", max_len=500, fuzzable=True),
                        # Repeat param2 (parameter pollution)
                        Delim("param-sep1", "&"),
                        SmartString("Query-Param2-Name", "param", max_len=100, fuzzable=True),
                        Delim("equals2", "="),
                        SmartString("Query-Param2-Value", "value2", max_len=500, fuzzable=True),
                        # Additional param3 (more pollution)
                        Delim("param-sep2", "&"),
                        SmartString("Query-Param3-Name", "id", max_len=100, fuzzable=True),
                        Delim("equals3", "="),
                        SmartString("Query-Param3-Value", "123", max_len=500, fuzzable=True),
                        Delim("space-2", " "),
                        SmartString("HTTP-Version", "HTTP/1.1", max_len=20, fuzzable=True),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=tuple(unified_headers_children),
                ),
                Static("Headers-End", "\r\n"),
                Block(
                    "Body",
                    children=(
                        SmartString(
                            "Body-Content",
                            "field1=value1&field2=value2",
                            max_len=8192,
                            fuzzable=True,
                            radamsa_mutation_count=1000,
                        ),
                        Static("Body-End", "\r\n"),  # Proper HTTP message termination
                    ),
                ),
            ),
        )

        # ==================== SPECIAL METHODS REQUEST ====================
        # Replaces: connect_request, trace_request, webdav_search
        # Only create if there are special methods to fuzz
        special_methods_request = None
        if SPECIAL_METHODS:
            # Build special methods headers with custom headers
            special_headers_children = [
                Block(
                    "Host",
                    children=(
                        Static("Host-Key", "Host: "),
                        SmartString(
                            "Host-Value",
                            self.config.target_ip,
                            max_len=256,
                            fuzzable=True,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                ),
            ]
            special_headers_children.extend(self._build_custom_headers_children())
            special_headers_children.append(
                Block(
                    "CommonHeaders",
                    children=(
                        Group(
                            "HeaderName",
                            values=[
                                "User-Agent",
                                "Authorization",
                                "Max-Forwards",
                                "Via",
                            ],
                        ),
                        Delim("colon", ": "),
                        SmartString("HeaderValue", "test", max_len=512, fuzzable=True),
                        Static("CRLF", "\r\n"),
                    ),
                ),
            )

            special_methods_request = Request(
                "HTTP_Special_Methods",
                children=(
                    Block(
                        "Request-Line",
                        children=(
                            Group("Method", values=SPECIAL_METHODS),
                            Delim("space-1", " "),
                            SmartString(
                                "URI-Path",
                                "/",
                                max_len=2000,
                                fuzzable=True,
                                context=StringContext.PATH,
                            ),
                            Delim("space-2", " "),
                            Static("HTTP-Version", "HTTP/1.1"),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Headers",
                        children=tuple(special_headers_children),
                    ),
                    Static("Headers-End", "\r\n"),
                ),
            )

        # ==================== WEBDAV METHODS REQUEST ====================
        # WebDAV (Web Distributed Authoring and Versioning) - RFC 4918
        # Very common on Apache, nginx, IIS for file management
        # Only create if there are WebDAV methods to fuzz
        webdav_request = None
        if WEBDAV_METHODS:
            # Build WebDAV headers with custom headers after Host
            webdav_headers_children = [
                Block(
                    "Host",
                    children=(
                        Static("Host-Key", "Host: "),
                        SmartString(
                            "Host-Value",
                            self.config.target_ip,
                            max_len=256,
                            fuzzable=True,
                        ),
                        Static("CRLF", "\r\n"),
                    ),
                ),
            ]
            webdav_headers_children.extend(self._build_custom_headers_children())
            # WebDAV-specific headers
            webdav_headers_children.extend(
                [
                    Block(
                        "Depth",
                        children=(
                            Static("Depth-Key", "Depth: "),
                            SmartString(
                                "Depth-Value",
                                "0",
                                max_len=10,
                                fuzzable=True,
                                context=StringContext.NUMERIC,
                            ),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Destination",
                        children=(
                            Static("Dest-Key", "Destination: "),
                            SmartString(
                                "Dest-Value",
                                "/webdav/destination",
                                max_len=2000,
                                fuzzable=True,
                                context=StringContext.PATH,
                            ),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Lock-Token",
                        children=(
                            Static("Lock-Key", "Lock-Token: "),
                            SmartString(
                                "Lock-Value",
                                "<opaquelocktoken:12345>",
                                max_len=256,
                                fuzzable=True,
                            ),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Timeout",
                        children=(
                            Static("Timeout-Key", "Timeout: "),
                            SmartString(
                                "Timeout-Value",
                                "Infinite",
                                max_len=50,
                                fuzzable=True,
                            ),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Overwrite",
                        children=(
                            Static("Overwrite-Key", "Overwrite: "),
                            SmartString("Overwrite-Value", "T", max_len=10, fuzzable=True),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Content-Length",
                        children=(
                            Static("CL-Key", "Content-Length: "),
                            Size("Body-Size", "Body", output_format="ascii"),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                ]
            )

            webdav_request = Request(
                "WebDAV_Methods",
                children=(
                    Block(
                        "Request-Line",
                        children=(
                            Group("Method", values=WEBDAV_METHODS),
                            Delim("space-1", " "),
                            SmartString(
                                "URI-Path",
                                "/webdav/",
                                max_len=2000,
                                fuzzable=True,
                                context=StringContext.PATH,
                            ),
                            Delim("space-2", " "),
                            Static("HTTP-Version", "HTTP/1.1"),
                            Static("CRLF", "\r\n"),
                        ),
                    ),
                    Block(
                        "Headers",
                        children=tuple(webdav_headers_children),
                    ),
                    Static("Headers-End", "\r\n"),
                    Block(
                        "Body",
                        children=(
                            SmartString(
                                "WebDAV-XML-Body",
                                '<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>',
                                max_len=8192,
                                fuzzable=True,
                            ),
                            Static("Body-End", "\r\n"),  # Proper HTTP message termination
                        ),
                    ),
                ),
            )

        # ==================== DUPLICATE HEADERS REQUEST ====================
        # Tests duplicate/repeated header handling (slow, deprioritized)
        # Many servers have bugs when same header appears multiple times
        duplicate_headers_request = Request(
            "HTTP_Duplicate_Headers",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),  # POST most common for duplicate header bugs
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            "/",
                            max_len=2000,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Common headers (25 headers) - 3x repetition for duplicate testing
                        Block(
                            "CommonHeaders1",
                            children=(
                                Group("CommonHeaderName1", values=COMMON_HEADERS),
                                Delim("common-colon1", ": "),
                                SmartString(
                                    "CommonHeaderValue1",
                                    "value1",
                                    max_len=4096,
                                    fuzzable=True,
                                ),
                                Static("common-CRLF1", "\r\n"),
                            ),
                        ),
                        Block(
                            "CommonHeaders2",
                            children=(
                                Group("CommonHeaderName2", values=COMMON_HEADERS),
                                Delim("common-colon2", ": "),
                                SmartString(
                                    "CommonHeaderValue2",
                                    "value2-duplicate",
                                    max_len=4096,
                                    fuzzable=True,
                                ),
                                Static("common-CRLF2", "\r\n"),
                            ),
                        ),
                        Block(
                            "CommonHeaders3",
                            children=(
                                Group("CommonHeaderName3", values=COMMON_HEADERS),
                                Delim("common-colon3", ": "),
                                SmartString(
                                    "CommonHeaderValue3",
                                    "value3-triplicate",
                                    max_len=4096,
                                    fuzzable=True,
                                ),
                                Static("common-CRLF3", "\r\n"),
                            ),
                        ),
                        # Rare headers (98 headers) - 3x repetition for duplicate testing
                        Block(
                            "RareHeaders1",
                            children=(
                                Group("RareHeaderName1", values=RARE_HEADERS),
                                Delim("rare-colon1", ": "),
                                SmartString(
                                    "RareHeaderValue1",
                                    "rare-value1",
                                    max_len=4096,
                                    fuzzable=True,
                                ),
                                Static("rare-CRLF1", "\r\n"),
                            ),
                        ),
                        Block(
                            "RareHeaders2",
                            children=(
                                Group("RareHeaderName2", values=RARE_HEADERS),
                                Delim("rare-colon2", ": "),
                                SmartString(
                                    "RareHeaderValue2",
                                    "rare-value2-duplicate",
                                    max_len=4096,
                                    fuzzable=True,
                                ),
                                Static("rare-CRLF2", "\r\n"),
                            ),
                        ),
                        Block(
                            "RareHeaders3",
                            children=(
                                Group("RareHeaderName3", values=RARE_HEADERS),
                                Delim("rare-colon3", ": "),
                                SmartString(
                                    "RareHeaderValue3",
                                    "rare-value3-triplicate",
                                    max_len=4096,
                                    fuzzable=True,
                                ),
                                Static("rare-CRLF3", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Length",
                            children=(
                                Static("CL-Key", "Content-Length: "),
                                Size("Body-Size", "Body", output_format="ascii"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                Block(
                    "Body",
                    children=(
                        SmartString(
                            "Body-Content",
                            "test=data",
                            max_len=8192,
                            fuzzable=True,
                        ),
                        Static("Body-End", "\r\n"),  # Proper HTTP message termination
                    ),
                ),
            ),
        )

        # ==================== DELIMITER FUZZING REQUEST ====================
        # Tests malformed delimiter edge cases (slow, deprioritized)
        # Fuzzes all delimiters: ?, =, &, :, spaces
        delimiter_fuzzing_request = Request(
            "HTTP_Delimiter_Fuzzing",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "GET"),  # Simple GET for delimiter testing
                        Delim("space-1", " ", fuzzable=True),  # Fuzz space after method
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/test"),
                            max_len=100,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        # Fuzzable query delimiters
                        Delim("query-start", "?", fuzzable=True),  # Fuzz ? delimiter
                        SmartString("Param1-Name", "key1", max_len=50, fuzzable=True),
                        Delim("equals1", "=", fuzzable=True),  # Fuzz = delimiter
                        SmartString("Param1-Value", "val1", max_len=50, fuzzable=True),
                        Delim("param-sep", "&", fuzzable=True),  # Fuzz & delimiter
                        SmartString("Param2-Name", "key2", max_len=50, fuzzable=True),
                        Delim("equals2", "=", fuzzable=True),  # Fuzz = delimiter
                        SmartString("Param2-Value", "val2", max_len=50, fuzzable=True),
                        Delim("space-2", " ", fuzzable=True),  # Fuzz space before version
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host"),
                                Delim("host-colon", ": ", fuzzable=True),  # Fuzz colon-space
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "User-Agent",
                            children=(
                                Static("UA-Key", "User-Agent"),
                                Delim("ua-colon", ": ", fuzzable=True),  # Fuzz colon-space
                                SmartString(
                                    "UA-Value",
                                    "OIDA/1.0",
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Accept",
                            children=(
                                Static("Accept-Key", "Accept"),
                                Delim("accept-colon", ": ", fuzzable=True),  # Fuzz colon-space
                                SmartString("Accept-Value", "*/*", max_len=256, fuzzable=True),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
            ),
        )

        # ==================== KEEP SPECIAL CASE REQUESTS ====================
        # Keep requests with unique structures that can't be condensed into Groups

        # HTTP/0.9 Simple GET Request - Minimal HTTP protocol
        http09_get = Request(
            "HTTP_0_9_GET",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "GET"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            "/",
                            max_len=1000,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Static("CRLF", "\r\n"),  # No HTTP version in 0.9
                    ),
                ),
            ),
        )

        # PATCH Method Request - RFC 5789
        # CONNECT Method Request - HTTP tunneling
        # TRACE Method Request - Diagnostic method
        # Define POST request with multipart form data
        post_multipart = Request(
            "POST_Multipart",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/upload"),
                            max_len=1000,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Type",
                            children=(
                                Static("CT-Key", "Content-Type: "),
                                Static(
                                    "CT-Value",
                                    "multipart/form-data; boundary=---------------------------974767299852498929531610575",
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Length",
                            children=(
                                Static("CL-Key", "Content-Length: "),
                                Size("CL-Value", "Body", output_format="ascii"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "User-Agent",
                            children=(
                                Static("UA-Key", "User-Agent: "),
                                SmartString(
                                    "UA-Value",
                                    "Mozilla/5.0",
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                Block(
                    "Body",
                    children=(
                        SmartString(
                            "Body-Content",
                            "-----------------------------974767299852498929531610575\r\n"
                            + 'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
                            + "Content-Type: text/plain\r\n\r\n"
                            + "Test content for file upload\r\n"
                            + "-----------------------------974767299852498929531610575--\r\n",
                            max_len=16384,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # JSON Request
        json_req = Request(
            "JSON_Request",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/api/data"),
                            max_len=1000,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Type",
                            children=(
                                Static("CT-Key", "Content-Type: "),
                                Static("CT-Value", "application/json"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Length",
                            children=(
                                Static("CL-Key", "Content-Length: "),
                                Size("CL-Value", "Body", output_format="ascii"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Accept",
                            children=(
                                Static("Accept-Key", "Accept: "),
                                Static("Accept-Value", "application/json"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                Block(
                    "Body",
                    children=(
                        SmartString(
                            "Body-Content",
                            '{"key":"value","array":[1,2,3],"nested":{"prop":"val"}}',
                            max_len=8192,
                            fuzzable=True,
                        ),
                        Static("Body-End", "\r\n"),  # Proper HTTP message termination
                    ),
                ),
            ),
        )

        # HTTP Range Request - Partial content
        # HTTP Pipeline Testing - Multiple requests in one connection
        pipeline_request = Request(
            "Pipeline_Request",
            children=(
                Block(
                    "First-Request",
                    children=(
                        Static("Method1", "GET"),
                        Static("space1", " "),
                        SmartString(
                            "URI1",
                            "/page1.html",
                            max_len=100,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Static("space2", " "),
                        Static("HTTP-Version1", "HTTP/1.1"),
                        Static("CRLF1", "\r\n"),
                        Static("Host1", "Host: "),
                        SmartString(
                            "HostValue1",
                            self.config.target_ip,
                            max_len=100,
                            fuzzable=True,
                            context=StringContext.HOSTNAME,
                        ),
                        Static("CRLF2", "\r\n"),
                        Static("Connection1", "Connection: keep-alive\r\n"),
                        Static("End1", "\r\n"),
                    ),
                ),
                Block(
                    "Second-Request",
                    children=(
                        Static("Method2", "GET"),
                        Static("space3", " "),
                        SmartString(
                            "URI2",
                            "/page2.html",
                            max_len=100,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Static("space4", " "),
                        Static("HTTP-Version2", "HTTP/1.1"),
                        Static("CRLF3", "\r\n"),
                        Static("Host2", "Host: "),
                        SmartString(
                            "HostValue2",
                            self.config.target_ip,
                            max_len=100,
                            fuzzable=True,
                            context=StringContext.HOSTNAME,
                        ),
                        Static("CRLF4", "\r\n"),
                        Static("Connection2", "Connection: close\r\n"),
                        Static("End2", "\r\n"),
                    ),
                ),
            ),
        )

        # Chunked Encoding Request - Tests invalid chunk sizes and malformed chunked bodies
        chunked_request = Request(
            "HTTP_Chunked_Encoding",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/api/data"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Transfer-Encoding",
                            children=(
                                Static("TE-Key", "Transfer-Encoding: "),
                                Static("TE-Value", "chunked"),  # Not fuzzed - must be "chunked"
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Connection",
                            children=(
                                Static("Conn-Key", "Connection: "),
                                Static("Conn-Value", "close"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                # Chunked body with malformed chunks
                Block(
                    "Chunked-Body",
                    children=(
                        # First chunk with fuzzed size
                        SmartString(
                            "Chunk1-Size",
                            "a",  # hex length of the 10-byte "0123456789" chunk data
                            max_len=20,
                            fuzzable=True,
                            context=StringContext.NUMERIC,
                        ),  # Hex size (fuzzes to invalid: -1, FFFF, etc.)
                        Static("Chunk1-CRLF", "\r\n"),
                        SmartString(
                            "Chunk1-Data", "0123456789", max_len=100, fuzzable=True
                        ),  # Data (size mismatch possible)
                        Static("Chunk1-End-CRLF", "\r\n"),
                        # Second chunk
                        SmartString(
                            "Chunk2-Size",
                            "8",
                            max_len=20,
                            fuzzable=True,
                            context=StringContext.NUMERIC,
                        ),  # Hex size
                        Static("Chunk2-CRLF", "\r\n"),
                        SmartString("Chunk2-Data", "abcdefgh", max_len=100, fuzzable=True),  # Data
                        Static("Chunk2-End-CRLF", "\r\n"),
                        # Terminating chunk (size 0)
                        SmartString(
                            "Final-Chunk-Size",
                            "0",
                            max_len=10,
                            fuzzable=True,
                            context=StringContext.NUMERIC,
                        ),  # Should be "0", but fuzzable
                        Static("Final-CRLF", "\r\n"),
                        Static("Trailer-CRLF", "\r\n"),  # End of chunked body
                    ),
                ),
            ),
        )

        # DELETE Method Request - Resource deletion
        # PUT Method Request - Full resource replacement
        # HEAD Method Request - Identical to GET but without body
        # Used to retrieve headers only (Content-Length, Content-Type, etc.)
        # ==================== TRANSFORMER EXAMPLES ====================
        # These requests demonstrate field-level transformation using the
        # oida.fuzz.primitives.transformers module. Transformers encode
        # mutated data before sending (e.g., Base64, Gzip, JWT).

        # Example 1: Basic Authentication with proper encoding
        # Mutates username:password, then Base64-encodes automatically
        basic_auth_request = Request(
            "BasicAuth_Transformer",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "GET"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/secure"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Authorization: Basic <base64(username:password)>
                        # Transformer automatically encodes mutated credentials
                        Block(
                            "Authorization",
                            encoder=BasicAuthTransformer().to_encoder_func(),
                            children=(
                                SmartString(
                                    "username",
                                    "admin",
                                    max_len=64,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Delim("colon", ":"),
                                SmartString(
                                    "password",
                                    "password123",
                                    max_len=128,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                            ),
                        ),
                        Static("Auth-CRLF", "\r\n"),
                    ),
                ),
                Static("Headers-End", "\r\n"),
            ),
        )

        # Example 2: JWT Bearer Token Authentication
        # Generates JWT tokens with configurable algorithms and claims
        jwt_request = Request(
            "JWT_Transformer",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/api/protected"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Type",
                            children=(
                                Static("CT-Key", "Content-Type: "),
                                Static("CT-Value", "application/json"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Length",
                            children=(
                                Static("CL-Key", "Content-Length: "),
                                Size("CL-Value", "Body", output_format="ascii"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Authorization: Bearer <JWT-token>
                        # JWT transformer generates header.payload.signature with HMAC
                        Block(
                            "Authorization",
                            children=(
                                Static("Auth-Prefix", "Authorization: Bearer "),
                                Block(
                                    "JWT-Token",
                                    encoder=JWTTransformer(
                                        secret_key=b"secret", algorithm="HS256"
                                    ).to_encoder_func(),
                                    children=(
                                        SmartString(
                                            "subject",
                                            "user123",
                                            max_len=64,
                                            fuzzable=True,
                                            context=StringContext.CREDENTIAL,
                                        ),
                                    ),
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                Block(
                    "Body",
                    children=(
                        SmartString(
                            "Body-Content",
                            '{"action":"read","resource":"data"}',
                            max_len=4096,
                            fuzzable=True,
                        ),
                        Static("Body-End", "\r\n"),  # Proper HTTP message termination
                    ),
                ),
            ),
        )

        # Example 3: Gzip Compressed Body
        # Tests Content-Encoding: gzip with actual compression
        gzip_request = Request(
            "Gzip_Transformer",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/api/upload"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Type",
                            children=(
                                Static("CT-Key", "Content-Type: "),
                                Static("CT-Value", "application/json"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Encoding",
                            children=(
                                Static("CE-Key", "Content-Encoding: "),
                                Static("CE-Value", "gzip"),  # Declare gzip encoding
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Length",
                            children=(
                                Static("CL-Key", "Content-Length: "),
                                Size(
                                    "CL-Value", "Body", output_format="ascii"
                                ),  # Size of compressed data
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                # Body is mutated, then gzip-compressed automatically
                Block(
                    "Body",
                    encoder=GzipTransformer(level=9).to_encoder_func(),
                    children=(
                        SmartString(
                            "Body-Content",
                            '{"data":"' + "x" * 1000 + '"}',
                            max_len=8192,
                            fuzzable=True,
                        ),
                        Static("Body-End", "\r\n"),  # Proper HTTP message termination
                    ),
                ),
            ),
        )

        # Example 4: Transformer Chain - Gzip + Base64
        # Demonstrates chaining: data -> gzip -> base64
        chain_request = Request(
            "TransformerChain_Example",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "POST"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/api/binary"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Type",
                            children=(
                                Static("CT-Key", "Content-Type: "),
                                Static("CT-Value", "application/octet-stream"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Transfer-Encoding",
                            children=(
                                Static("CTE-Key", "Content-Transfer-Encoding: "),
                                Static("CTE-Value", "base64"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Content-Length",
                            children=(
                                Static("CL-Key", "Content-Length: "),
                                Size("CL-Value", "Body", output_format="ascii"),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
                # Chain: mutate -> gzip compress -> base64 encode
                Block(
                    "Body",
                    encoder=TransformerChain(
                        GzipTransformer(level=9), Base64Transformer()
                    ).to_encoder_func(),
                    children=(
                        SmartString(
                            "Body-Content",
                            "Compressed and encoded payload " * 50,
                            max_len=8192,
                            fuzzable=True,
                        ),
                        Static("Body-End", "\r\n"),  # Proper HTTP message termination
                    ),
                ),
            ),
        )

        # Example 5: URL-Encoded Query Parameters
        # Properly encodes special characters in URLs
        urlencoded_request = Request(
            "URLEncoded_Transformer",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Static("Method", "GET"),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/search"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("query-start", "?"),
                        # URL-encode the query parameter value
                        Static("param-name", "q="),
                        Block(
                            "param-value",
                            encoder=URLEncodeTransformer().to_encoder_func(),
                            children=(
                                SmartString(
                                    "search-query",
                                    "test & value with spaces",
                                    max_len=200,
                                    fuzzable=True,
                                ),
                            ),
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
            ),
        )

        # ==================== COOKIE FUZZING REQUEST ====================
        # Dedicated Cookie header fuzzing with proper syntax:
        # Cookie: name=value; name2=value2
        # Tests cookie parsing, attribute handling, and injection vectors
        cookie_request = Request(
            "Cookie_Fuzzing",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Group("Method", values=["GET", "POST", "PUT", "DELETE", "HEAD"]),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            self._get_url_path("/dashboard"),
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Primary Cookie header with multiple cookies
                        Block(
                            "Cookie",
                            children=(
                                Static("Cookie-Key", "Cookie: "),
                                # First cookie (session identifier)
                                SmartString("Cookie1-Name", "session", max_len=64, fuzzable=True),
                                Delim("equals1", "="),
                                SmartString(
                                    "Cookie1-Value",
                                    "abc123def456",
                                    max_len=4096,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Delim("semi1", "; "),
                                # Second cookie (auth token)
                                SmartString(
                                    "Cookie2-Name",
                                    "auth_token",
                                    max_len=64,
                                    fuzzable=True,
                                ),
                                Delim("equals2", "="),
                                SmartString(
                                    "Cookie2-Value",
                                    "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ",
                                    max_len=4096,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Delim("semi2", "; "),
                                # Third cookie (preferences)
                                SmartString("Cookie3-Name", "prefs", max_len=64, fuzzable=True),
                                Delim("equals3", "="),
                                SmartString(
                                    "Cookie3-Value",
                                    "lang=en&theme=dark",
                                    max_len=1024,
                                    fuzzable=True,
                                ),
                                Delim("semi3", "; "),
                                # Fourth cookie (CSRF token)
                                SmartString(
                                    "Cookie4-Name",
                                    "csrf_token",
                                    max_len=64,
                                    fuzzable=True,
                                ),
                                Delim("equals4", "="),
                                SmartString(
                                    "Cookie4-Value",
                                    "x8f2k9d3m5n7",
                                    max_len=256,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Second Cookie header (tests duplicate header handling)
                        Block(
                            "Cookie2",
                            children=(
                                Static("Cookie2-Key", "Cookie: "),
                                SmartString(
                                    "Cookie5-Name",
                                    "tracking_id",
                                    max_len=64,
                                    fuzzable=True,
                                ),
                                Delim("equals5", "="),
                                SmartString(
                                    "Cookie5-Value",
                                    "uuid-1234-5678-abcd",
                                    max_len=512,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
            ),
        )

        # ==================== USER-AGENT FUZZING REQUEST ====================
        # Dedicated User-Agent fuzzing with browser fingerprint patterns
        # Tests UA parsing, bot detection bypass, and injection vectors
        USERAGENT_PATTERNS = [
            # Desktop browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
            # Mobile browsers
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            # Bots and crawlers
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "curl/8.4.0",
            "Wget/1.21",
            "python-requests/2.31.0",
            # Legacy/exotic
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            "Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18",
            # Injection test patterns
            "Mozilla/5.0 <script>alert(1)</script>",
            "Mozilla/5.0\r\nX-Injected: header",
            "Mozilla/5.0'; DROP TABLE users;--",
        ]

        useragent_request = Request(
            "UserAgent_Fuzzing",
            children=(
                Block(
                    "Request-Line",
                    children=(
                        Group("Method", values=["GET", "POST", "HEAD"]),
                        Delim("space-1", " "),
                        SmartString(
                            "URI-Path",
                            "/",
                            max_len=500,
                            fuzzable=True,
                            context=StringContext.PATH,
                        ),
                        Delim("space-2", " "),
                        Static("HTTP-Version", "HTTP/1.1"),
                        Static("CRLF", "\r\n"),
                    ),
                ),
                Block(
                    "Headers",
                    children=(
                        Block(
                            "Host",
                            children=(
                                Static("Host-Key", "Host: "),
                                SmartString(
                                    "Host-Value",
                                    self.config.target_ip,
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # User-Agent with pattern cycling + value fuzzing
                        Block(
                            "UserAgent",
                            children=(
                                Static("UA-Key", "User-Agent: "),
                                Group("UA-Pattern", values=USERAGENT_PATTERNS),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Additional User-Agent with full fuzzing (mutation-based)
                        Block(
                            "UserAgent-Fuzzed",
                            children=(
                                Static("UA2-Key", "User-Agent: "),
                                SmartString(
                                    "UA-Value",
                                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                                    max_len=4096,
                                    fuzzable=True,
                                    radamsa_mutation_count=500,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        # Client hints (modern browsers)
                        Block(
                            "Sec-CH-UA",
                            children=(
                                Static("CH-Key", "Sec-CH-UA: "),
                                SmartString(
                                    "CH-Value",
                                    '"Chromium";v="120", "Google Chrome";v="120"',
                                    max_len=512,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Sec-CH-UA-Platform",
                            children=(
                                Static("Platform-Key", "Sec-CH-UA-Platform: "),
                                SmartString(
                                    "Platform-Value",
                                    '"Windows"',
                                    max_len=64,
                                    fuzzable=True,
                                ),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                        Block(
                            "Sec-CH-UA-Mobile",
                            children=(
                                Static("Mobile-Key", "Sec-CH-UA-Mobile: "),
                                SmartString("Mobile-Value", "?0", max_len=16, fuzzable=True),
                                Static("CRLF", "\r\n"),
                            ),
                        ),
                    ),
                ),
                Static("Headers-End", "\r\n"),
            ),
        )

        # ==================== CONNECT REQUESTS (Ordered by Coverage Priority) ====================
        # Order optimized for maximum coverage: baseline -> common patterns -> slow edge cases
        # Use --enable or --disable CLI flags to select specific requests

        # 0. BASELINE - Simple connectivity test (FASTEST - catches basic issues)
        if self.is_request_enabled("HTTP_Baseline"):
            self.session.connect(baseline_request)

        # 1. CORE FUZZING - Broadest coverage (FAST - single headers)
        if self.is_request_enabled("HTTP_Unified_Standard"):
            self.session.connect(unified_request)

        # 2. VERY COMMON - High-frequency patterns in production (requires POST support)
        if self.is_request_enabled("POST_Multipart") and "POST" in self.http_methods:
            self.session.connect(post_multipart)
        elif self.is_request_enabled("POST_Multipart"):
            self.log.display("Skipping POST_Multipart (POST method not supported by server)")
        if self.is_request_enabled("JSON_Request") and "POST" in self.http_methods:
            self.session.connect(json_req)
        elif self.is_request_enabled("JSON_Request"):
            self.log.display("Skipping JSON_Request (POST method not supported by server)")

        # 3. COMMON - Frequently seen on web servers
        # Only fuzz special methods if any are supported
        if self.is_request_enabled("HTTP_Special_Methods") and special_methods_request:
            self.session.connect(special_methods_request)
        elif self.is_request_enabled("HTTP_Special_Methods"):
            self.log.display("Skipping HTTP_Special_Methods (none supported by server)")

        # Only fuzz WebDAV if server supports it (or enumeration is disabled)
        if self.is_request_enabled("WebDAV_Methods") and webdav_request and self._supports_webdav():
            self.session.connect(webdav_request)
        elif self.is_request_enabled("WebDAV_Methods"):
            self.log.display("Skipping WebDAV_Methods (not supported by server)")

        # 4. IMPORTANT EDGE CASES - Protocol-level vulnerabilities
        if self.is_request_enabled("HTTP_Chunked_Encoding") and "POST" in self.http_methods:
            self.session.connect(chunked_request)
        elif self.is_request_enabled("HTTP_Chunked_Encoding"):
            self.log.display("Skipping HTTP_Chunked_Encoding (POST method not supported by server)")
        if self.is_request_enabled("Pipeline_Request"):
            self.session.connect(pipeline_request)

        # 5. DUPLICATE HEADER TESTING - Edge case (SLOW)
        if self.is_request_enabled("HTTP_Duplicate_Headers") and "POST" in self.http_methods:
            self.session.connect(duplicate_headers_request)
        elif self.is_request_enabled("HTTP_Duplicate_Headers"):
            self.log.display(
                "Skipping HTTP_Duplicate_Headers (POST method not supported by server)"
            )

        # 6. DELIMITER FUZZING - Malformed delimiter testing (SLOW)
        if self.is_request_enabled("HTTP_Delimiter_Fuzzing"):
            self.session.connect(delimiter_fuzzing_request)

        # 7. HEADER-SPECIFIC FUZZING - Dedicated Cookie and User-Agent testing
        if self.is_request_enabled("Cookie_Fuzzing"):
            self.session.connect(cookie_request)
        if self.is_request_enabled("UserAgent_Fuzzing"):
            self.session.connect(useragent_request)

        # 8. TRANSFORMER EXAMPLES - Demonstrates field-level encoding
        if self.is_request_enabled("BasicAuth_Transformer"):
            self.session.connect(basic_auth_request)
        if self.is_request_enabled("JWT_Transformer") and "POST" in self.http_methods:
            self.session.connect(jwt_request)
        elif self.is_request_enabled("JWT_Transformer"):
            self.log.display("Skipping JWT_Transformer (POST method not supported by server)")
        if self.is_request_enabled("Gzip_Transformer") and "POST" in self.http_methods:
            self.session.connect(gzip_request)
        elif self.is_request_enabled("Gzip_Transformer"):
            self.log.display("Skipping Gzip_Transformer (POST method not supported by server)")
        if self.is_request_enabled("TransformerChain_Example") and "POST" in self.http_methods:
            self.session.connect(chain_request)
        elif self.is_request_enabled("TransformerChain_Example"):
            self.log.display(
                "Skipping TransformerChain_Example (POST method not supported by server)"
            )
        if self.is_request_enabled("URLEncoded_Transformer"):
            self.session.connect(urlencoded_request)

        # 9. LEGACY - HTTP/0.9 rarely used, run last
        if self.is_request_enabled("HTTP_0_9_GET"):
            self.session.connect(http09_get)

        return self.session

    def setup_custom_monitors(self) -> list:
        """
        Setup HTTP-specific monitoring with GET request comparison.

        Returns:
            List of monitor instances for HTTP service health checking
        """
        from oida.fuzz.monitors import HTTPGetMonitor

        # Create HTTP GET monitor with default settings
        http_monitor = HTTPGetMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            path="/",  # Default path, can be customized
            use_ssl=False,  # Set to True for HTTPS monitoring
            timeout=2,
            check_interval=3,  # Check every 3 test cases
            compare_body=True,
            compare_size_threshold=50,  # 50% size difference triggers failure
        )

        return [http_monitor]

    def _define_state_machine(self) -> None:
        """
        Define HTTP connection state machine

        States:
        - DISCONNECTED: No connection
        - CONNECTED: TCP connection established
        - REQUEST_SENT: HTTP request transmitted
        - RESPONSE_RECEIVED: Server responded
        - PERSISTENT: Keep-alive connection active
        - AUTHENTICATED: For auth-required resources
        """
        from oida.fuzz.core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
            TransitionRule,
        )

        # Define HTTP states

        disconnected = ProtocolState(
            name="DISCONNECTED",
            state_type=StateType.CONNECTION,
            description="No HTTP connection active",
        )

        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            requires=[
                "DISCONNECTED",
                "RESPONSE_RECEIVED",
            ],  # Can reconnect after response
            description="TCP connection established to HTTP server",
        )

        request_sent = ProtocolState(
            name="REQUEST_SENT",
            state_type=StateType.TRANSACTION,
            requires=["CONNECTED", "PERSISTENT"],
            timeout=30.0,  # Request timeout
            timeout_callback=lambda: self.log.warning(
                "HTTP request timeout - no response received"
            ),
            description="HTTP request transmitted, waiting for response",
        )

        response_received = ProtocolState(
            name="RESPONSE_RECEIVED",
            state_type=StateType.TRANSACTION,
            requires=["REQUEST_SENT"],
            description="HTTP response received from server",
        )

        persistent = ProtocolState(
            name="PERSISTENT",
            state_type=StateType.SESSION,
            requires=["RESPONSE_RECEIVED"],
            description="Keep-alive connection active, can send more requests",
        )

        authenticated = ProtocolState(
            name="AUTHENTICATED",
            state_type=StateType.AUTHENTICATION,
            requires=["RESPONSE_RECEIVED", "PERSISTENT"],
            description="Successfully authenticated (received 200 after 401)",
        )

        # Define transition rules
        transitions = [
            TransitionRule(
                from_state="DISCONNECTED",
                to_state="CONNECTED",
                description="Establish TCP connection",
            ),
            TransitionRule(
                from_state="CONNECTED",
                to_state="REQUEST_SENT",
                description="Send HTTP request",
            ),
            TransitionRule(
                from_state="REQUEST_SENT",
                to_state="RESPONSE_RECEIVED",
                description="Receive HTTP response",
            ),
            TransitionRule(
                from_state="RESPONSE_RECEIVED",
                to_state="PERSISTENT",
                description="Connection has Keep-Alive header",
            ),
            TransitionRule(
                from_state="RESPONSE_RECEIVED",
                to_state="AUTHENTICATED",
                description="Successful authentication (200 after providing credentials)",
            ),
            TransitionRule(
                from_state="RESPONSE_RECEIVED",
                to_state="DISCONNECTED",
                description="Connection close (no Keep-Alive or Connection: close)",
            ),
            TransitionRule(
                from_state="PERSISTENT",
                to_state="REQUEST_SENT",
                description="Send another request on persistent connection",
            ),
            TransitionRule(
                from_state="PERSISTENT",
                to_state="DISCONNECTED",
                description="Close persistent connection",
            ),
            TransitionRule(
                from_state="AUTHENTICATED",
                to_state="REQUEST_SENT",
                description="Send authenticated request",
            ),
            TransitionRule(
                from_state="AUTHENTICATED",
                to_state="DISCONNECTED",
                description="Close authenticated session",
            ),
        ]

        # Create state machine (starts in DISCONNECTED)
        self.state_machine = StateMachine(
            initial_state=disconnected,
            states=[
                disconnected,
                connected,
                request_sent,
                response_received,
                persistent,
                authenticated,
            ],
            transitions=transitions,
            allow_invalid_transitions=False,  # Enforce valid HTTP state transitions
        )

        self.log.display(
            f"HTTP state machine initialized in {self.state_machine.get_current_state_name()} state"
        )

    def handle_response(self, status_code: int = 200, has_keep_alive: bool = False):
        """
        Handle HTTP response

        Args:
            status_code: HTTP status code (200, 401, etc.)
            has_keep_alive: Whether Connection: keep-alive header present
        """
        if not self.state_machine:
            return

        current = self.state_machine.get_current_state_name()
        if current == "REQUEST_SENT":
            self.state_machine.transition_to("RESPONSE_RECEIVED")

            # Determine next state based on response
            if status_code == 200 and has_keep_alive:
                self.state_machine.transition_to("PERSISTENT")
                self.log.display("HTTP: Keep-alive connection active")
            elif status_code == 200:
                # Check if we were trying to authenticate
                prev_state = self.state_machine.get_state_history()
                if len(prev_state) > 2 and "AUTHENTICATED" not in prev_state:
                    self.state_machine.transition_to("AUTHENTICATED")
                    self.log.display("HTTP: Authentication successful")

    def close_connection(self):
        """Close HTTP connection - return to DISCONNECTED"""
        if self.state_machine:
            current = self.state_machine.get_current_state_name()
            if current != "DISCONNECTED":
                self.state_machine.transition_to("DISCONNECTED", force=True)
                self.log.display("HTTP: Connection closed")
