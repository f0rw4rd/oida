"""
HTTP Passive Listener for network discovery and credential extraction.

Passively captures HTTP traffic to identify:
- Web servers and their technology stacks
- HTTP clients and their user agents
- Virtual hosts being accessed
- Authentication methods in use
- HTTP Basic credentials (plaintext)
- HTTP Digest authentication hashes

Extracts from responses:
- Server header (Apache, nginx, IIS, etc.)
- X-Powered-By header (PHP, ASP.NET, etc.)
- WWW-Authenticate header (auth methods)
- Content-Type

Extracts from requests:
- User-Agent header
- Host header
- Authorization header (Basic and Digest credentials)

Based on BruteShark's HttpBasicPasswordParser and HttpDigestHashParser.
Uses PyShark for packet dissection with Wireshark's HTTP dissector.
"""

import base64
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from .pyshark_base import ProtocolInteraction, PySharkListenerBase


@dataclass
class HTTPCredential:
    """Extracted HTTP credential."""

    auth_type: str  # "Basic" or "Digest"
    credential_type: str  # "plaintext" or "hash"
    username: str
    password: str = ""  # For Basic auth
    # Digest auth fields
    realm: str = ""
    nonce: str = ""
    uri: str = ""
    qop: str = ""
    nc: str = ""
    cnonce: str = ""
    response: str = ""  # The hash/response
    method: str = ""  # HTTP method (GET, POST, etc.)
    algorithm: str = ""
    # Network info
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return f"HTTP-{self.auth_type}"

    @property
    def hash_value(self) -> str:
        """Digest response hash for scanner loop."""
        return self.response

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string (mode 11400)."""
        if self.auth_type == "Digest":
            return (
                f"$digest-md5${self.realm}${self.username}${self.method}${self.uri}$"
                f"{self.nonce}${self.nc}${self.cnonce}${self.qop}${self.response}"
            )
        return ""


@dataclass
class HTTPEndpoint:
    """Tracked HTTP endpoint (unique per method+path per server)."""

    method: str  # GET, POST, PUT, etc.
    path: str  # URI path without query string
    params: Set[str] = field(default_factory=set)  # query parameter names only
    status_codes: Counter = field(default_factory=Counter)  # response_code -> count
    hit_count: int = 0
    content_types: Set[str] = field(default_factory=set)  # response content types seen


class HTTPPassiveListener(PySharkListenerBase):
    """Passive HTTP traffic listener using PyShark.

    Captures HTTP traffic to identify web servers, clients, and their technologies.
    Uses PyShark with Wireshark's HTTP dissector for field extraction.

    Usage:
        # Live capture
        listener = HTTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Testing - feed packets directly
        listener = HTTPPassiveListener(interface="eth0")
        listener.feed_packet(mock_http_packet)
    """

    PROTOCOL_NAME = "http"
    DISPLAY_FILTER = "http"
    REQUIRED_LAYERS = ("http",)

    PROTOCOL_COLUMNS = ("method", "host", "path", "status", "content_type")

    # Regex patterns for parsing Digest authorization header values
    DIGEST_FIELD_REGEX = re.compile(r'(\w+)=(?:"([^"]+)"|([^,\s]+))')

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(
            interface=interface,
            timeout=timeout,
            nxc_logger=nxc_logger,
        )
        # Track servers and clients separately
        self._servers: Dict[str, Dict] = {}  # IP -> server info
        self._clients: Dict[str, Dict] = {}  # IP -> client info

        # Extracted credentials
        self.credentials: List[HTTPCredential] = []

        # URL map: (server_ip, server_port) -> {(method, path): HTTPEndpoint}
        self._url_map: Dict[Tuple[str, int], Dict[Tuple[str, str], HTTPEndpoint]] = {}

        # Pending requests for response correlation: (client_ip, server_ip, server_port) -> (method, path)
        self._pending_requests: Dict[Tuple[str, str, int], Tuple[str, str]] = {}

    def process_packet(self, packet) -> None:
        """Process captured HTTP packet using PyShark's HTTP dissector."""
        if not hasattr(packet, "http"):
            return

        http_layer = packet.http
        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)

        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Detect if this is a request or response
        # PyShark exposes http.request or http.response fields
        request_method = self.get_field(http_layer, "request_method", None)
        response_code = self.get_field(http_layer, "response_code", None)

        if request_method:
            # This is an HTTP request
            host = self.get_field(http_layer, "host", "") or ""
            uri = self.get_field(http_layer, "request_uri", "") or ""
            request_version = self.get_field(http_layer, "request_version", "") or ""
            if not request_version:
                request_version = "?"
                self.logger.debug(
                    f"Missing request_version in HTTP request from {src_ip} -> {dst_ip}"
                )
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                f"{request_method} Request",
                {
                    "method": request_method,
                    "host": host,
                    "path": uri,
                    "http_version": request_version,
                },
                f"{request_method} {host}{uri}" if host else f"{request_method} {uri}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            self._process_http_request(
                client_ip=src_ip,
                server_ip=dst_ip,
                server_port=dst_port,
                http_layer=http_layer,
                request_method=request_method,
            )
        elif response_code:
            # This is an HTTP response
            content_type = self.get_field(http_layer, "content_type", "") or ""
            response_version = self.get_field(http_layer, "response_version", "") or ""
            if not response_version:
                response_version = "?"
                self.logger.debug(
                    f"Missing response_version in HTTP response from {src_ip} -> {dst_ip}"
                )
            response_code_desc = self.get_field(http_layer, "response_code_desc", "") or ""
            if not response_code_desc:
                response_code_desc = "?"
                self.logger.debug(
                    f"Missing response_code_desc for HTTP {response_code} from {src_ip}"
                )
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                f"HTTP {response_code} {response_code_desc}",
                {
                    "response_code": response_code,
                    "response_code_desc": response_code_desc,
                    "content_type": content_type,
                    "http_version": response_version,
                },
                (
                    f"{response_version} {response_code} {response_code_desc}"
                    + (f" ({content_type})" if content_type else "")
                ),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            self._process_http_response(
                server_ip=src_ip,
                client_ip=dst_ip,
                server_port=src_port,
                http_layer=http_layer,
            )
        else:
            # HTTP-layer packet with no request method and no response code.
            # These are typically TCP continuation segments carrying HTTP body
            # data (file_data), or intermediate NTLM/auth negotiation frames
            # that tshark still tags with the "http" display filter.
            now = datetime.now().isoformat()
            # Try to determine data length for the summary
            file_data = self.get_field(http_layer, "file_data", None)
            data_len = ""
            if file_data is not None:
                # EK mode returns bytes as hex-colon string
                if isinstance(file_data, str) and ":" in file_data:
                    data_len = str(file_data.count(":") + 1)
                elif isinstance(file_data, bytes):
                    data_len = str(len(file_data))
            content_length = self.get_field(http_layer, "content_length", "") or ""
            summary_parts = ["HTTP continuation"]
            if data_len:
                summary_parts.append(f"({data_len} bytes)")
            elif content_length:
                summary_parts.append(f"(content-length {content_length})")

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",  # continuations are server->client body data
                "HTTP Data",
                {
                    "data_length": data_len or content_length or "?",
                },
                " ".join(summary_parts),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

    @staticmethod
    def _parse_uri(uri: str) -> Tuple[str, List[str]]:
        """Split URI into (path, param_names).

        E.g. /api/v1/devices?id=5&page=2 -> ("/api/v1/devices", ["id", "page"])
        """
        try:
            parsed = urlparse(uri)
            path = parsed.path or "/"
            param_names = list(parse_qs(parsed.query).keys())
        except Exception:
            path = uri.split("?", 1)[0] or "/"
            param_names = []
        return path, param_names

    def _process_http_response(
        self, server_ip: str, client_ip: str, server_port: int, http_layer
    ) -> None:
        """Process HTTP response and extract server info."""
        # Extract fields from PyShark HTTP layer
        server_banner = self.get_field(http_layer, "server", "") or ""
        x_powered_by = self.get_field(http_layer, "x_powered_by", "") or ""
        content_type = self.get_field(http_layer, "content_type", "") or ""
        www_auth = self.get_field(http_layer, "www_authenticate", "") or ""

        # Extract response code and its description for endpoint correlation
        response_code = self.get_field(http_layer, "response_code", "") or ""
        response_code_desc = self.get_field(http_layer, "response_code_desc", "") or ""
        response_version = self.get_field(http_layer, "response_version", "") or ""

        # Extract technologies from headers
        technologies = self._extract_technologies(server_banner, x_powered_by)

        # Extract auth methods
        auth_methods = self._extract_auth_methods(www_auth)

        # Correlate response with pending request to update endpoint
        req_key = (client_ip, server_ip, server_port)
        pending = self._pending_requests.pop(req_key, None)
        if pending and response_code:
            method, path = pending
            server_key = (server_ip, server_port)
            ep_key = (method, path)
            endpoints = self._url_map.get(server_key, {})
            ep = endpoints.get(ep_key)
            if ep:
                code_label = (
                    f"{response_code} {response_code_desc}" if response_code_desc else response_code
                )
                ep.status_codes[code_label] += 1
                if content_type:
                    ep.content_types.add(content_type)

        device_key = f"http-server:{server_ip}"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            name=f"HTTP Server ({server_banner})" if server_banner else "HTTP Server",
            device_type="Web Server",
        )
        if is_new:
            device.http_passive_data = {
                "role": "server",
                "server_banner": server_banner,
                "x_powered_by": x_powered_by,
                "technologies": technologies,
                "virtual_hosts": [],
                "auth_methods": auth_methods,
                "user_agents": [],
                "content_types": [content_type] if content_type else [],
                "ports": [server_port],
                "protocol": "HTTP/TCP",
                "http_versions": [response_version] if response_version else [],
            }

            self._servers[server_ip] = device.http_passive_data

            self.logger.debug(
                f"HTTP Server: {server_ip}:{server_port} Server={server_banner or 'unknown'}"
            )
        else:
            # Update existing server info

            if device.http_passive_data:
                # Add new content types
                if content_type and content_type not in device.http_passive_data.get(
                    "content_types", []
                ):
                    device.http_passive_data.setdefault("content_types", []).append(content_type)

                # Add new auth methods
                for method in auth_methods:
                    if method not in device.http_passive_data.get("auth_methods", []):
                        device.http_passive_data.setdefault("auth_methods", []).append(method)

                # Add new ports
                if server_port not in device.http_passive_data.get("ports", []):
                    device.http_passive_data.setdefault("ports", []).append(server_port)

                # Update server banner if not set
                if server_banner and not device.http_passive_data.get("server_banner"):
                    device.http_passive_data["server_banner"] = server_banner

                # Add technologies
                for tech in technologies:
                    if tech not in device.http_passive_data.get("technologies", []):
                        device.http_passive_data.setdefault("technologies", []).append(tech)

                # Track HTTP versions
                if response_version and response_version not in device.http_passive_data.get(
                    "http_versions", []
                ):
                    device.http_passive_data.setdefault("http_versions", []).append(
                        response_version
                    )

    def _process_http_request(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        http_layer,
        request_method: str,
    ) -> None:
        """Process HTTP request and extract client info and credentials."""
        # Extract fields from PyShark HTTP layer
        user_agent = self.get_field(http_layer, "user_agent", "") or ""
        host = self.get_field(http_layer, "host", "") or ""
        authorization = self.get_field(http_layer, "authorization", "") or ""
        request_version = self.get_field(http_layer, "request_version", "") or ""

        # tshark pre-decodes Basic auth into http.authbasic ("user:pass")
        authbasic = self.get_field(http_layer, "authbasic", "") or ""

        # Try to extract credentials from Authorization header
        if authorization:
            self._try_extract_credentials(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                authorization=authorization,
                method=request_method,
                authbasic=authbasic,
            )

        # Track endpoint in URL map
        uri = self.get_field(http_layer, "request_uri", "") or "/"
        path, param_names = self._parse_uri(uri)
        server_key = (server_ip, server_port)
        ep_key = (request_method, path)

        if server_key not in self._url_map:
            self._url_map[server_key] = {}

        endpoints = self._url_map[server_key]
        if ep_key not in endpoints:
            endpoints[ep_key] = HTTPEndpoint(method=request_method, path=path)

        ep = endpoints[ep_key]
        ep.hit_count += 1
        ep.params.update(param_names)

        # Store pending request for response correlation
        self._pending_requests[(client_ip, server_ip, server_port)] = (request_method, path)

        # Track client
        client_key = f"http-client:{client_ip}"

        device, is_new = self._ensure_device(
            client_key,
            client_ip,
            name="HTTP Client",
            device_type="HTTP Client",
        )
        if is_new:
            device.http_passive_data = {
                "role": "client",
                "server_banner": "",
                "x_powered_by": "",
                "technologies": [],
                "virtual_hosts": [],
                "auth_methods": [],
                "user_agents": [user_agent] if user_agent else [],
                "protocol": "HTTP/TCP",
                "http_versions": [request_version] if request_version else [],
            }

            self._clients[client_ip] = device.http_passive_data

            self.logger.debug(
                f"HTTP Client: {client_ip} UA={user_agent if user_agent else 'unknown'}"
            )
        else:
            if device.http_passive_data and user_agent:
                if user_agent not in device.http_passive_data.get("user_agents", []):
                    device.http_passive_data.setdefault("user_agents", []).append(user_agent)
            if device.http_passive_data and request_version:
                if request_version not in device.http_passive_data.get("http_versions", []):
                    device.http_passive_data.setdefault("http_versions", []).append(request_version)
        # Update server with virtual host info
        server_key = f"http-server:{server_ip}"
        if server_key in self.discovered_devices:
            server_device = self.discovered_devices[server_key]
            if server_device.http_passive_data and host:
                if host not in server_device.http_passive_data.get("virtual_hosts", []):
                    server_device.http_passive_data.setdefault("virtual_hosts", []).append(host)

    def _try_extract_credentials(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        authorization: str,
        method: str,
        authbasic: str = "",
    ) -> None:
        """Extract credentials from Authorization header."""
        auth_lower = authorization.lower()

        if auth_lower.startswith("basic "):
            self._extract_basic_auth(
                client_ip, server_ip, server_port, authorization, authbasic=authbasic
            )
        elif auth_lower.startswith("digest "):
            self._extract_digest_auth(client_ip, server_ip, server_port, authorization, method)

    def _extract_basic_auth(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        authorization: str,
        authbasic: str = "",
    ) -> None:
        """Extract HTTP Basic authentication credentials.

        Basic auth format: Basic base64(username:password)
        Also uses tshark's pre-decoded http.authbasic field as fallback.
        """
        decoded = ""
        try:
            # Remove "Basic " prefix and decode base64
            b64_creds = authorization[6:].strip()
            decoded = base64.b64decode(b64_creds).decode("utf-8", errors="ignore")
        except Exception as e:
            self.logger.debug(f"HTTP Basic auth base64 decode error: {e}")

        # Fall back to tshark's pre-decoded authbasic field
        if not decoded and authbasic:
            decoded = authbasic
            self.logger.debug(f"Using tshark authbasic field for {client_ip} -> {server_ip}")

        if decoded and ":" in decoded:
            username, password = decoded.split(":", 1)

            # Check for duplicate
            if self._is_duplicate_credential("Basic", username, password, server_ip):
                return

            cred = HTTPCredential(
                auth_type="Basic",
                credential_type="plaintext",
                username=username,
                password=password,
                server_ip=server_ip,
                server_port=server_port,
                client_ip=client_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)

            self.logger.info(f"HTTP Basic Auth: {username}:{password} @ {server_ip}:{server_port}")

    def _extract_digest_auth(
        self, client_ip: str, server_ip: str, server_port: int, authorization: str, method: str
    ) -> None:
        """Extract HTTP Digest authentication hash.

        Digest auth format: Digest username="user", realm="...", ...
        """
        try:
            # Remove "Digest " prefix
            header_data = authorization[7:].strip()

            # Parse digest header fields
            digest_parts = self._parse_digest_header(header_data)

            username = digest_parts.get("username", "")
            if not username:
                return

            response = digest_parts.get("response", "")
            if not response:
                return

            # Check for duplicate
            if self._is_duplicate_digest(username, response, server_ip):
                return

            cred = HTTPCredential(
                auth_type="Digest",
                credential_type="hash",
                username=username,
                realm=digest_parts.get("realm", ""),
                nonce=digest_parts.get("nonce", ""),
                uri=digest_parts.get("uri", ""),
                qop=digest_parts.get("qop", ""),
                nc=digest_parts.get("nc", ""),
                cnonce=digest_parts.get("cnonce", ""),
                response=response,
                method=method,
                algorithm=digest_parts.get("algorithm", "MD5"),
                server_ip=server_ip,
                server_port=server_port,
                client_ip=client_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)

            self.logger.info(
                f"HTTP Digest Auth: {username} @ {server_ip}:{server_port} (realm={cred.realm})"
            )
        except Exception as e:
            self.logger.debug(f"HTTP Digest auth parse error: {e}")

    def _parse_digest_header(self, header_data: str) -> Dict[str, str]:
        """Parse HTTP Digest authorization header fields.

        Example: username="user", realm="test", nonce="abc", uri="/", response="hash"
        """
        result = {}
        try:
            # Split by comma, but handle quoted values
            parts = self.DIGEST_FIELD_REGEX.findall(header_data)
            for key, quoted_val, unquoted_val in parts:
                result[key.lower()] = quoted_val or unquoted_val
        except Exception as e:
            self.logger.debug(f"Digest header parse error: {e}")
        return result

    def _extract_technologies(self, server_banner: str, x_powered_by: str) -> List[str]:
        """Extract technology names from server headers."""
        technologies = []

        # Common server software patterns
        server_patterns = {
            "apache": "Apache",
            "nginx": "nginx",
            "iis": "IIS",
            "lighttpd": "lighttpd",
            "tomcat": "Tomcat",
            "jetty": "Jetty",
            "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn",
            "node": "Node.js",
            "express": "Express",
            "openresty": "OpenResty",
            "caddy": "Caddy",
            "haproxy": "HAProxy",
            "cloudflare": "Cloudflare",
        }

        # X-Powered-By patterns
        powered_by_patterns = {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "servlet": "Java Servlet",
            "express": "Express",
            "django": "Django",
            "flask": "Flask",
            "rails": "Ruby on Rails",
            "laravel": "Laravel",
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
        }

        # Check server banner
        server_lower = server_banner.lower()
        for pattern, tech in server_patterns.items():
            if pattern in server_lower:
                technologies.append(tech)

        # Check X-Powered-By
        powered_lower = x_powered_by.lower()
        for pattern, tech in powered_by_patterns.items():
            if pattern in powered_lower:
                technologies.append(tech)

        return list(set(technologies))  # Remove duplicates

    def _extract_auth_methods(self, www_auth: str) -> List[str]:
        """Extract authentication methods from WWW-Authenticate header."""
        if not www_auth:
            return []

        methods = []
        auth_lower = www_auth.lower()

        # Common auth methods
        if "basic" in auth_lower:
            methods.append("Basic")
        if "digest" in auth_lower:
            methods.append("Digest")
        if "ntlm" in auth_lower:
            methods.append("NTLM")
        if "negotiate" in auth_lower:
            methods.append("Negotiate")
        if "bearer" in auth_lower:
            methods.append("Bearer")
        if "oauth" in auth_lower:
            methods.append("OAuth")

        return methods

    def _is_duplicate_credential(
        self, auth_type: str, username: str, password: str, server_ip: str
    ) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.auth_type == auth_type
                and cred.username == username
                and cred.password == password
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def _is_duplicate_digest(self, username: str, response: str, server_ip: str) -> bool:
        """Check if digest hash is already recorded."""
        for cred in self.credentials:
            if (
                cred.auth_type == "Digest"
                and cred.username == username
                and cred.response == response
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials using canonical key names."""
        result = []
        for cred in self.credentials:
            entry: Dict[str, Any] = {
                "protocol": "HTTP",
                "auth_method": f"HTTP-{cred.auth_type}",
                "credential_type": cred.credential_type,
                "username": cred.username,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            if cred.auth_type == "Basic":
                entry["password"] = cred.password
            else:
                entry["realm"] = cred.realm
                entry["nonce"] = cred.nonce
                entry["uri"] = cred.uri
                entry["qop"] = cred.qop
                entry["nc"] = cred.nc
                entry["cnonce"] = cred.cnonce
                entry["response"] = cred.response
                entry["method"] = cred.method
                entry["algorithm"] = cred.algorithm
            result.append(entry)
        return result

    def get_hashcat_hashes(self) -> List[str]:
        """Get HTTP Digest hashes in hashcat-compatible format.

        Hashcat mode 11400: HTTP Digest authentication.
        Format: $digest-md5$realm$user$method$uri$nonce$nc$cnonce$qop$response
        """
        result = []
        for cred in self.credentials:
            if cred.auth_type == "Digest":
                # Format for hashcat
                result.append(
                    f"$digest-md5${cred.realm}${cred.username}${cred.method}${cred.uri}$"
                    f"{cred.nonce}${cred.nc}${cred.cnonce}${cred.qop}${cred.response}"
                )
        return result

    def get_url_map(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get URL map: "ip:port" -> list of endpoint dicts sorted by hit_count desc."""
        result: Dict[str, List[Dict[str, Any]]] = {}
        for (ip, port), endpoints in self._url_map.items():
            key = f"{ip}:{port}"
            ep_list = []
            for ep in sorted(endpoints.values(), key=lambda e: e.hit_count, reverse=True):
                ep_list.append(
                    {
                        "method": ep.method,
                        "path": ep.path,
                        "params": sorted(ep.params),
                        "status_codes": dict(ep.status_codes),
                        "hit_count": ep.hit_count,
                        "content_types": sorted(ep.content_types),
                    }
                )
            result[key] = ep_list
        return result

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Get summary of extracted HTTP Digest hashes for base class harvest().

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        hashcat_format.
        """
        hashcat_lines = self.get_hashcat_hashes()
        result = []
        hashcat_idx = 0
        for cred in self.credentials:
            if cred.auth_type != "Digest":
                continue
            result.append(
                {
                    "protocol": "HTTP",
                    "hash_type": f"Digest-{cred.algorithm or 'MD5'}",
                    "username": cred.username,
                    "domain": cred.realm,
                    "server_ip": cred.server_ip,
                    "client_ip": cred.client_ip,
                    "hashcat_format": (
                        hashcat_lines[hashcat_idx] if hashcat_idx < len(hashcat_lines) else ""
                    ),
                }
            )
            hashcat_idx += 1
        return result

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as [Method, Host, Path, Status, Content-Type]."""
        d = ix.details
        if ix.direction == "request":
            return [
                str(d.get("method", "")),
                str(d.get("host", "")),
                str(d.get("path", "")),
                "",
                "",
            ]
        else:
            code = str(d.get("response_code", ""))
            desc = str(d.get("response_code_desc", ""))
            status = f"{code} {desc}".strip()
            content_type = str(d.get("content_type", ""))
            return ["", "", "", status, content_type]

    def harvest(self) -> Dict[str, Any]:
        """Return HTTP discovery tables and results for the scanner pipeline.

        Credentials and hashes are collected centrally by the scanner via
        _collect_credentials() / _collect_hashes().  This override adds
        HTTP-specific asset/discovery tables (servers, clients, endpoints).
        """
        url_map = self.get_url_map()

        if not url_map and not self.credentials:
            return {}

        # Get alerts from base class (write/control operations)
        base = super().harvest()

        results: Dict[str, Any] = {}
        tables: List[Dict[str, Any]] = base.get("tables", [])
        alerts: List[Dict[str, str]] = base.get("alerts", [])
        log_messages: List[Dict[str, str]] = []

        # Populate results dict for scanner pipeline
        http_results: Dict[str, Any] = {}
        if url_map:
            http_results["url_map"] = url_map
        creds_summary = self.get_credentials_summary()
        if creds_summary:
            http_results["credentials"] = creds_summary
        results["http"] = http_results

        if url_map:
            total_endpoints = sum(len(eps) for eps in url_map.values())
            total_requests = sum(ep["hit_count"] for eps in url_map.values() for ep in eps)
            log_messages.append(
                {
                    "level": "success",
                    "message": (
                        f"HTTP: {len(url_map)} servers, {total_endpoints} endpoints,"
                        f" {total_requests} requests"
                    ),
                }
            )

            # HTTP Servers table (banners, technologies, auth, versions)
            if self._servers:
                srv_headers = [
                    "IP",
                    "Server",
                    "X-Powered-By",
                    "Technologies",
                    "Auth",
                    "Hosts",
                    "HTTP Versions",
                ]
                srv_rows = []
                for ip, info in self._servers.items():
                    banner = info.get("server_banner", "") or ""
                    powered = info.get("x_powered_by", "") or ""
                    techs = ", ".join(info.get("technologies", []))
                    auth = ", ".join(info.get("auth_methods", []))
                    hosts = ", ".join(info.get("virtual_hosts", []))
                    versions = ", ".join(info.get("http_versions", []))
                    srv_rows.append([ip, banner, powered, techs, auth, hosts, versions])
                tables.append({"headers": srv_headers, "rows": srv_rows, "title": "HTTP Servers"})

            # HTTP Clients table (user agents)
            if self._clients:
                ua_rows = []
                for ip, info in self._clients.items():
                    for ua in info.get("user_agents", []):
                        ua_rows.append([ip, ua])
                if ua_rows:
                    tables.append(
                        {
                            "headers": ["Client IP", "User-Agent"],
                            "rows": ua_rows,
                            "title": "HTTP Clients",
                        }
                    )

            # HTTP Endpoints table
            ep_headers = ["Server", "Method", "Path", "Params", "Hits", "Status"]
            ep_rows = []
            for server, endpoints in url_map.items():
                for ep in endpoints:
                    params = ", ".join(ep["params"]) if ep["params"] else ""
                    codes = ", ".join(str(c) for c in sorted(ep["status_codes"]))
                    ep_rows.append(
                        [server, ep["method"], ep["path"], params, ep["hit_count"], codes]
                    )
            tables.append(
                {
                    "headers": ep_headers,
                    "rows": ep_rows,
                    "title": (
                        f"HTTP Endpoints ({total_endpoints} endpoints, {total_requests} requests)"
                    ),
                }
            )

        result: Dict[str, Any] = {"results": results, "tables": tables}
        if alerts:
            result["alerts"] = alerts
        if log_messages:
            result["log_messages"] = log_messages
        return result
