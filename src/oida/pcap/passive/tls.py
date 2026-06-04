"""
TLS Passive Listener - Monitor TLS handshakes for certificate and cipher info.

Uses PyShark for packet dissection, leveraging Wireshark's TLS dissector.

Extracts:
- Server certificates (CN, SAN, issuer, thumbprint via central parsing)
- SNI from ClientHello
- Cipher suites offered/selected
- TLS version
- Client certificate usage
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
    normalize_mac,
)

from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


# Common cipher suites (subset for display)
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

TLS_VERSIONS = {
    "0x0300": "SSLv3",
    "0x0301": "TLSv1.0",
    "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2",
    "0x0304": "TLSv1.3",
    # PyShark may also return decimal strings
    "768": "SSLv3",
    "769": "TLSv1.0",
    "770": "TLSv1.1",
    "771": "TLSv1.2",
    "772": "TLSv1.3",
}


def _resolve_tls_version(raw) -> str:
    """Resolve TLS version string, including draft versions."""
    v = str(raw)
    if v in TLS_VERSIONS:
        return TLS_VERSIONS[v]
    # TLS 1.3 draft versions: 0x7F00-0x7F1C (decimal 32512-32540)
    try:
        n = int(v)
        if 32512 <= n <= 32540:
            return "TLSv1.3"
    except (ValueError, TypeError) as e:
        logger.debug(f"TLS: version int parse failed (non-numeric): {e}")
    if v.lower().startswith("0x7f"):
        return "TLSv1.3"
    return v


class TLSPassiveListener(PySharkListenerBase):
    """Passive TLS handshake listener using PyShark.

    Captures:
    - Server certificates with full info via central parser
    - Client SNI requests
    - Cipher suites (offered and selected)
    - Client certificate usage
    - TLS versions
    """

    PROTOCOL_NAME = "tls"
    DISPLAY_FILTER = "tls.handshake or tls.alert_message"
    REQUIRED_LAYERS = ("tls",)
    # Ports where the *server* side typically sends the Certificate message.
    # Used to disambiguate server-cert vs client-cert direction.
    _SERVER_PORTS = frozenset(
        {
            443,
            8443,
            636,
            993,
            995,
            8883,  # native TLS
            25,
            465,
            587,  # SMTP / SMTPS
            110,
            143,  # POP3 / IMAP STARTTLS
            389,  # LDAP STARTTLS
            5222,  # XMPP STARTTLS
            3306,
            5432,  # MySQL / PostgreSQL
            21,  # FTP AUTH TLS
            4840,
            4843,  # OPC UA / OPC UA TLS
        }
    )
    PROTOCOL_COLUMNS = ("message", "version", "detail", "info")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track connections: (client_ip, server_ip, server_port) -> connection_data
        self._connections: Dict[tuple, Dict[str, Any]] = {}

        # Track all certificates seen (by thumbprint)
        self.certificates: Dict[str, Dict[str, Any]] = {}

        # Track TLS errors/alerts
        self._tls_errors: List[Dict[str, str]] = []

    @staticmethod
    def _normalize_multi_record_layer(tls_layer) -> None:
        """Fix pyshark EK-mode layers where multiple TLS records produce a list.

        When a TCP segment carries several TLS records (e.g. ServerHello +
        Certificate + ServerKeyExchange), pyshark's EK JSON parser stores the
        layer's ``_fields_dict`` as a *list* of dicts instead of a single dict.
        ``EkLayer.get_field`` then crashes with
        ``AttributeError: 'dict' object has no attribute 'startswith'``.

        This method detects the list case and merges the sub-dicts into one,
        combining values that appear in multiple sub-dicts into lists so that
        the standard ``get_field`` -> comma-join pipeline works normally.
        """
        try:
            fd = object.__getattribute__(tls_layer, "_fields_dict")
        except AttributeError as e:
            logger.debug(f"TLS EK layer _fields_dict access failed: {e}")
            return
        if not isinstance(fd, list):
            return

        merged: dict = {}
        for sub in fd:
            if not isinstance(sub, dict):
                continue
            for k, v in sub.items():
                if v is None:
                    # Keep the key present (so field_names picks it up) but
                    # don't overwrite a real value with None.
                    merged.setdefault(k, None)
                    continue
                if k not in merged or merged[k] is None:
                    merged[k] = v
                else:
                    existing = merged[k]
                    if isinstance(existing, list):
                        if isinstance(v, list):
                            existing.extend(v)
                        else:
                            existing.append(v)
                    else:
                        if isinstance(v, list):
                            merged[k] = [existing] + v
                        else:
                            merged[k] = [existing, v]
        object.__setattr__(tls_layer, "_fields_dict", merged)

    def process_packet(self, packet) -> None:
        """Process TLS handshake packet using PyShark."""
        if not hasattr(packet, "tls"):
            return

        tls_layer = packet.tls

        # Fix multi-record EK layers BEFORE any field access.
        self._normalize_multi_record_layer(tls_layer)

        # Get IP and port info using base class helpers
        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Normalize MACs
        src_mac = normalize_mac(src_mac) if src_mac else ""
        dst_mac = normalize_mac(dst_mac) if dst_mac else ""

        # Track whether we recorded at least one interaction for this packet.
        interaction_recorded = False

        # Check for TLS alert messages
        alert_level = self.get_field(tls_layer, "alert_message_level", None)
        alert_desc = self.get_field(tls_layer, "alert_message_desc", None)
        if alert_desc is not None:
            self._process_tls_alert(
                src_ip,
                dst_ip,
                alert_level,
                alert_desc,
                flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            interaction_recorded = True

        # Handshake type may be a comma-separated list when multiple
        # handshake messages are bundled in one TCP segment (e.g. "2,11,14"
        # for ServerHello + Certificate + ServerKeyExchange).
        hs_type_raw = self.get_field(tls_layer, "handshake_type", None)
        if hs_type_raw is None:
            if not interaction_recorded:
                # Packet matched the display filter but has no parseable
                # handshake type and no alert — likely an encrypted Finished,
                # ChangeCipherSpec, or encrypted alert.  Record a minimal
                # interaction so the packet is not silently dropped.
                content_type = self.get_field(tls_layer, "record_content_type", None)
                ct_label = {
                    "20": "ChangeCipherSpec",
                    "21": "EncryptedAlert",
                    "22": "EncryptedHandshake",
                    "23": "ApplicationData",
                }
                ct_str = str(content_type) if content_type else ""
                # Pick a label from the first content type present
                first_ct = ct_str.split(",")[0].strip() if ct_str else ""
                label = ct_label.get(first_ct, f"TLS({first_ct})" if first_ct else "TLS")
                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    f"TLS {label}",
                    {"content_type": ct_str},
                    f"TLS {label}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=self.get_stream_id(packet),
                )
            return
        hs_types = {t.strip() for t in str(hs_type_raw or "").split(",") if t.strip()}

        # Record interaction using the most interesting type in the bundle
        now = datetime.now().isoformat()
        hs_names = {
            "0": "HelloRequest",
            "1": "ClientHello",
            "2": "ServerHello",
            "3": "HelloVerifyRequest",
            "4": "NewSessionTicket",
            "5": "EndOfEarlyData",
            "6": "HelloRetryRequest",
            "8": "EncryptedExtensions",
            "11": "Certificate",
            "12": "ServerKeyExchange",
            "13": "CertificateRequest",
            "14": "ServerHelloDone",
            "15": "CertificateVerify",
            "16": "ClientKeyExchange",
            "20": "Finished",
            "22": "CertificateStatus",
            "67": "NextProtocol",
        }
        # Pick the first named type in priority order for the interaction label
        hs_label = next(
            (
                hs_names[t]
                for t in ("13", "11", "2", "1", "4", "12", "14", "15", "16", "20", "8", "0")
                if t in hs_types
            ),
            # Fall back to the first named type in the bundle, or the raw value
            next(
                (hs_names[t] for t in hs_types if t in hs_names),
                f"Handshake({hs_type_raw})" if hs_type_raw else "TLS",
            ),
        )

        # Extract key fields for the interaction details
        details: Dict[str, Any] = {}
        version_raw = self.get_field(tls_layer, "handshake_version", None)
        if version_raw:
            details["version"] = _resolve_tls_version(version_raw)
        # TLS 1.3 supported_versions override
        sv = self.get_field(tls_layer, "handshake_extensions_supported_version", None)
        if sv:
            for v in str(sv).split(","):
                resolved = _resolve_tls_version(v.strip())
                if resolved != v.strip():
                    details["version"] = resolved
                    break
        # SNI (ClientHello)
        sni = self.get_field(tls_layer, "handshake_extensions_server_name", None)
        if sni:
            details["sni"] = str(sni)
        # Cipher suite (ServerHello = selected, ClientHello = count offered)
        cipher_raw = self.get_field(tls_layer, "handshake_ciphersuite", None)
        if cipher_raw:
            parts = [c.strip() for c in str(cipher_raw).split(",") if c.strip()]
            if "2" in hs_types and parts:
                # ServerHello: show selected cipher name
                try:
                    cs = parts[0]
                    ci = int(cs, 16) if cs.startswith("0x") else int(cs)
                    details["cipher"] = CIPHER_SUITES.get(ci, f"0x{ci:04X}")
                except ValueError:
                    details["cipher"] = parts[0]
            elif "1" in hs_types:
                details["ciphers_offered"] = len(parts)
        # ALPN
        alpn = self.get_field(tls_layer, "handshake_extensions_alpn_str", None)
        if alpn:
            details["alpn"] = str(alpn)
        # OCSP status_request extension type (1 = OCSP stapling requested)
        status_req = self.get_field(tls_layer, "handshake_extensions_status_request_type", None)
        if status_req is not None:
            details["ocsp_status_request"] = "ocsp" if str(status_req) == "1" else str(status_req)
        # Encrypted PreMaster secret length (RSA key exchange = no forward secrecy)
        epms_len = self.get_field(tls_layer, "handshake_epms_len", None)
        if epms_len is not None:
            details["rsa_key_exchange"] = True
            details["epms_len"] = str(epms_len)
        # JA3/JA3S fingerprint
        ja3 = self.get_field(tls_layer, "handshake_ja3_hash", None) or self.get_field(
            tls_layer, "handshake_ja3", None
        )
        if ja3:
            details["ja3"] = str(ja3)
        ja3s = self.get_field(tls_layer, "handshake_ja3s_hash", None) or self.get_field(
            tls_layer, "handshake_ja3s", None
        )
        if ja3s:
            details["ja3s"] = str(ja3s)
        # Certificate CN — extract from raw cert hex (works in EK mode)
        if "11" in hs_types:
            cert_hex = self.get_field(tls_layer, "handshake_certificate", None)
            if not cert_hex:
                cert_hex = self.get_field(tls_layer, "handshake_certificates", None)
            if cert_hex:
                try:
                    cert_str = str(cert_hex).split(",")[0].strip().replace(":", "").replace(" ", "")
                    cn = self._quick_cert_cn(bytes.fromhex(cert_str))
                    if cn:
                        details["cert_cn"] = cn
                except Exception as e:
                    self.logger.debug(f"Failed to get cert_str: {e}")

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request" if "1" in hs_types else "response",
            f"TLS {hs_label}",
            details,
            f"TLS {hs_label}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Dispatch to all matching handlers (a single packet can carry
        # ServerHello + Certificate + ServerKeyExchange together).
        if "1" in hs_types:
            self._process_client_hello(tls_layer, src_ip, dst_ip, dst_port, src_mac)
        if "2" in hs_types:
            self._process_server_hello(tls_layer, src_ip, dst_ip, src_port, dst_mac)
        if "11" in hs_types:
            self._process_certificate(
                tls_layer, packet, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac
            )
        if "13" in hs_types:
            self._process_certificate_request(tls_layer, src_ip, dst_ip, src_port, dst_port)
        if "16" in hs_types:
            # ClientKeyExchange: epms_len present => RSA key exchange (no PFS)
            epms_len = self.get_field(tls_layer, "handshake_epms_len", None)
            if epms_len is not None:
                # ClientKeyExchange flows client -> server; server port is dst.
                if dst_port in self._SERVER_PORTS or src_port not in self._SERVER_PORTS:
                    c_ip, s_ip, s_port = src_ip, dst_ip, dst_port
                else:
                    c_ip, s_ip, s_port = dst_ip, src_ip, src_port
                _, conn = self._ensure_connection(c_ip, s_ip, s_port)
                conn["rsa_key_exchange"] = True

    def _process_client_hello(
        self,
        tls_layer,
        client_ip: str,
        server_ip: str,
        server_port: int,
        client_mac: str,
    ) -> None:
        """Extract SNI and offered cipher suites from ClientHello."""
        try:
            # Get SNI from PyShark
            sni_names = []
            sni = self.get_field(tls_layer, "handshake_extensions_server_name", None)
            if sni:
                # Could be a single value or comma-separated
                sni_names = [s.strip() for s in str(sni).split(",") if s.strip()]

            # Get TLS version
            version_raw = self.get_field(tls_layer, "handshake_version", None)
            tls_version = _resolve_tls_version(version_raw) if version_raw else "Unknown"

            # Check for supported_versions extension (TLS 1.3)
            supported_versions = self.get_field(
                tls_layer, "handshake_extensions_supported_version", None
            )
            if supported_versions:
                # Use highest supported version
                for v in str(supported_versions).split(","):
                    resolved = _resolve_tls_version(v.strip())
                    if resolved != v.strip():
                        tls_version = resolved
                        break

            # Get offered cipher suites
            offered_ciphers = []
            ciphers_raw = self.get_field(tls_layer, "handshake_ciphersuite", None)
            if ciphers_raw:
                # PyShark returns cipher suites, may be multiple
                # They could be hex strings like "0x1301" or decimal
                for cs in str(ciphers_raw).split(","):
                    cs = cs.strip()
                    try:
                        if cs.startswith("0x"):
                            cipher_int = int(cs, 16)
                        else:
                            cipher_int = int(cs)
                        cipher_name = CIPHER_SUITES.get(cipher_int, f"0x{cipher_int:04X}")
                        offered_ciphers.append(cipher_name)
                    except ValueError:
                        offered_ciphers.append(cs)

            # Also try handshake_ciphersuites (plural form)
            if not offered_ciphers:
                ciphers_raw = self.get_field(tls_layer, "handshake_ciphersuites", None)
                if ciphers_raw:
                    offered_ciphers = [str(ciphers_raw)]

            # Extract JA3/JA4 fingerprints (requires Wireshark 3.x+ with JA3 plugin)
            ja3_hash = self.get_field(tls_layer, "handshake_ja3_hash", None)
            ja3_full = self.get_field(tls_layer, "handshake_ja3_full", None)
            # Also try the tls.handshake.ja3 field name variant
            if not ja3_hash:
                ja3_hash = self.get_field(tls_layer, "handshake_ja3", None)
            ja4 = self.get_field(tls_layer, "handshake_ja4", None)

            # Session ID
            session_id = self.get_field(tls_layer, "handshake_session_id", None)

            # ALPN (Application-Layer Protocol Negotiation)
            alpn_raw = self.get_field(tls_layer, "handshake_extensions_alpn_str", None)
            alpn_protocols = []
            if alpn_raw:
                alpn_protocols = [p.strip() for p in str(alpn_raw).split(",") if p.strip()]

            # Signature algorithms offered by client
            sig_algs_raw = self.get_field(tls_layer, "handshake_sig_hash_alg", None)
            sig_algorithms = []
            if sig_algs_raw:
                for sa in str(sig_algs_raw).split(","):
                    sa = sa.strip()
                    if sa:
                        sig_algorithms.append(sa)

            # ECH (Encrypted Client Hello) parameters
            ech_config_id = self.get_field(tls_layer, "ech_config_id", None)
            ech_kdf_id = self.get_field(tls_layer, "ech_hpke_keyconfig_cipher_suite_kdf_id", None)
            ech_aead_id = self.get_field(tls_layer, "ech_hpke_keyconfig_cipher_suite_aead_id", None)

            # OCSP status_request extension (client asks server to staple OCSP)
            status_request_type = self.get_field(
                tls_layer, "handshake_extensions_status_request_type", None
            )

            # Token Binding parameters
            tb_version_major = self.get_field(tls_layer, "token_binding_version_major", None)
            tb_version_minor = self.get_field(tls_layer, "token_binding_version_minor", None)
            tb_key_param = self.get_field(tls_layer, "token_binding_key_parameter", None)

            # Store connection info (create or update)
            _, conn = self._ensure_connection(client_ip, server_ip, server_port, client_mac)
            conn["sni"] = sni_names
            conn["offered_ciphers"] = offered_ciphers
            if tls_version:
                conn["tls_version"] = tls_version
            if ja3_hash:
                conn["ja3"] = str(ja3_hash)
            if ja3_full:
                conn["ja3_full"] = str(ja3_full)
            if ja4:
                conn["ja4"] = str(ja4)
            if session_id:
                conn["session_id"] = str(session_id)
            if alpn_protocols:
                conn["alpn"] = alpn_protocols
            if sig_algorithms:
                conn["signature_algorithms"] = sig_algorithms
            if status_request_type is not None:
                conn["ocsp_status_request"] = str(status_request_type) == "1"
            if ech_config_id is not None:
                conn["ech"] = {
                    "config_id": str(ech_config_id),
                    "kdf_id": str(ech_kdf_id) if ech_kdf_id is not None else "",
                    "aead_id": str(ech_aead_id) if ech_aead_id is not None else "",
                }
            if tb_version_major is not None:
                conn["token_binding"] = {
                    "version": f"{tb_version_major}.{tb_version_minor or '0'}",
                    "key_parameter": str(tb_key_param) if tb_key_param is not None else "",
                }

            # Add client device
            if sni_names:
                self._add_tls_device(
                    client_ip,
                    client_mac,
                    "client",
                    {"sni": sni_names, "offered_ciphers": offered_ciphers},
                )

        except Exception as e:
            self.logger.debug(f"ClientHello parse error: {e}")

    def _ensure_connection(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        client_mac: str = "",
    ) -> tuple:
        """Ensure a connection entry exists, return (conn_key, conn_dict)."""
        conn_key = (client_ip, server_ip, server_port)
        if conn_key not in self._connections:
            self._connections[conn_key] = {
                "client_ip": client_ip,
                "client_mac": client_mac,
                "server_ip": server_ip,
                "server_port": server_port,
                "sni": [],
                "offered_ciphers": [],
                "tls_version": "",
                "selected_cipher": None,
                "server_cert": None,
                "client_cert_used": False,
                "client_cert_requested": False,
                "requested_cas": [],
                "ja3": None,
                "ja3_full": None,
                "ja3s": None,
                "ja4": None,
                "ja4s": None,
            }
        return conn_key, self._connections[conn_key]

    def _process_server_hello(
        self,
        tls_layer,
        server_ip: str,
        client_ip: str,
        server_port: int,
        server_mac: str,
    ) -> None:
        """Extract selected cipher suite from ServerHello."""
        try:
            # Get TLS version
            version_raw = self.get_field(tls_layer, "handshake_version", None)
            tls_version = _resolve_tls_version(version_raw) if version_raw else ""

            # Check for supported_versions extension (TLS 1.3 response)
            supported_version = self.get_field(
                tls_layer, "handshake_extensions_supported_version", None
            )
            if supported_version:
                resolved = _resolve_tls_version(str(supported_version).strip())
                if resolved != str(supported_version).strip():
                    tls_version = resolved

            # Get selected cipher suite
            cipher_raw = self.get_field(tls_layer, "handshake_ciphersuite", None)
            cipher_name = None
            if cipher_raw:
                try:
                    cs = str(cipher_raw).strip()
                    if cs.startswith("0x"):
                        cipher_int = int(cs, 16)
                    else:
                        cipher_int = int(cs)
                    cipher_name = CIPHER_SUITES.get(cipher_int, f"0x{cipher_int:04X}")
                except ValueError:
                    cipher_name = str(cipher_raw)

            # Extract JA3S/JA4S fingerprints
            ja3s_hash = self.get_field(tls_layer, "handshake_ja3s_hash", None)
            if not ja3s_hash:
                ja3s_hash = self.get_field(tls_layer, "handshake_ja3s", None)
            ja4s = self.get_field(tls_layer, "handshake_ja4s", None)

            # Session ID (server echoes back)
            session_id = self.get_field(tls_layer, "handshake_session_id", None)

            # Compression method selected by server
            comp_method = self.get_field(tls_layer, "handshake_comp_method", None)

            # ALPN selected by server
            alpn_raw = self.get_field(tls_layer, "handshake_extensions_alpn_str", None)
            selected_alpn = None
            if alpn_raw:
                # Server selects a single ALPN protocol
                selected_alpn = str(alpn_raw).split(",")[0].strip()

            # SCT (Signed Certificate Timestamp) from ServerHello extension
            sct_version = self.get_field(tls_layer, "sct_sct_version", None)
            sct_logid = self.get_field(tls_layer, "sct_sct_logid", None)

            # Update or create connection
            _, conn = self._ensure_connection(client_ip, server_ip, server_port)
            if cipher_name:
                conn["selected_cipher"] = cipher_name
            if tls_version:
                conn["tls_version"] = tls_version
            if ja3s_hash:
                conn["ja3s"] = str(ja3s_hash)
            if ja4s:
                conn["ja4s"] = str(ja4s)
            if session_id:
                conn["session_id"] = str(session_id)
            if comp_method is not None:
                conn["compression_method"] = str(comp_method)
            if selected_alpn:
                conn["selected_alpn"] = selected_alpn
            if sct_version is not None:
                sct_list = conn.setdefault("sct", [])
                # May contain multiple SCTs (comma-separated in EK mode)
                versions = str(sct_version).split(",")
                logids = str(sct_logid).split(",") if sct_logid else []
                for idx, ver in enumerate(versions):
                    sct_entry = {"version": ver.strip()}
                    if idx < len(logids):
                        sct_entry["log_id"] = logids[idx].strip()
                    sct_list.append(sct_entry)

        except Exception as e:
            self.logger.debug(f"ServerHello parse error: {e}")

    def _process_certificate_request(
        self,
        tls_layer,
        server_ip: str,
        client_ip: str,
        server_port: int,
        client_port: int,
    ) -> None:
        """Extract acceptable CA list from CertificateRequest (mTLS).

        The server sends handshake type 13 to request a client certificate.
        The message includes a list of CA distinguished names the server
        trusts for client authentication.
        """
        try:
            # Server sends CertificateRequest, so src_ip is the server
            # Determine direction from port
            if server_port in self._SERVER_PORTS:
                s_ip, c_ip, s_port = server_ip, client_ip, server_port
            else:
                s_ip, c_ip, s_port = client_ip, server_ip, client_port

            _, conn = self._ensure_connection(c_ip, s_ip, s_port)
            conn["client_cert_requested"] = True

            # Extract acceptable CA distinguished names
            # tshark: tls.handshake.dname contains DER-decoded DN strings
            ca_dns = []
            dnames_raw = self.get_field(tls_layer, "handshake_dname", None)
            if dnames_raw:
                # May be comma-separated for multiple DNs
                for dn in str(dnames_raw).split(","):
                    dn = dn.strip()
                    if dn:
                        ca_dns.append(dn)

            # Also try x509if field that Wireshark decodes DNs into
            if not ca_dns:
                dn_field = self.get_field(tls_layer, "handshake_dnames", None)
                if dn_field:
                    ca_dns.append(str(dn_field))

            # Try get_all_fields for multiple DN entries
            if not ca_dns:
                all_fields = self.get_all_fields(tls_layer)
                for key, val in all_fields.items():
                    if "dname" in key.lower() and val:
                        for part in str(val).split(","):
                            part = part.strip()
                            if part and len(part) > 3:
                                ca_dns.append(part)
                        break

            if ca_dns:
                conn["requested_cas"] = ca_dns

            self.logger.debug(
                f"TLS: CertificateRequest {s_ip}:{s_port} -> {c_ip} ({len(ca_dns)} acceptable CAs)"
            )

        except Exception as e:
            self.logger.debug(f"CertificateRequest parse error: {e}")

    def _process_certificate(
        self,
        tls_layer,
        packet,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
    ) -> None:
        """Process Certificate message (server or client cert)."""
        try:
            # Try to get certificate data from PyShark
            cert_data_hex = self.get_field(tls_layer, "handshake_certificate", None)
            if not cert_data_hex:
                cert_data_hex = self.get_field(tls_layer, "handshake_certificates", None)
            if not cert_data_hex:
                return

            # Convert hex string to bytes
            # EK mode may return multiple certs comma-separated (list fields)
            cert_data_str = str(cert_data_hex).split(",")[0].strip()
            cert_data_str = cert_data_str.replace(":", "").replace(" ", "")
            cert_data = bytes.fromhex(cert_data_str)

            # Parse certificate via central get_cert_info
            cert_info = self._parse_cert(cert_data)
            if not cert_info:
                return

            # Try to get TLS version from handshake or record layer
            version_raw = self.get_field(tls_layer, "handshake_version", None)
            if not version_raw:
                version_raw = self.get_field(tls_layer, "record_version", None)
            tls_version = _resolve_tls_version(version_raw) if version_raw else ""

            # Determine if server or client cert based on port direction
            is_server_cert = src_port in self._SERVER_PORTS

            if is_server_cert:
                server_ip, client_ip = src_ip, dst_ip
                server_mac = src_mac
                server_port = src_port

                # Store certificate
                thumbprint = cert_info.get("thumbprint", "")
                if thumbprint:
                    self.certificates[thumbprint] = cert_info

                # Ensure connection exists (handles pcaps without ClientHello)
                _, conn = self._ensure_connection(client_ip, server_ip, server_port)
                conn["server_cert"] = cert_info
                if tls_version and not conn.get("tls_version"):
                    conn["tls_version"] = tls_version

                # Add server device
                self._add_tls_device(server_ip, server_mac, "server", cert_info)

            else:
                # Client certificate
                client_ip, server_ip = src_ip, dst_ip
                server_port = dst_port

                # Ensure connection exists
                _, conn = self._ensure_connection(client_ip, server_ip, server_port)
                conn["client_cert_used"] = True
                conn["client_cert"] = cert_info
                if tls_version and not conn.get("tls_version"):
                    conn["tls_version"] = tls_version

                self.logger.debug(
                    f"TLS: Client cert from {client_ip}: {cert_info.get('subject', '')}"
                )

        except Exception as e:
            self.logger.debug(f"Certificate parse error: {e}")

    def _parse_cert(self, cert_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse certificate via central display_cert_info (security checks included)."""
        info = self._display_cert_info(cert_data, protocol="tls")
        if not info or "error" in info:
            self.logger.debug("TLS: certificate parse failed")
            return None

        # Extract CN from subject
        cn = ""
        for part in info.get("subject", "").split(","):
            if part.strip().upper().startswith("CN="):
                cn = part.strip()[3:]
                break

        return {
            "common_name": cn,
            "subject": info.get("subject", ""),
            "issuer": info.get("issuer", ""),
            "thumbprint": info.get("thumbprint", ""),
            "key_type": info.get("key_type", ""),
            "key_size": info.get("key_size", 0),
            "self_signed": info.get("self_signed", False),
            "not_before": info.get("not_before", "") if info.get("not_before") else "",
            "not_after": info.get("not_after", "") if info.get("not_after") else "",
            "issues": info.get("issues", []),
            "extensions": info.get("extensions", {}),
        }

    @staticmethod
    def _quick_cert_cn(cert_der: bytes) -> str:
        """Extract CN from DER cert without full security analysis."""
        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(cert_der)
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    return attr.value
        except Exception as e:
            logger.debug(f"Optional import x509 not available: {e}")
        return ""

    # TLS alert descriptions (RFC 5246 Section 7.2.2)
    _ALERT_DESCRIPTIONS = {
        "0": "close_notify",
        "10": "unexpected_message",
        "20": "bad_record_mac",
        "40": "handshake_failure",
        "42": "bad_certificate",
        "43": "unsupported_certificate",
        "44": "certificate_revoked",
        "45": "certificate_expired",
        "46": "certificate_unknown",
        "47": "illegal_parameter",
        "48": "unknown_ca",
        "49": "access_denied",
        "50": "decode_error",
        "51": "decrypt_error",
        "70": "protocol_version",
        "71": "insufficient_security",
        "80": "internal_error",
        "86": "inappropriate_fallback",
        "90": "user_canceled",
        "100": "no_renegotiation",
        "109": "missing_extension",
        "110": "unsupported_extension",
        "112": "unrecognized_name",
        "113": "bad_certificate_status_response",
        "115": "unknown_psk_identity",
        "116": "certificate_required",
        "120": "no_application_protocol",
    }

    def _process_tls_alert(
        self,
        src_ip: str,
        dst_ip: str,
        alert_level: Optional[str],
        alert_desc: Optional[str],
        flow_id: str,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process TLS alert message.

        Always records an interaction (including close_notify) so that every
        packet matching the display filter produces at least one interaction.
        Only non-close_notify alerts are added to ``_tls_errors``.
        """
        desc_str = self._ALERT_DESCRIPTIONS.get(str(alert_desc), str(alert_desc))
        level_str = "fatal" if str(alert_level) == "2" else "warning"
        is_close_notify = str(alert_desc) == "0"

        if is_close_notify:
            level_str = "info"
            desc_str = "close_notify"
        else:
            self._tls_errors.append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "level": level_str,
                    "description": desc_str,
                    "flow_id": flow_id,
                }
            )

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            f"TLS Alert ({level_str})",
            {"alert_level": level_str, "alert_desc": desc_str},
            f"TLS Alert: {level_str} {desc_str}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _add_tls_device(self, ip: str, mac: str, role: str, data: Dict[str, Any]) -> None:
        """Add or update device."""
        if not is_valid_discovered_ip(ip):
            return

        device_key = f"tls-{role}:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""

        device, is_new = self._ensure_device(
            device_key,
            ip,
            mac=mac,
            name=data.get("common_name", ""),
            device_type=f"TLS {role.title()}",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.tls_passive_data = {
                "role": role,
                "protocol": "TLS/TCP",
                **data,
            }

            if role == "server":
                self.logger.debug(
                    f"TLS: Server {ip} CN={data.get('common_name', '')} "
                    f"thumb={data.get('thumbprint', '')}"
                )
        else:
            # Merge data
            if hasattr(device, "tls_passive_data") and device.tls_passive_data:
                device.tls_passive_data.update(data)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        # Message name from the operation field (e.g. "TLS ClientHello")
        message = ix.operation or ""
        # Version: check details first, fall back to empty string
        version = str(d.get("version", ""))
        # Detail: for alerts use level+description, for handshakes show key fields
        alert_desc = d.get("alert_desc", "")
        alert_level = d.get("alert_level", "")
        if alert_desc:
            detail = f"{alert_level} {alert_desc}".strip() if alert_level else str(alert_desc)
            info = ""
        else:
            # Build detail from handshake fields
            detail_parts = []
            if d.get("sni"):
                detail_parts.append(f"SNI={d['sni']}")
            if d.get("cipher"):
                detail_parts.append(d["cipher"])
            elif d.get("ciphers_offered"):
                detail_parts.append(f"{d['ciphers_offered']} ciphers")
            if d.get("cert_cn"):
                detail_parts.append(f"CN={d['cert_cn']}")
            if d.get("alpn"):
                detail_parts.append(f"ALPN={d['alpn']}")
            detail = " ".join(detail_parts)
            # Info: JA3/JA3S fingerprint
            info = d.get("ja3", d.get("ja3s", ""))
        return [str(message), str(version), str(detail), str(info)]

    def get_connections(self) -> List[Dict[str, Any]]:
        """Get all observed TLS connections with cipher and fingerprint info."""
        result = []
        for conn in self._connections.values():
            entry: Dict[str, Any] = {
                "client": conn["client_ip"],
                "server": f"{conn['server_ip']}:{conn['server_port']}",
                "sni": conn.get("sni", []),
                "tls_version": conn.get("tls_version", ""),
                "selected_cipher": conn.get("selected_cipher", ""),
                "client_cert_used": conn.get("client_cert_used", False),
                "client_cert_requested": conn.get("client_cert_requested", False),
                "requested_cas": conn.get("requested_cas", []),
                "server_cn": (
                    conn.get("server_cert", {}).get("common_name", "")
                    if conn.get("server_cert")
                    else ""
                ),
                "ja3": conn.get("ja3"),
                "ja3s": conn.get("ja3s"),
                "ja4": conn.get("ja4"),
                "ja4s": conn.get("ja4s"),
            }
            # Optional fields -- only include when present
            if conn.get("session_id"):
                entry["session_id"] = conn["session_id"]
            if conn.get("compression_method") is not None:
                entry["compression_method"] = conn["compression_method"]
            if conn.get("alpn"):
                entry["alpn"] = conn["alpn"]
            if conn.get("selected_alpn"):
                entry["selected_alpn"] = conn["selected_alpn"]
            if conn.get("signature_algorithms"):
                entry["signature_algorithms"] = conn["signature_algorithms"]
            if conn.get("ech"):
                entry["ech"] = conn["ech"]
            if conn.get("token_binding"):
                entry["token_binding"] = conn["token_binding"]
            if conn.get("sct"):
                entry["sct"] = conn["sct"]
            if conn.get("ocsp_status_request"):
                entry["ocsp_status_request"] = True
            if conn.get("rsa_key_exchange"):
                entry["rsa_key_exchange"] = True
            result.append(entry)
        return result

    def get_certificates(self) -> Dict[str, Dict[str, Any]]:
        """Get all certificates by thumbprint."""
        return self.certificates

    # Deprecated / insecure TLS versions
    _WEAK_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}

    # Weak cipher keywords (null, export, RC4, DES, anon)
    _WEAK_CIPHER_KEYWORDS = ("NULL", "EXPORT", "RC4", "DES_CBC", "_anon_", "MD5")

    def harvest(self) -> Dict[str, Any]:
        """Return TLS handshake tables, security alerts, and cert results."""
        certs = self.get_certificates()
        conns = self.get_connections()

        if not certs and not conns and not self._tls_errors:
            return {}

        tables: List[Dict[str, Any]] = []
        alerts: List[Dict[str, str]] = []

        # Certificate table (gated behind -X / --x509)
        if certs and getattr(self, "_x509", False):
            cert_rows = []
            for thumb, cert in list(certs.items()):
                cn = cert.get("common_name", "")
                issuer = cert.get("issuer", "")
                key_info = (
                    f"{cert.get('key_type', '')} {cert.get('key_size', '')}"
                    if cert.get("key_type")
                    else ""
                )
                expires = cert.get("not_after", "")
                issues = cert.get("issues", [])
                issues_str = f"{len(issues)} issues" if issues else "OK"
                cert_rows.append([cn, issuer, key_info.strip(), expires, issues_str])
            tables.append(
                {
                    "headers": ["CN", "Issuer", "Key", "Expires", "Status"],
                    "rows": cert_rows,
                    "title": f"TLS Certificates ({len(cert_rows)})",
                }
            )

        # Acceptable CAs table (from CertificateRequest messages)
        ca_conns = [c for c in conns if c.get("requested_cas")]
        if ca_conns:
            ca_rows = []
            for conn in ca_conns:
                for ca_dn in conn.get("requested_cas", []):
                    ca_rows.append(
                        [
                            conn.get("server", ""),
                            ca_dn,
                        ]
                    )
            if ca_rows:
                tables.append(
                    {
                        "headers": ["Server", "Acceptable CA"],
                        "rows": ca_rows,
                        "title": f"mTLS Acceptable CAs ({len(ca_rows)})",
                    }
                )

        # TLS errors table
        if self._tls_errors:
            err_rows = []
            for err in self._tls_errors:
                err_rows.append(
                    [
                        err["src"],
                        err["dst"],
                        err["level"],
                        err["description"],
                    ]
                )
            tables.append(
                {
                    "headers": ["Source", "Dest", "Level", "Alert"],
                    "rows": err_rows,
                    "title": f"TLS Errors ({len(err_rows)})",
                }
            )

        # Security alerts: deprecated TLS versions
        weak_version_conns = [c for c in conns if c.get("tls_version") in self._WEAK_VERSIONS]
        for conn in weak_version_conns:
            alerts.append(
                {
                    "level": "fail",
                    "category": "tls_version",
                    "message": (
                        f"TLS: Deprecated {conn['tls_version']}"
                        f" {conn['client']} -> {conn['server']}"
                    ),
                }
            )

        # Security alerts: weak ciphers
        for conn in conns:
            cipher = conn.get("selected_cipher", "")
            if cipher and any(kw in cipher.upper() for kw in self._WEAK_CIPHER_KEYWORDS):
                alerts.append(
                    {
                        "level": "fail",
                        "category": "tls_cipher",
                        "message": f"TLS: Weak cipher {cipher} {conn['client']} -> {conn['server']}",
                    }
                )

        # Security alerts: RSA key exchange (no forward secrecy)
        for conn in conns:
            if conn.get("rsa_key_exchange"):
                alerts.append(
                    {
                        "level": "warning",
                        "category": "tls_no_pfs",
                        "message": (
                            f"TLS: RSA key exchange (no forward secrecy)"
                            f" {conn['client']} -> {conn['server']}"
                        ),
                    }
                )

        # Security alerts: mTLS requested
        for conn in conns:
            if conn.get("client_cert_requested"):
                cas = conn.get("requested_cas", [])
                ca_info = f" ({len(cas)} acceptable CAs)" if cas else ""
                if conn.get("client_cert_used"):
                    alerts.append(
                        {
                            "level": "info",
                            "category": "tls_mtls",
                            "message": (
                                f"TLS: mTLS active{ca_info} {conn['client']} -> {conn['server']}"
                            ),
                        }
                    )
                else:
                    alerts.append(
                        {
                            "level": "warning",
                            "category": "tls_mtls",
                            "message": (
                                f"TLS: mTLS requested but no client cert seen{ca_info}"
                                f" {conn['client']} -> {conn['server']}"
                            ),
                        }
                    )

        # Security alerts: fatal TLS errors
        for err in self._tls_errors:
            if err["level"] == "fatal":
                alerts.append(
                    {
                        "level": "fail",
                        "category": "tls_error",
                        "message": (
                            f"TLS: Fatal alert {err['description']} {err['src']} -> {err['dst']}"
                        ),
                    }
                )

        results: Dict[str, Any] = {
            "protocols_used_append": ["tls"],
        }
        # Pass certs and connections for pipeline merge
        if certs:
            results["tls_certificates_merge"] = certs
        if conns:
            results["tls_connections"] = conns
        # TLS fingerprints summary for structured output
        fp_conns = [c for c in conns if c.get("ja3") or c.get("ja3s")]
        if fp_conns:
            results["tls_fingerprints"] = [
                {
                    "client": c.get("client", ""),
                    "server": c.get("server", ""),
                    "sni": c.get("sni", []),
                    "ja3": c.get("ja3"),
                    "ja3s": c.get("ja3s"),
                    "ja4": c.get("ja4"),
                    "ja4s": c.get("ja4s"),
                }
                for c in fp_conns
            ]
            # Fingerprints display table
            fp_rows = []
            for c in fp_conns:
                sni_str = ", ".join(c.get("sni", [])) if c.get("sni") else ""
                fp_rows.append(
                    [
                        c.get("client", ""),
                        c.get("server", ""),
                        sni_str,
                        c.get("ja3") or "",
                        c.get("ja3s") or "",
                    ]
                )
            tables.append(
                {
                    "headers": ["Client", "Server", "SNI", "JA3", "JA3S"],
                    "rows": fp_rows,
                    "title": f"TLS Fingerprints ({len(fp_rows)})",
                }
            )

        return {
            "tables": tables,
            "alerts": alerts,
            "results": results,
        }
