"""
EtherNet/IP CIP Security Mixin

Handles CIP Security detection and analysis:
- CIP Security Object (0x5D) detection and dump
- EtherNet/IP Security Object (0x5E)
- Certificate Management Object (0x5F)
- Password Authenticator Object (0x61)
- TLS support detection (port 2221)
- Certificate parsing (X.509)
- Security status reporting
"""

from __future__ import annotations

import base64
import struct
from typing import Any, Dict, Optional, TYPE_CHECKING

from ....utils.lazy_import import lazy_import

_cryptography = lazy_import("cryptography", "EtherNet/IP", install_hint="pip install cryptography")

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class CipSecurityMixin(_ScannerBase):
    """Mixin providing CIP Security detection and analysis."""

    def _report_security_status(self, security: Dict[str, Any]) -> None:
        """
        Report CIP Security status based on actual security dump data.

        Provides accurate messaging about security state:
        - NOT SUPPORTED: Security objects not accessible
        - NOT CONFIGURED: Objects exist but in Factory Default state
        - ENABLED: Security is actively configured
        """
        cip_sec = security.get("cip_security") or {}
        eip_sec = security.get("eip_security") or {}
        certs = security.get("certificates") or {}

        # Check if CIP Security object is accessible
        if not cip_sec.get("accessible"):
            self.logger.security_finding("No authentication", detail="CIP Security: NOT SUPPORTED")
            return

        # Check security state
        state_raw = cip_sec.get("state_raw", 0)
        state_name = cip_sec.get("state", "Unknown")

        if state_raw == 0:
            # Factory Default - security exists but not configured
            self.logger.security_finding(
                "No authentication", detail=f"CIP Security: NOT CONFIGURED ({state_name})"
            )
        else:
            # Security is configured
            self.logger.success(f"CIP Security: ENABLED ({state_name})")
            # Report active profile
            profiles = cip_sec.get("profiles", [])
            active = cip_sec.get("active_profile", 0)
            if profiles:
                self.logger.display(f"  Profiles: {', '.join(profiles)}")
            if active > 0:
                self.logger.display(f"  Active Profile: {active}")

        # EtherNet/IP Security status
        if eip_sec.get("accessible"):
            caps = eip_sec.get("capabilities", [])
            psk_count = eip_sec.get("psk_count", 0)
            if caps:
                self.logger.display(f"EIP Capabilities: {', '.join(caps)}")
            if psk_count > 0:
                active_psk = eip_sec.get("active_psk_slot", 0)
                if active_psk > 0:
                    self.logger.display(f"PSK: Slot {active_psk} active ({psk_count} configured)")
                else:
                    self.logger.display(f"PSK: {psk_count} configured, none active")

        # Certificate status
        if certs.get("accessible"):
            installed = certs.get("installed_certificates", 0)
            max_certs = certs.get("max_certificates", 0)
            if installed > 0:
                self.logger.display(f"Certificates: {installed}/{max_certs} installed")

    def _dump_security_settings(self, conn: Any) -> Dict[str, Any]:
        """
        Dump detailed security settings from all CIP Security objects.

        Reads specific attributes from:
        - CIP Security (0x5D): state, profiles, targets
        - EtherNet/IP Security (0x5E): capabilities, cipher suites, PSKs
        - Certificate Management (0x5F): installed certs, trust anchors
        - Password Authenticator (0x61): password policy, lockout settings
        """
        security_dump = {
            "cip_security": None,
            "eip_security": None,
            "certificates": None,
            "password_auth": None,
        }

        self.logger.debug("Dumping CIP Security settings...")

        if not conn or not hasattr(conn, "generic_message"):
            self.logger.debug("Connection does not support security dump operations")
            return security_dump

        # CIP Security Object (0x5D)
        cip_sec = self._dump_cip_security_object(conn)
        if cip_sec:
            security_dump["cip_security"] = cip_sec

        # EtherNet/IP Security Object (0x5E)
        eip_sec = self._dump_eip_security_object(conn)
        if eip_sec:
            security_dump["eip_security"] = eip_sec

        # Certificate Management Object (0x5F)
        cert_mgmt = self._dump_certificate_management(conn)
        if cert_mgmt:
            security_dump["certificates"] = cert_mgmt

        # Password Authenticator Object (0x61)
        pwd_auth = self._dump_password_authenticator(conn)
        if pwd_auth:
            security_dump["password_auth"] = pwd_auth

        return security_dump

    def _dump_cip_security_object(self, conn: Any) -> Optional[Dict[str, Any]]:
        """Dump CIP Security Object (0x5D) attributes"""
        info = {"class_id": 0x5D, "class_name": "CIP Security"}

        # Attr 1: State (USINT)
        state_data = self._read_cip_attribute(conn, 0x5D, 1, 1)
        if state_data is None:
            return None

        info["accessible"] = True

        if len(state_data) >= 1:
            state = state_data[0]
            state_names = {
                0: "Factory Default",
                1: "Configuring",
                2: "Configured",
                3: "Incomplete Configuration",
            }
            info["state"] = state_names.get(state, f"Unknown ({state})")
            info["state_raw"] = state
            self.logger.debug(f"  CIP Security State: {info['state']}")

        # Attr 2: Security Profiles Supported (UINT bitmask)
        profiles_data = self._read_cip_attribute(conn, 0x5D, 1, 2)
        if profiles_data and len(profiles_data) >= 2:
            profiles = struct.unpack("<H", profiles_data[:2])[0]
            info["profiles_raw"] = profiles
            info["profiles"] = []
            if profiles & 0x01:
                info["profiles"].append("EtherNet/IP Confidentiality")
            if profiles & 0x02:
                info["profiles"].append("CIP Authorization")
            if profiles & 0x04:
                info["profiles"].append("CIP User Authentication")
            if profiles & 0x08:
                info["profiles"].append("Resource-Constrained")
            self.logger.debug(f"  Security Profiles: {', '.join(info['profiles']) or 'None'}")

        # Attr 3: Active Security Profile (USINT)
        active_data = self._read_cip_attribute(conn, 0x5D, 1, 3)
        if active_data and len(active_data) >= 1:
            info["active_profile"] = active_data[0]
            self.logger.debug(f"  Active Profile: {info['active_profile']}")

        return info

    def _dump_eip_security_object(self, conn: Any) -> Optional[Dict[str, Any]]:
        """Dump EtherNet/IP Security Object (0x5E) attributes"""
        info = {"class_id": 0x5E, "class_name": "EtherNet/IP Security"}

        # Attr 1: State (USINT)
        state_data = self._read_cip_attribute(conn, 0x5E, 1, 1)
        if state_data is None:
            return None

        info["accessible"] = True

        if len(state_data) >= 1:
            state = state_data[0]
            state_names = {0: "Factory Default", 1: "Configured", 2: "Operational"}
            info["state"] = state_names.get(state, f"Unknown ({state})")
            self.logger.debug(f"  EIP Security State: {info['state']}")

        # Attr 2: Capability Flags (USINT)
        caps_data = self._read_cip_attribute(conn, 0x5E, 1, 2)
        if caps_data and len(caps_data) >= 1:
            caps = caps_data[0]
            info["capabilities_raw"] = caps
            info["capabilities"] = []
            if caps & 0x01:
                info["capabilities"].append("TLS 1.2")
            if caps & 0x02:
                info["capabilities"].append("TLS 1.3")
            if caps & 0x04:
                info["capabilities"].append("DTLS 1.2")
            if caps & 0x08:
                info["capabilities"].append("Pre-Shared Keys")
            if caps & 0x10:
                info["capabilities"].append("Certificates")
            self.logger.debug(f"  Capabilities: {', '.join(info['capabilities'])}")

        # Attr 4: Number of Pre-Shared Keys (USINT)
        psk_data = self._read_cip_attribute(conn, 0x5E, 1, 4)
        if psk_data and len(psk_data) >= 1:
            info["psk_count"] = psk_data[0]
            self.logger.debug(f"  Pre-Shared Keys: {info['psk_count']} configured")

        # Attr 5: Active PSK Slot (USINT)
        active_psk = self._read_cip_attribute(conn, 0x5E, 1, 5)
        if active_psk and len(active_psk) >= 1:
            info["active_psk_slot"] = active_psk[0]

        return info

    def _dump_certificate_management(self, conn: Any) -> Optional[Dict[str, Any]]:
        """Dump Certificate Management Object (0x5F) attributes"""
        info = {"class_id": 0x5F, "class_name": "Certificate Management"}

        # Attr 1: State (USINT)
        state_data = self._read_cip_attribute(conn, 0x5F, 1, 1)
        if state_data is None:
            return None

        info["accessible"] = True

        if len(state_data) >= 1:
            info["state"] = "Certificates Present" if state_data[0] else "No Certificates"
            self.logger.debug(f"  Certificate State: {info['state']}")

        # Attr 2: Max Certificates (USINT)
        max_certs = self._read_cip_attribute(conn, 0x5F, 1, 2)
        if max_certs and len(max_certs) >= 1:
            info["max_certificates"] = max_certs[0]

        # Attr 3: Installed Certificates (USINT)
        installed = self._read_cip_attribute(conn, 0x5F, 1, 3)
        if installed and len(installed) >= 1:
            info["installed_certificates"] = installed[0]
            self.logger.debug(
                f"  Installed Certs: {info['installed_certificates']}/{info.get('max_certificates', '?')}"
            )

        # Attr 6: Device Certificate CN (SHORT_STRING)
        cn_data = self._read_cip_attribute(conn, 0x5F, 1, 6)
        if cn_data and len(cn_data) >= 2:
            cn_len = struct.unpack("<H", cn_data[:2])[0]
            if len(cn_data) >= 2 + cn_len:
                info["device_cert_cn"] = cn_data[2 : 2 + cn_len].decode("ascii", errors="replace")
                self.logger.debug(f"  Device Cert CN: {info['device_cert_cn']}")

        # Download actual certificates from instances
        info["certificates"] = []
        num_certs = info.get("installed_certificates", 0)
        for inst in range(1, num_certs + 1):
            cert_info = self._download_certificate_instance(conn, inst)
            if cert_info:
                info["certificates"].append(cert_info)
                size = cert_info.get("raw_size", 0)
                subject = cert_info.get("subject", "Unknown")
                self.logger.debug(f"  Cert {inst}: {subject} ({size} bytes)")

        return info

    def _download_certificate_instance(self, conn: Any, instance: int) -> Optional[Dict[str, Any]]:
        """Download a single certificate from Certificate Management Object instance."""
        cert_info = {"instance": instance}

        # Attr 1: Certificate State (USINT)
        state = self._read_cip_attribute(conn, 0x5F, instance, 1)
        if state is None:
            return None
        cert_info["state"] = state[0] if state else 0

        # Attr 2: Device Type (USINT) - what this cert is for
        dev_type = self._read_cip_attribute(conn, 0x5F, instance, 2)
        if dev_type and len(dev_type) >= 1:
            type_names = {0: "Device", 1: "CA/Trust Anchor", 2: "CRL"}
            cert_info["type"] = type_names.get(dev_type[0], f"Unknown ({dev_type[0]})")

        # Attr 3: Certificate Format (USINT)
        fmt = self._read_cip_attribute(conn, 0x5F, instance, 3)
        if fmt and len(fmt) >= 1:
            fmt_names = {1: "DER", 2: "PEM"}
            cert_info["format"] = fmt_names.get(fmt[0], f"Unknown ({fmt[0]})")

        # Attr 4: Certificate Data (ARRAY of USINT)
        cert_data = self._read_cip_attribute(conn, 0x5F, instance, 4)
        if cert_data and len(cert_data) > 2:
            # First 2 bytes are array length
            data_len = struct.unpack("<H", cert_data[:2])[0]
            raw_cert = cert_data[2 : 2 + data_len]
            cert_info["raw"] = base64.b64encode(raw_cert).decode("ascii")
            cert_info["raw_size"] = len(raw_cert)

            # Try to parse certificate for subject/issuer
            try:
                self._parse_certificate_info(cert_info, raw_cert)
            except Exception as e:
                self.logger.debug(f"download certificate instance failed: {e}")
                pass  # Certificate parsing is optional

        return cert_info

    def _parse_certificate_info(self, cert_info: Dict[str, Any], raw_cert: bytes) -> None:
        """Parse X.509 certificate to extract subject/issuer/validity."""
        try:
            _cryptography()  # Ensure cryptography is available
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            # Try DER first, then PEM
            try:
                cert = x509.load_der_x509_certificate(raw_cert, default_backend())
            except Exception as e:
                self.logger.debug(f"parse certificate info failed: {e}")
                cert = x509.load_pem_x509_certificate(raw_cert, default_backend())

            cert_info["subject"] = cert.subject.rfc4514_string()
            cert_info["issuer"] = cert.issuer.rfc4514_string()
            cert_info["serial"] = format(cert.serial_number, "x")
            cert_info["not_before"] = cert.not_valid_before_utc.isoformat()
            cert_info["not_after"] = cert.not_valid_after_utc.isoformat()

            # Check if self-signed
            cert_info["self_signed"] = cert.subject == cert.issuer

        except Exception as e:
            self.logger.debug(f"parse certificate info failed: {e}")
            cert_info["parse_error"] = str(e)

    def _dump_password_authenticator(self, conn: Any) -> Optional[Dict[str, Any]]:
        """Dump Password Authenticator Object (0x61) attributes"""
        info = {"class_id": 0x61, "class_name": "Password Authenticator"}

        # Attr 1: State (USINT)
        state_data = self._read_cip_attribute(conn, 0x61, 1, 1)
        if state_data is None:
            return None

        info["accessible"] = True

        if len(state_data) >= 1:
            info["enabled"] = bool(state_data[0])
            self.logger.display(f"  Password Auth: {'Enabled' if info['enabled'] else 'Disabled'}")

        # Attr 2: Password Configured (BOOL)
        pwd_cfg = self._read_cip_attribute(conn, 0x61, 1, 2)
        if pwd_cfg and len(pwd_cfg) >= 1:
            info["password_configured"] = bool(pwd_cfg[0])
            self.logger.display(f"  Password Set: {'Yes' if info['password_configured'] else 'No'}")

        # Attr 3: Max Password Length (USINT)
        max_len = self._read_cip_attribute(conn, 0x61, 1, 3)
        if max_len and len(max_len) >= 1:
            info["max_password_length"] = max_len[0]

        # Attr 4: Min Password Length (USINT)
        min_len = self._read_cip_attribute(conn, 0x61, 1, 4)
        if min_len and len(min_len) >= 1:
            info["min_password_length"] = min_len[0]
            self.logger.display(
                f"  Password Length: {info['min_password_length']}-{info.get('max_password_length', '?')} chars"
            )

        # Attr 5: Failed Attempts (UDINT)
        failed = self._read_cip_attribute(conn, 0x61, 1, 5)
        if failed and len(failed) >= 4:
            info["failed_attempts"] = struct.unpack("<I", failed[:4])[0]
            if info["failed_attempts"] > 0:
                self.logger.warning(f"  Failed Login Attempts: {info['failed_attempts']}")

        # Attr 6: Lockout Time (UDINT)
        lockout = self._read_cip_attribute(conn, 0x61, 1, 6)
        if lockout and len(lockout) >= 4:
            info["lockout_time_seconds"] = struct.unpack("<I", lockout[:4])[0]
            self.logger.display(f"  Lockout Time: {info['lockout_time_seconds']} seconds")

        return info
