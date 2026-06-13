"""
OPC UA Security Mixin

Provides security analysis, auditing checks, and certificate validation functionality.
"""

import asyncio
import os
from typing import TYPE_CHECKING

from ....utils.lazy_import import lazy_import


_asyncua_cert_gen = lazy_import(
    "asyncua.crypto.cert_gen", "OPC UA", install_hint="pip install asyncua"
)
_asyncua_sec_policies = lazy_import(
    "asyncua.crypto.security_policies", "OPC UA", install_hint="pip install asyncua"
)
_asyncua_validator = lazy_import(
    "asyncua.crypto.validator", "OPC UA", install_hint="pip install asyncua"
)
_cryptography_x509 = lazy_import("cryptography", "OPC UA", install_hint="pip install cryptography")

if TYPE_CHECKING:
    pass


class SecurityMixin:
    """Mixin providing OPC UA security analysis functionality."""

    async def _check_server_security(self):
        """Check server security configuration by reading namespace 0 nodes.

        Checks:
        1. Auditing status (i=2994)
        2. RBAC support via ServerProfileArray (i=2269)
        3. Diagnostics enabled (i=2294)
        4. Security rejection counts (i=2279, i=2287)
        5. Current session count (i=2277)
        6. Session diagnostics array (i=3707) - client app, connection time, subscriptions
        7. Session security diagnostics (i=3708) - user IDs, auth mechanism, security mode
        8. Redundancy support (i=3709)
        """
        security_info = {}

        # 1. Auditing (OpalOPC 10002)
        try:
            auditing_node = self._client.get_node("ns=0;i=2994")
            auditing_enabled = await auditing_node.read_value()
            security_info["auditing"] = auditing_enabled
            if not auditing_enabled:
                self.logger.security_finding(
                    "Insecure configuration", detail="Auditing disabled - no activity logging"
                )
            else:
                self.logger.display("  Auditing: enabled")
        except Exception as e:
            self.logger.debug(f"Could not read auditing: {e}")

        # 2. RBAC support via ServerProfileArray (OpalOPC 10004)
        try:
            profile_node = self._client.get_node("ns=0;i=2269")
            profiles = await profile_node.read_value()
            security_info["server_profiles"] = profiles if profiles else []

            # Check for RBAC-related profiles
            rbac_profiles = [
                "http://opcfoundation.org/UA-Profile/Security/UserAccessFull",
                "Security User Access Control Full",
                "http://opcfoundation.org/UA-Profile/UAFX-Controller-Server-Profile",
                "UAFX Controller Server Profile",
            ]
            has_rbac = any(p in (profiles or []) for p in rbac_profiles)
            security_info["rbac_supported"] = has_rbac

            if profiles:
                self.logger.display(f"  Profiles: {len(profiles)} loaded")
                if has_rbac:
                    self.logger.display("  RBAC: supported (profile advertised)")
                else:
                    self.logger.warning("  RBAC: not advertised in server profiles")
        except Exception as e:
            self.logger.debug(f"Could not read server profiles: {e}")

        # 3. Diagnostics enabled flag (i=2294)
        try:
            diag_node = self._client.get_node("ns=0;i=2294")
            diag_enabled = await diag_node.read_value()
            security_info["diagnostics_enabled"] = diag_enabled
            if diag_enabled:
                self.logger.display("  Diagnostics: enabled (may leak info)")
        except Exception as e:
            self.logger.debug(f"Could not read diagnostics flag: {e}")

        # 4. Security rejection counts (indicates attacks or misconfigs)
        try:
            rejected_sessions_node = self._client.get_node("ns=0;i=2279")
            rejected_sessions = await rejected_sessions_node.read_value()
            security_info["security_rejected_sessions"] = rejected_sessions
            if rejected_sessions and rejected_sessions > 0:
                self.logger.display(f"  Security rejected sessions: {rejected_sessions}")
        except Exception as e:
            self.logger.debug(f"Failed to get rejected_sessions_node: {e}")

        try:
            rejected_requests_node = self._client.get_node("ns=0;i=2287")
            rejected_requests = await rejected_requests_node.read_value()
            security_info["security_rejected_requests"] = rejected_requests
            if rejected_requests and rejected_requests > 0:
                self.logger.display(f"  Security rejected requests: {rejected_requests}")
        except Exception as e:
            self.logger.debug(f"Failed to get rejected_requests_node: {e}")

        # 5. Current session count (reconnaissance)
        try:
            session_count_node = self._client.get_node("ns=0;i=2277")
            session_count = await session_count_node.read_value()
            security_info["current_session_count"] = session_count
            if session_count:
                self.logger.display(f"  Active sessions: {session_count}")
        except Exception as e:
            self.logger.debug(f"Failed to get session_count_node: {e}")

        # 6. Session diagnostics array (i=3707) - detailed session info
        try:
            session_diag_node = self._client.get_node("ns=0;i=3707")
            session_diag = await session_diag_node.read_value()
            if session_diag:
                sessions = []
                for sess in session_diag:
                    session_info = {}
                    # Extract available fields
                    if hasattr(sess, "SessionId"):
                        session_info["session_id"] = str(sess.SessionId)
                    if hasattr(sess, "SessionName"):
                        session_info["session_name"] = sess.SessionName
                    if hasattr(sess, "ClientDescription") and sess.ClientDescription:
                        cd = sess.ClientDescription
                        session_info["client_app"] = getattr(cd, "ApplicationName", None)
                        if hasattr(session_info["client_app"], "Text"):
                            session_info["client_app"] = session_info["client_app"].Text
                        session_info["client_uri"] = getattr(cd, "ApplicationUri", None)
                    if hasattr(sess, "EndpointUrl"):
                        session_info["endpoint_url"] = sess.EndpointUrl
                    if hasattr(sess, "ClientConnectionTime"):
                        session_info["connected_since"] = str(sess.ClientConnectionTime)
                    if hasattr(sess, "ClientLastContactTime"):
                        session_info["last_contact"] = str(sess.ClientLastContactTime)
                    if hasattr(sess, "CurrentSubscriptionsCount"):
                        session_info["subscriptions"] = sess.CurrentSubscriptionsCount
                    if hasattr(sess, "CurrentMonitoredItemsCount"):
                        session_info["monitored_items"] = sess.CurrentMonitoredItemsCount
                    sessions.append(session_info)

                security_info["sessions"] = sessions
                if sessions:
                    self.logger.display(f"  Session details ({len(sessions)} active):")
                    for s in sessions:
                        name = s.get("session_name", "unknown")
                        client = s.get("client_app", s.get("client_uri", "unknown"))
                        self.logger.display(f"    - {name}: {client}")
                        if s.get("connected_since"):
                            self.logger.display(f"      Connected: {s['connected_since']}")
        except Exception as e:
            self.logger.debug(f"Could not read session diagnostics: {e}")

        # 7. Session security diagnostics (i=3708) - auth info per session
        try:
            sec_diag_node = self._client.get_node("ns=0;i=3708")
            sec_diag = await sec_diag_node.read_value()
            if sec_diag:
                session_security = []
                for sess in sec_diag:
                    sec_info = {}
                    if hasattr(sess, "SessionId"):
                        sec_info["session_id"] = str(sess.SessionId)
                    if hasattr(sess, "ClientUserIdOfSession"):
                        sec_info["username"] = sess.ClientUserIdOfSession
                    if hasattr(sess, "ClientUserIdHistory"):
                        # Previous usernames if identity changed during session
                        history = sess.ClientUserIdHistory
                        if history:
                            sec_info["username_history"] = list(history)
                    if hasattr(sess, "AuthenticationMechanism"):
                        sec_info["auth_mechanism"] = sess.AuthenticationMechanism
                    if hasattr(sess, "Encoding"):
                        sec_info["encoding"] = sess.Encoding
                    if hasattr(sess, "TransportProtocol"):
                        sec_info["transport"] = sess.TransportProtocol
                    if hasattr(sess, "SecurityMode"):
                        sec_info["security_mode"] = str(sess.SecurityMode)
                    if hasattr(sess, "SecurityPolicyUri"):
                        policy = sess.SecurityPolicyUri
                        if policy:
                            # Extract just the policy name
                            sec_info["security_policy"] = (
                                policy.split("/")[-1] if "/" in policy else policy
                            )
                    if hasattr(sess, "ClientCertificate") and sess.ClientCertificate:
                        # Client used certificate authentication
                        try:
                            from cryptography import x509

                            cert = x509.load_der_x509_certificate(bytes(sess.ClientCertificate))
                            sec_info["client_cert_subject"] = cert.subject.rfc4514_string()
                            sec_info["client_cert_issuer"] = cert.issuer.rfc4514_string()
                        except Exception:
                            sec_info["client_cert"] = "present (parse failed)"
                    session_security.append(sec_info)

                security_info["session_security"] = session_security

                # Display connected users with details
                if session_security:
                    self.logger.display("  Connected clients:")
                    for s in session_security:
                        username = s.get("username", "unknown")
                        auth = s.get("auth_mechanism", "")
                        mode = s.get("security_mode", "")
                        policy = s.get("security_policy", "")

                        # Format: username (auth) via SecurityMode/Policy
                        details = []
                        if auth:
                            details.append(auth)
                        if mode or policy:
                            details.append(f"{mode}/{policy}" if policy else mode)

                        detail_str = f" ({', '.join(details)})" if details else ""
                        self.logger.display(f"    - {username}{detail_str}")

                        # Show client cert subject if present
                        if s.get("client_cert_subject"):
                            self.logger.display(f"      Cert: {s['client_cert_subject']}")
        except Exception as e:
            err_str = str(e)
            if "BadSecurityModeInsufficient" in err_str:
                self.logger.display("  User info: requires secure channel (SignAndEncrypt)")
            else:
                self.logger.debug(f"Could not read session security diagnostics: {e}")

        # 8. Redundancy support (i=3709)
        try:
            redundancy_node = self._client.get_node("ns=0;i=3709")
            redundancy = await redundancy_node.read_value()
            if redundancy is not None:
                # RedundancySupport enum: 0=None, 1=Cold, 2=Warm, 3=Hot, 4=Transparent
                redundancy_names = ["None", "Cold", "Warm", "Hot", "Transparent"]
                red_name = (
                    redundancy_names[redundancy]
                    if 0 <= redundancy < len(redundancy_names)
                    else str(redundancy)
                )
                security_info["redundancy_support"] = red_name
                if redundancy > 0:
                    self.logger.display(f"  Redundancy: {red_name}")
        except Exception as e:
            self.logger.debug(f"Failed to get redundancy_node: {e}")

        # Store results
        self.results["data"]["security_info"] = security_info
        return security_info

    async def _generate_client_cert(self) -> tuple:
        """Generate a temporary client certificate for secure channel.

        Uses asyncua's cert_gen for proper OPC UA compliant certificates.

        Returns:
            Tuple of (cert_path, key_path) for temp cert files
        """
        import tempfile
        import socket
        from pathlib import Path

        try:
            if not _asyncua_cert_gen.is_available or not _cryptography_x509.is_available:
                self.logger.debug("asyncua cert_gen or cryptography not available")
                return None, None

            setup_self_signed_certificate = _asyncua_cert_gen.setup_self_signed_certificate
            ExtendedKeyUsageOID = _cryptography_x509.x509.oid.ExtendedKeyUsageOID

            # Create temp files for cert and key
            temp_dir = Path(tempfile.gettempdir())
            cert_path = temp_dir / f"oida_client_{os.getpid()}.der"
            key_path = temp_dir / f"oida_client_{os.getpid()}.pem"

            host_name = socket.gethostname()
            app_uri = f"urn:{host_name}:oida:client"

            # Generate proper OPC UA certificate using asyncua
            await setup_self_signed_certificate(
                key_path,
                cert_path,
                app_uri,
                host_name,
                [ExtendedKeyUsageOID.CLIENT_AUTH],
                {
                    "countryName": "US",
                    "organizationName": "OIDA",
                },
            )

            self.logger.debug(f"Generated client cert: {cert_path}")

            # Store app_uri for client configuration
            self._client_app_uri = app_uri

            return str(cert_path), str(key_path)

        except Exception as e:
            self.logger.debug(f"Error generating client cert: {e}")
            return None, None

    async def _test_self_signed_cert_acceptance(self, url: str) -> dict:
        """Test if server accepts untrusted self-signed client certificates.

        Security check: Servers should verify client certificates against a
        trust list. If they accept any self-signed cert, attackers can
        establish secure channels without pre-registration.

        This is different from user authentication - this tests if the
        secure channel (Sign/SignAndEncrypt) can be established with an
        untrusted client certificate.
        """
        import tempfile
        import socket
        from pathlib import Path
        from ..helpers import _get_client_class

        result = {
            "accepts_untrusted_client_cert": False,
            "tested": False,
        }

        cert_path = None
        key_path = None

        try:
            if not _asyncua_cert_gen.is_available or not _cryptography_x509.is_available:
                self.logger.debug("asyncua crypto or cryptography not available")
                result["error"] = "asyncua crypto not available"
                return result

            setup_self_signed_certificate = _asyncua_cert_gen.setup_self_signed_certificate
            SecurityPolicyBasic256Sha256 = _asyncua_sec_policies.SecurityPolicyBasic256Sha256
            CertificateValidator = _asyncua_validator.CertificateValidator
            CertificateValidatorOptions = _asyncua_validator.CertificateValidatorOptions
            ExtendedKeyUsageOID = _cryptography_x509.x509.oid.ExtendedKeyUsageOID

            self.logger.display("Testing if server accepts untrusted client certs...")

            # Generate proper OPC UA certificate
            temp_dir = Path(tempfile.gettempdir())
            cert_path = temp_dir / f"oida_test_{os.getpid()}.der"
            key_path = temp_dir / f"oida_test_{os.getpid()}.pem"

            host_name = socket.gethostname()
            app_uri = f"urn:{host_name}:oida:attacker-test"

            await setup_self_signed_certificate(
                key_path,
                cert_path,
                app_uri,
                host_name,
                [ExtendedKeyUsageOID.CLIENT_AUTH],
                {
                    "countryName": "XX",
                    "organizationName": "Attacker",
                    "commonName": "Untrusted Client",
                },
            )

            try:
                # Try to connect with untrusted self-signed cert
                Client = _get_client_class()
                test_client = Client(url=url, timeout=10)
                test_client.application_uri = app_uri

                # Don't validate server cert (we're testing server's validation of us)
                validator = CertificateValidator(CertificateValidatorOptions.EXT_VALIDATION)
                test_client.certificate_validator = validator

                await test_client.set_security(
                    SecurityPolicyBasic256Sha256,
                    certificate=str(cert_path),
                    private_key=str(key_path),
                )

                await test_client.connect()
                await test_client.disconnect()

                # If we got here, server accepted untrusted cert - vulnerability!
                result["accepts_untrusted_client_cert"] = True
                result["tested"] = True
                self.logger.warning("Server ACCEPTS untrusted client certificates!")
                self.logger.warning(
                    "  Attackers can establish secure channels without registration"
                )

            except asyncio.TimeoutError:
                # Timeout usually means server rejected/didn't respond to our cert
                result["tested"] = True
                result["rejection_reason"] = "Connection timeout (likely rejected)"
                self.logger.success("Server rejects untrusted client certificates")
            except Exception as e:
                err_str = str(e).lower()
                err_type = type(e).__name__.lower()
                # Check for certificate rejection errors
                if any(
                    x in err_str or x in err_type
                    for x in [
                        "badcertificate",
                        "untrusted",
                        "rejected",
                        "securitychecksfailed",
                        "timeout",
                        "certificate",
                    ]
                ):
                    result["tested"] = True
                    result["rejection_reason"] = str(e)[:100]
                    self.logger.success("Server rejects untrusted client certificates")
                else:
                    result["tested"] = True
                    result["error"] = str(e)[:100]
                    self.logger.debug(f"Cert test error: {e}")

        except Exception as e:
            self.logger.debug(f"Self-signed cert test error: {e}")
            result["error"] = str(e)
        finally:
            # Cleanup temp files
            if cert_path and cert_path.exists():
                os.unlink(cert_path)
            if key_path and key_path.exists():
                os.unlink(key_path)

        return result

    async def _check_certificate(self):
        """Check server certificate for security issues using central checker"""
        try:
            from oida.utils.security_findings import display_cert_info

            endpoints = await self._client.get_endpoints()
            target = f"{self.host}:{getattr(self.args, 'port', 4840)}"

            for ep in endpoints:
                cert_bytes = ep.ServerCertificate
                if not cert_bytes:
                    continue

                # Use central display function for certificate info and security checks
                info = display_cert_info(
                    logger=self.logger,
                    cert=cert_bytes,
                    protocol="opcua",
                    target=target,
                    verbose=getattr(self, "debug", False),
                )

                # Store issues in results
                self.results["data"]["certificate_issues"] = info.get("issues", [])
                break  # Only check first certificate

        except Exception as e:
            self.logger.fail(f"Certificate check error: {e}")
