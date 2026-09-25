"""
OPC UA Security Mixin

Provides security analysis, auditing checks, and certificate validation functionality.
"""

import asyncio
import os


from oida.utils.lazy_import import lazy_import

_asyncua_cert_gen = lazy_import(
    "asyncua.crypto.cert_gen", "OPC UA", install_hint="pip install oida-ics[opcua]"
)
_asyncua_sec_policies = lazy_import(
    "asyncua.crypto.security_policies", "OPC UA", install_hint="pip install oida-ics[opcua]"
)
_cryptography_x509 = lazy_import(
    "cryptography", "OPC UA", install_hint="pip install oida-ics[opcua]"
)


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
                    "Insecure configuration",
                    detail="Auditing disabled - no activity logging",
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

        cert_path = None
        key_path = None
        try:
            if not _asyncua_cert_gen.is_available or not _cryptography_x509.is_available:
                self.logger.debug("asyncua cert_gen or cryptography not available")
                return None, None

            setup_self_signed_certificate = _asyncua_cert_gen.setup_self_signed_certificate
            ExtendedKeyUsageOID = _cryptography_x509.x509.oid.ExtendedKeyUsageOID

            # Create uniquely-named temp files for cert and key. A fixed
            # oida_client_{pid}.der/.pem name is reused by every concurrent
            # target scanned in this process (the CLI thread-pools multiple
            # targets under one PID) - two targets racing the same path can
            # clobber each other's cert mid-generation/read, and the file
            # was never unlinked, leaving a private key world-readable in
            # shared temp indefinitely. mkstemp() gives each call a unique
            # path and creates the file mode 0600 (owner-only). The caller
            # (cli_runner._async_proto_flow) unlinks both paths once the
            # secure channel is established.
            cert_fd, cert_name = tempfile.mkstemp(prefix="oida_client_", suffix=".der")
            os.close(cert_fd)
            key_fd, key_name = tempfile.mkstemp(prefix="oida_client_", suffix=".pem")
            os.close(key_fd)
            # mkstemp reserves a unique name but CREATES the (empty) file;
            # setup_self_signed_certificate only generates when the files are
            # ABSENT and otherwise tries to load them -- an empty file raises
            # "Unable to load PEM file (MalformedFraming)". Remove them so the
            # cert/key are freshly generated at these unique paths.
            os.unlink(cert_name)
            os.unlink(key_name)
            cert_path = Path(cert_name)
            key_path = Path(key_name)

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
            for p in (cert_path, key_path):
                try:
                    if p and p.exists():
                        os.unlink(p)
                except OSError:
                    pass
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
        from oida.protocols.opcua.helpers import _get_client_class

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
            ExtendedKeyUsageOID = _cryptography_x509.x509.oid.ExtendedKeyUsageOID

            self.logger.display("Testing if server accepts untrusted client certs...")

            # Generate proper OPC UA certificate. Use mkstemp (unique name,
            # 0600) rather than a fixed oida_test_{pid} path: the CLI thread-
            # pools multiple targets under one PID, so a shared path would let
            # concurrent scans clobber each other's private key and leave it at
            # a predictable world-readable location (CWE-377).
            cert_fd, cert_name = tempfile.mkstemp(prefix="oida_test_", suffix=".der")
            key_fd, key_name = tempfile.mkstemp(prefix="oida_test_", suffix=".pem")
            os.close(cert_fd)
            os.close(key_fd)
            # See note in _test_self_signed_cert_acceptance: remove the empty
            # mkstemp files so setup_self_signed_certificate regenerates them.
            os.unlink(cert_name)
            os.unlink(key_name)
            cert_path = Path(cert_name)
            key_path = Path(key_name)

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

                # Deliberately leave certificate_validator unset (asyncua's
                # default = None => accept any server cert). We are probing
                # whether the *server* trusts *our* untrusted client cert; we
                # must not abort because the server's own cert is imperfect.
                # Setting EXT_VALIDATION here made the client reject servers
                # whose cert lacked a matching URI / KeyUsage, masking the
                # actual result (the server's cert is assessed by
                # _check_certificate instead).

                await test_client.set_security(
                    SecurityPolicyBasic256Sha256,
                    certificate=str(cert_path),
                    private_key=str(key_path),
                )

                await test_client.connect()

                # If we got here, server accepted untrusted cert - vulnerability!
                # Record the verdict BEFORE attempting disconnect: a disconnect-time
                # error must never be allowed to fall through to the outer except
                # and get misread as a clean rejection.
                result["accepts_untrusted_client_cert"] = True
                result["tested"] = True
                self.logger.warning("Server ACCEPTS untrusted client certificates!")
                self.logger.warning(
                    "  Attackers can establish secure channels without registration"
                )

                try:
                    await test_client.disconnect()
                except Exception as disc_err:
                    self.logger.debug(f"Disconnect after cert test failed: {disc_err}")

            except asyncio.TimeoutError:
                # A timeout (firewall drop, packet loss, slow/overloaded server)
                # says nothing about whether the server validated the client cert.
                # Do NOT assert the server is clean - report inconclusive.
                result["tested"] = False
                result["status"] = "inconclusive"
                result["error"] = "Connection timeout (could not determine)"
                self.logger.warning(
                    "Could not determine if server accepts untrusted certs (timeout)"
                )
            except Exception as e:
                err = (str(e) + " " + type(e).__name__).lower()
                # Channel/cert-trust rejection: the server validated our untrusted
                # application cert and refused the secure channel. This is the ONLY
                # outcome that proves the server is not vulnerable. These are
                # specific trust-decision codes - a bare "badcertificate" substring
                # also matches format errors (BadCertificateUriInvalid /
                # TimeInvalid) that say nothing about the trust list, so it is
                # excluded; BadCertificateInvalid IS included because servers use
                # it as a catch-all when refusing an untrusted client cert.
                channel_rejected = any(
                    x in err
                    for x in [
                        "badsecuritychecksfailed",
                        "securitychecksfailed",
                        "badcertificateuntrusted",
                        "badcertificateinvalid",
                        "untrusted",
                    ]
                )
                # Session-level auth failure: reaching ActivateSession means the
                # secure channel was ALREADY established with our untrusted cert
                # (create_session ran the server's cert validation and passed) -
                # only the anonymous user identity was refused. This is evidence
                # the app-cert trust check is weak, NOT a rejection. The old code
                # lumped these codes into "rejected" (false negative); they now
                # surface the channel acceptance and ask for creds to confirm.
                #
                # NOTE: the *user*-cert probe (_test_self_signed_user_cert_acceptance)
                # deliberately treats these same codes as a clean rejection - there
                # the user cert IS the trust-checked identity, so a refusal is the
                # correct-secure outcome. Do not "unify" the two lists.
                session_reached = any(x in err for x in ["baduseraccessdenied", "badidentitytoken"])
                if channel_rejected:
                    result["tested"] = True
                    result["rejection_reason"] = str(e)[:100]
                    self.logger.success("Server rejects untrusted client certificates")
                elif session_reached:
                    result["tested"] = False
                    result["status"] = "inconclusive"
                    result["channel_established"] = True
                    result["error"] = str(e)[:100]
                    self.logger.warning(
                        "Secure channel established with untrusted client cert, but no "
                        "anonymous session - rerun with -u/-P to confirm app-cert trust"
                    )
                else:
                    # Unrelated/ambiguous error - cannot conclude either way.
                    result["tested"] = False
                    result["status"] = "inconclusive"
                    result["error"] = str(e)[:100]
                    self.logger.warning("Could not determine if server accepts untrusted certs")
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

    async def _test_self_signed_user_cert_acceptance(self, endpoints) -> dict:
        """Test if the server accepts an untrusted self-signed X509 *user* certificate.

        This is distinct from ``_test_self_signed_cert_acceptance`` (which tests
        the application / secure-channel certificate). Here we present a freshly
        generated self-signed certificate as a **user identity token**
        (``X509IdentityToken``). A server that activates a session with it does
        not validate user certificates against a trust list - equivalent to
        OpalOPC plugin 10016.

        Only meaningful on endpoints that advertise a ``Certificate`` user
        token; returns ``{"applicable": False}`` otherwise.

        We prefer a ``SecurityPolicy=None`` cert-token endpoint so the result
        isolates the *user*-cert trust decision. The policy-endpoint fallback
        (when no None endpoint exists) opens a secure channel with an auto app
        cert first, so a server that rejects that *app* cert at the channel
        layer would surface as a user-cert rejection - a known limitation of
        the fallback path; the None-policy path is unaffected.
        """
        import tempfile
        import socket
        from pathlib import Path
        from oida.protocols.opcua.helpers import _get_client_class, ua

        result = {
            "applicable": False,
            "accepts_untrusted_user_cert": False,
            "tested": False,
        }

        # 1. Applicability: find endpoints advertising a Certificate user token.
        cert_token_endpoints = []
        for ep in endpoints:
            for token in getattr(ep, "UserIdentityTokens", None) or []:
                ttype = getattr(token, "TokenType", None)
                tname = getattr(ttype, "name", None) or str(ttype)
                if tname == "Certificate":
                    cert_token_endpoints.append(ep)
                    break

        if not cert_token_endpoints:
            self.logger.debug("No Certificate user-token endpoint; skipping user-cert trust test")
            return result

        result["applicable"] = True

        # Prefer an endpoint with SecurityPolicy None (no app/secure-channel
        # cert required) so we isolate the *user* cert trust decision; fall back
        # to a policy endpoint (needs a secure channel we set up with an
        # auto-generated app cert).
        def _policy(ep):
            return (ep.SecurityPolicyUri or "").split("#")[-1]

        target = next((ep for ep in cert_token_endpoints if _policy(ep) == "None"), None)
        needs_secure_channel = target is None
        if target is None:
            target = cert_token_endpoints[0]

        cert_path = None
        key_path = None
        app_cert_path = None
        app_key_path = None
        try:
            if not _asyncua_cert_gen.is_available or not _cryptography_x509.is_available:
                self.logger.debug("asyncua crypto or cryptography not available")
                result["error"] = "asyncua crypto not available"
                return result

            setup_self_signed_certificate = _asyncua_cert_gen.setup_self_signed_certificate
            ExtendedKeyUsageOID = _cryptography_x509.x509.oid.ExtendedKeyUsageOID

            self.logger.display("Testing if server accepts untrusted self-signed user certs...")

            # Unique 0600 temp files per call (see _test_self_signed_cert_
            # acceptance) - avoids the shared oida_user_{pid} race/CWE-377.
            cert_fd, cert_name = tempfile.mkstemp(prefix="oida_user_", suffix=".der")
            key_fd, key_name = tempfile.mkstemp(prefix="oida_user_", suffix=".pem")
            os.close(cert_fd)
            os.close(key_fd)
            # See note in _test_self_signed_cert_acceptance: remove the empty
            # mkstemp files so setup_self_signed_certificate regenerates them.
            os.unlink(cert_name)
            os.unlink(key_name)
            cert_path = Path(cert_name)
            key_path = Path(key_name)
            host_name = socket.gethostname()
            app_uri = f"urn:{host_name}:oida:untrusted-user"

            await setup_self_signed_certificate(
                key_path,
                cert_path,
                app_uri,
                host_name,
                [ExtendedKeyUsageOID.CLIENT_AUTH],
                {
                    "countryName": "XX",
                    "organizationName": "Attacker",
                    "commonName": "Untrusted User",
                },
            )

            # Connect to the address we actually reached, not the endpoint's
            # advertised EndpointUrl - servers often advertise their own
            # hostname / 0.0.0.0 which is unroutable from the scanner. asyncua
            # selects the endpoint by security policy (set_security / None), not
            # by the URL path, so the reachable URL is both sufficient and safer.
            url = self._original_url or (
                target.EndpointUrl or f"opc.tcp://{self.host}:{getattr(self.args, 'port', 4840)}"
            )

            try:
                Client = _get_client_class()
                test_client = Client(url=url, timeout=getattr(self.args, "timeout", 10))
                test_client.application_uri = app_uri

                # Deliberately leave certificate_validator unset (asyncua's
                # default = None, i.e. accept any server cert). We are probing
                # whether the *server* trusts *our* untrusted user cert; we must
                # not abort because the server's own cert is imperfect (the
                # server cert is assessed separately by _check_certificate).

                # Policy endpoint: stand up a secure channel with an auto app cert
                # so we can reach activate_session at all.
                if needs_secure_channel:
                    app_cert_fd, app_cert_name = tempfile.mkstemp(
                        prefix="oida_user_app_", suffix=".der"
                    )
                    app_key_fd, app_key_name = tempfile.mkstemp(
                        prefix="oida_user_app_", suffix=".pem"
                    )
                    os.close(app_cert_fd)
                    os.close(app_key_fd)
                    # Remove the empty mkstemp files so
                    # setup_self_signed_certificate regenerates them (see note
                    # in _test_self_signed_cert_acceptance).
                    os.unlink(app_cert_name)
                    os.unlink(app_key_name)
                    app_cert_path = Path(app_cert_name)
                    app_key_path = Path(app_key_name)
                    await setup_self_signed_certificate(
                        app_key_path,
                        app_cert_path,
                        app_uri,
                        host_name,
                        [ExtendedKeyUsageOID.CLIENT_AUTH],
                        {"countryName": "XX", "organizationName": "OIDA"},
                    )
                    await test_client.set_security(
                        _asyncua_sec_policies.SecurityPolicyBasic256Sha256,
                        certificate=str(app_cert_path),
                        private_key=str(app_key_path),
                        mode=ua.MessageSecurityMode.SignAndEncrypt,
                    )

                # Present the untrusted self-signed cert as the USER identity.
                await test_client.load_client_certificate(str(cert_path))
                await test_client.load_private_key(str(key_path))

                await test_client.connect()

                # Session activated with an untrusted self-signed user cert.
                # Record the verdict BEFORE attempting disconnect: a disconnect-time
                # error must never be allowed to fall through to the outer except
                # and get misread as a clean rejection.
                result["accepts_untrusted_user_cert"] = True
                result["tested"] = True
                self.logger.security_finding(
                    "Self-signed user certificate accepted",
                    detail="Server activates sessions with untrusted self-signed X509 user "
                    "identity tokens (no user-cert trust validation)",
                )

                try:
                    await test_client.disconnect()
                except Exception as disc_err:
                    self.logger.debug(f"Disconnect after user-cert test failed: {disc_err}")

            except asyncio.TimeoutError:
                result["tested"] = False
                result["status"] = "inconclusive"
                result["error"] = "Connection timeout (could not determine)"
                self.logger.warning(
                    "Could not determine if server accepts untrusted user certs (timeout)"
                )
            except Exception as e:
                err_str = str(e).lower()
                err_type = type(e).__name__.lower()
                # Only codes that represent a *trust* decision about the user
                # certificate count as a clean rejection. Cert-format errors
                # (BadCertificateUriInvalid / TimeInvalid / UseNotAllowed) say
                # nothing about trust and must fall through to "inconclusive".
                if any(
                    x in err_str or x in err_type
                    for x in [
                        "badcertificateuntrusted",
                        "badidentitytoken",  # Rejected / Invalid
                        "badsecuritychecksfailed",
                        "securitychecksfailed",
                        "baduseraccessdenied",
                        "untrusted",
                        "rejected",
                    ]
                ):
                    result["tested"] = True
                    result["rejection_reason"] = str(e)[:100]
                    self.logger.success("Server rejects untrusted self-signed user certificates")
                else:
                    result["tested"] = False
                    result["status"] = "inconclusive"
                    result["error"] = str(e)[:100]
                    self.logger.warning(
                        "Could not determine if server accepts untrusted user certs"
                    )
                    self.logger.debug(f"User-cert test error: {e}")

        except Exception as e:
            self.logger.debug(f"Self-signed user cert test error: {e}")
            result["error"] = str(e)
        finally:
            for p in (cert_path, key_path, app_cert_path, app_key_path):
                if p and p.exists():
                    os.unlink(p)

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
