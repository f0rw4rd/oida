"""
FHIR Security Mixin

Provides authentication testing, credential brute forcing, and security analysis.
"""

import time
from typing import Optional

from ..helpers import (
    fhirclient,
    patient,
    validate_credential_path,
)


class SecurityMixin:
    """Mixin providing FHIR security testing operations."""

    def _test_authentication(self):
        """Test authentication mechanisms"""
        self.logger.display("Testing authentication mechanisms...")

        auth_results = {
            "anonymous_access": False,
            "invalid_token_rejected": True,
            "token_required": True,
        }

        # Test anonymous access
        try:
            anon_settings = {
                "app_id": "oida_anon_test",
                "api_base": self._get_base_url(),
            }
            anon_client = fhirclient.FHIRClient(settings=anon_settings)

            search = patient.Patient.where(struct={"_count": "1"})
            results = search.perform_resources(anon_client.server)

            if results:
                auth_results["anonymous_access"] = True
                self.logger.security_finding(
                    "Anonymous access",
                    detail="Anonymous access allowed - returned patient data",
                )
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "Auth Test",
                        "issue": "Anonymous Access Allowed",
                        "description": "Server allows unauthenticated access to patient data",
                    }
                )
            else:
                self.logger.success("  Anonymous access properly restricted")

        except Exception as e:
            error_str = str(e).lower()
            if "401" in error_str or "403" in error_str or "unauthorized" in error_str:
                self.logger.success("  Anonymous access properly denied (401/403)")
            else:
                self.logger.debug(f"  Anonymous test error: {e}")

        # Test invalid token
        try:
            bad_settings = {
                "app_id": "oida_bad_token_test",
                "api_base": self._get_base_url(),
                "access_token": "invalid_token_12345",
            }
            bad_client = fhirclient.FHIRClient(settings=bad_settings)

            search = patient.Patient.where(struct={"_count": "1"})
            results = search.perform_resources(bad_client.server)

            if results:
                auth_results["invalid_token_rejected"] = False
                self.logger.security_finding(
                    "No authentication", detail="Invalid bearer token accepted by server"
                )
                self.results["data"].setdefault("security_findings", []).append(
                    {
                        "operation": "Auth Test",
                        "issue": "Invalid Token Accepted",
                        "description": "Server accepted invalid bearer token",
                    }
                )
            else:
                self.logger.success("  Invalid token properly rejected")

        except Exception as e:
            error_str = str(e).lower()
            if "401" in error_str or "403" in error_str or "unauthorized" in error_str:
                self.logger.success("  Invalid token properly rejected (401/403)")
            else:
                self.logger.debug(f"  Invalid token test error: {e}")

        self.results["data"]["auth_test"] = auth_results

    def _test_cross_patient_access(self):
        """Test cross-patient data access controls"""
        self.logger.display("Testing cross-patient access controls...")

        if not getattr(self.args, "patient_id", None):
            self.logger.warning("  --patient-id required for cross-patient testing")
            return

        self.logger.display("  Cross-patient access test requires manual verification")
        self.logger.display("  Compare accessible patients vs. token scope")

    def _test_scope_bypass(self):
        """Test scope enforcement"""
        self.logger.display("Testing scope enforcement...")

        server_info = self.results.get("data", {}).get("server_info", {})
        security = server_info.get("security", {})

        if "SMART" in str(security.get("security_services", [])):
            self.logger.display("  SMART on FHIR detected - scope enforcement should be active")
            self.logger.display("  Test by accessing resources outside token scope")
        else:
            self.logger.security_finding(
                "Insecure configuration",
                detail="No SMART/OAuth detected - scope may not be enforced",
            )

    def _brute_force_credentials(self):
        """Brute force HTTP Basic Auth or OAuth2 credentials"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "--brute / --default-creds runs OAuth2/Basic credential brute-force "
                "(56+ token-endpoint requests per host) — requires --confirm"
            )
            return
        import requests
        from requests.auth import HTTPBasicAuth

        brute_method = getattr(self.args, "brute_method", "basic")
        self.logger.display(f"Starting credential brute force ({brute_method} auth)...")

        usernames, passwords = self._load_credentials()

        if not usernames or not passwords:
            self.logger.fail("No credentials to test")
            return

        base_url = self._get_base_url()
        test_url = f"{base_url}/Patient?_count=1"
        delay = getattr(self.args, "brute_rate", 0.5)
        continue_on_success = getattr(self.args, "continue_on_success", False)
        tls_insecure = getattr(self.args, "tls_insecure", False)

        valid_creds = []
        tested = 0
        total = len(usernames) * len(passwords)

        self.logger.display(
            f"Testing {total} pairs ({len(usernames)} users x {len(passwords)} passwords)..."
        )

        for username in usernames:
            for password in passwords:
                tested += 1
                try:
                    if brute_method in ("basic", "both"):
                        response = requests.get(
                            test_url,
                            auth=HTTPBasicAuth(username, password),
                            timeout=10,
                            verify=not tls_insecure,
                        )

                        if response.status_code == 200:
                            self.logger.security_finding(
                                "Default credentials",
                                detail=f"Valid Basic Auth: {username}:{password}",
                            )
                            valid_creds.append(
                                {
                                    "username": username,
                                    "password": password,
                                    "method": "basic",
                                }
                            )

                            if not continue_on_success:
                                break
                        elif response.status_code in (401, 403):
                            self.logger.display(f"Failed: {username}:{password}")
                        else:
                            self.logger.debug(
                                f"Unexpected status {response.status_code} for {username}"
                            )

                    if brute_method in ("oauth2", "both") and (
                        continue_on_success or not valid_creds
                    ):
                        oauth_result = self._test_oauth2_credentials(username, password)
                        if oauth_result:
                            valid_creds.append(
                                {
                                    "username": username,
                                    "password": password,
                                    "method": "oauth2",
                                    "token": oauth_result,
                                }
                            )
                            if not continue_on_success:
                                break

                except requests.exceptions.Timeout:
                    self.logger.warning(f"Timeout testing {username}:{password}")
                except requests.exceptions.RequestException as e:
                    self.logger.debug(f"Error testing {username}:{password}: {e}")

                if delay > 0:
                    time.sleep(delay)

            if not continue_on_success and valid_creds:
                break

        self.logger.display(f"Tested {tested} credentials, found {len(valid_creds)} valid")

        if valid_creds:
            findings = self.results["data"].get("security_findings", [])
            self.results["data"]["security_findings"] = findings
            self.results["data"]["security_findings"].append(
                {
                    "category": "AUTHENTICATION",
                    "issue": "Valid Credentials Found",
                    "description": f"Found {len(valid_creds)} valid credential(s)",
                }
            )

        self.results["data"]["brute_force"] = {
            "tested": tested,
            "valid": valid_creds,
        }

    def _load_credentials(self) -> tuple:
        """Load usernames and passwords from args or files"""
        from ....utils.default_credentials import parse_credential_input

        usernames = []
        passwords = []

        # Check --user-file
        user_file = getattr(self.args, "user_file", None)
        if user_file:
            try:
                user_file = validate_credential_path(user_file)
                with open(user_file, "r") as f:
                    usernames = [line.strip() for line in f if line.strip()]
                self.logger.display(f"Loaded {len(usernames)} usernames from {user_file}")
            except ValueError as e:
                self.logger.fail(str(e))
            except Exception as e:
                self.logger.debug("load credentials failed: %s", e)
                self.logger.fail(f"Failed to load user file: {e}")

        # Check --pass-file
        pass_file = getattr(self.args, "pass_file", None)
        if pass_file:
            try:
                pass_file = validate_credential_path(pass_file)
                with open(pass_file, "r") as f:
                    passwords = [line.strip() for line in f if line.strip()]
                self.logger.display(f"Loaded {len(passwords)} passwords from {pass_file}")
            except ValueError as e:
                self.logger.fail(str(e))
            except Exception as e:
                self.logger.debug("load credentials failed: %s", e)
                self.logger.fail(f"Failed to load password file: {e}")

        # Check -u/--username (can be single value or file)
        username_arg = getattr(self.args, "username", None)
        if username_arg and not usernames:
            parsed, is_file = parse_credential_input(username_arg)
            usernames = parsed

        # Check -P/--password (can be single value or file)
        password_arg = getattr(self.args, "password", None)
        if password_arg and not passwords:
            parsed, is_file = parse_credential_input(password_arg)
            passwords = parsed

        # Check --wordlist (user:pass format)
        wordlist = getattr(self.args, "wordlist", None)
        if wordlist and not (usernames and passwords):
            try:
                wordlist = validate_credential_path(wordlist)
                with open(wordlist, "r") as f:
                    for line in f:
                        line = line.strip()
                        if ":" in line:
                            u, p = line.split(":", 1)
                            if u not in usernames:
                                usernames.append(u)
                            if p not in passwords:
                                passwords.append(p)
                # Use basename only — full wordlist path can leak
                # engagement context (client name, operator filesystem).
                from ....utils.login_scanner import format_wordlist_source

                self.logger.display(
                    f"Loaded credentials from wordlist: {format_wordlist_source(wordlist)}"
                )
            except ValueError as e:
                self.logger.fail(str(e))
            except Exception as e:
                self.logger.debug("load credentials failed: %s", e)
                self.logger.fail(f"Failed to load wordlist: {e}")

        # Check --default-creds (use built-in healthcare defaults)
        if getattr(self.args, "default_creds", False):
            default_users = ["admin", "fhir", "api", "system", "service", "root", "test"]
            default_passes = ["admin", "password", "fhir", "api", "system", "changeme", "test", ""]

            if not usernames:
                usernames = default_users
                self.logger.display(f"Using {len(default_users)} default usernames")
            if not passwords:
                passwords = default_passes
                self.logger.display(f"Using {len(default_passes)} default passwords")

        return usernames, passwords

    def _test_oauth2_credentials(self, username: str, password: str) -> Optional[str]:
        """Test OAuth2 resource owner password grant"""
        import requests

        server_info = self.results.get("data", {}).get("server_info", {})
        security = server_info.get("security", {})
        oauth_endpoints = security.get("oauth_endpoints", {})

        token_url = getattr(self.args, "token_url", None) or oauth_endpoints.get("token")
        if not token_url:
            return None

        client_id = getattr(self.args, "client_id", None) or "oida_scanner"
        client_secret = getattr(self.args, "client_secret", None) or ""
        scope = getattr(self.args, "scope", None) or "patient/*.read"

        try:
            response = requests.post(
                token_url,
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                },
                timeout=10,
                verify=not getattr(self.args, "tls_insecure", False),
            )

            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get("access_token")
                if access_token:
                    self.logger.security_finding(
                        "Default credentials", detail=f"Valid OAuth2: {username}:{password}"
                    )
                    return access_token

        except Exception as e:
            self.logger.debug(f"OAuth2 test failed for {username}: {e}")

        return None

    def _analyze_security(self):
        """Analyze overall security posture"""
        findings = self.results["data"].get("security_findings", [])

        # Check for TLS
        if not self.results["data"].get("tls_enabled", True):
            findings.append(
                {
                    "category": "ENCRYPTION",
                    "issue": "No TLS/HTTPS",
                    "description": "Connection is not encrypted",
                }
            )

        # Check security configuration
        server_info = self.results.get("data", {}).get("server_info", {})
        security = server_info.get("security", {})

        if not security.get("security_services"):
            findings.append(
                {
                    "category": "AUTHENTICATION",
                    "issue": "No Security Services Configured",
                    "description": "CapabilityStatement shows no security services",
                }
            )

        # CORS check
        if security.get("cors_enabled"):
            findings.append(
                {
                    "category": "CONFIGURATION",
                    "issue": "CORS Enabled",
                    "description": "Cross-origin requests allowed - verify origins are restricted",
                }
            )

        # Add certificate findings from logger
        for finding in self.logger.findings:
            findings.append(
                {
                    "category": "CERTIFICATE",
                    "issue": finding.get("title", ""),
                    "description": finding.get("detail", ""),
                }
            )

        self.results["data"]["security_findings"] = findings

        # Display findings
        if findings:
            self.logger.display("\nSecurity Findings:")
            for finding in findings:
                category = finding.get("category", "GENERAL")
                issue = finding.get("issue", "Unknown")
                desc = finding.get("description", "")
                self.logger.display(f"  [{category}] {issue}: {desc}")
