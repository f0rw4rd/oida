"""
MQTT Authentication Mixin

Handles anonymous auth testing, single credential testing,
and brute-force credential attacks.
"""

import time
from pathlib import Path
from typing import Any, Dict

from ..scanner import DEFAULT_CREDENTIALS, DEFAULT_WORDLIST_PATHS


class AuthMixin:
    """Mixin providing MQTT authentication operations."""

    def _test_anonymous_auth(self) -> Dict[str, Any]:
        """Test if broker allows anonymous connections"""
        result = {
            "anonymous_allowed": False,
            "requires_auth": True,
            "connack_code": None,
        }

        self.logger.display("Testing anonymous authentication...")
        client = self._create_mqtt_client(username="", password="", client_id_suffix="anon")
        success, reason = self._attempt_connect(client, timeout=2.0)

        result["connack_code"] = reason

        if success:
            result["anonymous_allowed"] = True
            result["requires_auth"] = False
            # The anonymous-access finding is reported once in _analyze_security
            # to avoid duplicate findings for the same broker.
        else:
            self.logger.display(f"Anonymous authentication denied ({reason})")
        return result

    def _test_credentials(self, username: str, password: str) -> bool:
        """Test a single credential pair using shared helpers"""
        self.logger.debug(f"Testing creds: user='{username}' pass='{password}'")
        client = self._create_mqtt_client(username, password, "auth")
        success, reason = self._attempt_connect(client, timeout=1.0)
        self.logger.debug(f"Result: {username}:{password} -> {'OK' if success else reason}")
        return success

    def _brute_force_credentials(self) -> Dict[str, Any]:
        """Brute-force credentials"""
        results = {
            "tested": 0,
            "valid": [],
            "stopped_early": False,
        }

        credentials = []

        # Load from credentials file (user:pass format)
        if self.credentials_path and Path(self.credentials_path).exists():
            with open(self.credentials_path) as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        user, passwd = line.split(":", 1)
                        credentials.append((user, passwd))

        # Load from wordlist (password only, use provided username)
        if self.wordlist_path and Path(self.wordlist_path).exists():
            user = self.username or "admin"
            with open(self.wordlist_path) as f:
                for line in f:
                    passwd = line.strip()
                    if passwd and not passwd.startswith("#"):
                        credentials.append((user, passwd))

        # Try default wordlist file if no credentials loaded
        if not credentials:
            for wordlist_path in DEFAULT_WORDLIST_PATHS:
                if wordlist_path.exists():
                    with open(wordlist_path) as f:
                        for line in f:
                            line = line.strip()
                            if ":" in line and not line.startswith("#"):
                                user, passwd = line.split(":", 1)
                                credentials.append((user, passwd))
                    if credentials:
                        self.logger.display(
                            f"Loaded {len(credentials)} credentials from {wordlist_path}"
                        )
                        break

        # Fallback to hardcoded defaults (Mirai + MQTT-PWN + ICS defaults)
        if not credentials:
            credentials = list(DEFAULT_CREDENTIALS)
            self.logger.display(f"Using {len(credentials)} built-in default credentials")

        # Use brute_rate as delay between attempts
        delay = self.brute_rate

        # Log brute-force start
        delay_info = f", delay={delay}s" if delay > 0 else ""
        self.logger.display(f"Brute-force: testing {len(credentials)} credentials{delay_info}")
        t_start = time.time()

        for user, passwd in credentials:
            results["tested"] += 1

            if self._test_credentials(user, passwd):
                results["valid"].append({"username": user, "password": passwd})
                self.logger.security_finding(
                    "Default credentials",
                    category="ACCESS_CONTROL",
                    detail=f"Valid MQTT credentials: {user}:***",
                )

                # Stop on first success unless continue_on_success is set (default: stop)
                if not self.continue_on_success:
                    results["stopped_early"] = True
                    break

            if delay > 0:
                time.sleep(delay)

        elapsed = time.time() - t_start
        valid_count = len(results["valid"])
        if valid_count > 0:
            self.logger.display(
                f"Brute-force complete: {valid_count} valid / {results['tested']} tested ({elapsed:.2f}s)"
            )
        else:
            self.logger.display(
                f"Brute-force complete: no valid credentials ({results['tested']} tested, {elapsed:.2f}s)"
            )

        return results
