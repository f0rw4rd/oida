"""
SNMP v3 Enumeration Mixin

Handles SNMPv3 credential enumeration:
- Single v3 probe (_probe_v3)
- Username enumeration (noAuthNoPriv probes)
- 3-phase orchestration: user enum, auth brute, priv brute
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Dict, List


if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class V3EnumerationMixin(_ScannerBase):
    """Mixin providing SNMPv3 credential enumeration."""

    def _probe_v3(
        self,
        username,
        auth_pass="",  # nosec B107 -- empty default for noAuthNoPriv probes
        priv_pass="",  # nosec B107
        auth_proto_name="SHA",
        priv_proto_name="AES128",
        sec_level="noAuthNoPriv",
    ) -> str:
        """Single SNMPv3 probe. Returns result classification string.

        Returns one of:
            "SUCCESS"      - query succeeded
            "INVALID_USER" - unknownSecurityName
            "WRONG_AUTH"   - authenticationFailure
            "WRONG_LEVEL"  - unsupportedSecurityLevel (user needs higher sec level)
            "WRONG_PRIV"   - decryptionError
            "TIMEOUT"      - host sent no reply before the timeout
            "ERROR"        - probe failed for a non-network reason (exception or
                             an unrecognized pysnmp error indication); the detail
                             is stashed in ``self._last_v3_error``
        """
        from pysnmp.hlapi.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            get_cmd,
        )

        from oida.protocols.snmp.constants import SNMP_OIDS
        from oida.protocols.snmp.scanner import _validate_snmp_key

        auth_protocols, priv_protocols = self._get_usm_protocol_maps()
        auth_proto = auth_protocols.get(auth_proto_name, auth_protocols["SHA"])
        priv_proto = priv_protocols.get(priv_proto_name, priv_protocols["AES128"])

        # RFC 3414 requires auth/priv passphrases >= 8 octets. A shorter wordlist
        # entry cannot be a valid key, so skip it rather than crash the whole phase.
        try:
            if sec_level == "noAuthNoPriv":
                usm_data = UsmUserData(username)
            elif sec_level == "authNoPriv":
                usm_data = UsmUserData(
                    username,
                    authKey=_validate_snmp_key(auth_pass, "auth password"),
                    authProtocol=auth_proto,
                )
            else:  # authPriv
                usm_data = UsmUserData(
                    username,
                    authKey=_validate_snmp_key(auth_pass, "auth password"),
                    privKey=_validate_snmp_key(priv_pass, "priv password"),
                    authProtocol=auth_proto,
                    privProtocol=priv_proto,
                )
        except ValueError as e:
            self.logger.debug(f"v3 probe skip (short key) for {username}: {e}")
            return "SHORT_KEY"

        async def _do_probe():
            engine = SnmpEngine()
            transport = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=0
            )
            error_indication, error_status, error_index, _ = await get_cmd(
                engine,
                usm_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(SNMP_OIDS["sysDescr"])),
            )
            return error_indication, error_status, error_index

        try:
            err, error_status, error_index = asyncio.run(_do_probe())
        except (TimeoutError, asyncio.TimeoutError):
            return "TIMEOUT"
        except Exception as e:
            # Not a timeout -- a real failure (bad transport, pysnmp internals,
            # unsupported algo). Don't masquerade it as a silent no-response.
            self._last_v3_error = f"{type(e).__name__}: {e}"
            self.logger.debug(f"v3 probe error for {username}: {self._last_v3_error}")
            return "ERROR"

        if err is None:
            # Auth succeeded at SNMP engine level -- check PDU error_status
            # authorizationError (error_status=16) means VACM rejects because
            # user requires a higher security level (e.g. authPriv)
            if error_status and int(error_status) == 16:
                return "WRONG_LEVEL"
            return "SUCCESS"

        err_str = str(err)
        err_cls = type(err).__name__
        if (
            "UnknownUserName" in err_cls
            or "unknownSecurityName" in err_str
            or "Unknown USM user" in err_str
        ):
            return "INVALID_USER"
        elif (
            "WrongDigest" in err_cls
            or "authenticationFailure" in err_str
            or "Wrong SNMP PDU digest" in err_str
        ):
            return "WRONG_AUTH"
        elif "UnsupportedSecurityLevel" in err_cls or "unsupportedSecurityLevel" in err_str:
            return "WRONG_LEVEL"
        elif "DecryptionError" in err_cls or "decryptionError" in err_str:
            return "WRONG_PRIV"
        elif (
            "RequestTimedOut" in err_cls
            or "timeout" in err_str.lower()
            or "No SNMP response received" in err_str
        ):
            return "TIMEOUT"
        else:
            # An error indication we don't recognize -- surface it instead of
            # silently treating it as a no-response.
            self._last_v3_error = f"{err_cls}: {err_str}"
            self.logger.debug(f"v3 probe unrecognized error for {username}: {self._last_v3_error}")
            return "ERROR"

    def _enum_v3_users(self, usernames: List[str]) -> Dict:
        """Phase 1: Enumerate valid SNMPv3 usernames via noAuthNoPriv probes.

        Returns dict with valid_users list and credentials for noAuthNoPriv users.
        """
        valid_users: List[Dict] = []
        credentials: List[Dict] = []

        self.logger.info(f"SNMP v3 enum: phase 1 -- testing {len(usernames)} usernames")
        p1_total = len(usernames)
        # Abort only after repeated no-response (dead/filtered host), not on a
        # single dropped UDP datagram -- and keep any users already discovered.
        max_consecutive_dead = max(3, p1_total // 10)
        consecutive_dead = 0
        # Distinguish "host responded but no users" from "host never replied at
        # all" (dead/filtered port). Any non-timeout/-error result is a reply.
        host_responded = False
        # Track non-network failures separately so the abort/summary names the
        # real cause instead of blaming the network.
        probe_errors = 0

        for p1_idx, username in enumerate(usernames, 1):
            self.logger.progress(p1_idx, p1_total)
            result = self._probe_v3(username, sec_level="noAuthNoPriv")

            # TIMEOUT (no reply) and ERROR (probe blew up) both yield no usable
            # answer and both feed the abort streak, but they're reported apart.
            if result in ("TIMEOUT", "ERROR"):
                consecutive_dead += 1
                if result == "ERROR":
                    probe_errors += 1
                if consecutive_dead >= max_consecutive_dead:
                    self.logger.progress(p1_idx, p1_total, end="\n")
                    if probe_errors:
                        self.logger.warning(
                            f"SNMP: aborting v3 user enumeration after {consecutive_dead} "
                            f"failed probes (last error: "
                            f"{getattr(self, '_last_v3_error', 'unknown')})"
                        )
                    else:
                        self.logger.warning(
                            f"SNMP: {consecutive_dead} consecutive no-responses -- "
                            "aborting v3 user enumeration"
                        )
                    return {
                        "valid_users": valid_users,
                        "credentials": credentials,
                        "host_responded": host_responded,
                        "probe_errors": probe_errors,
                    }
                if self.brute_rate > 0:
                    time.sleep(self.brute_rate)
                continue
            consecutive_dead = 0
            # SHORT_KEY is a locally-skipped probe, not a reply from the host.
            if result != "SHORT_KEY":
                host_responded = True

            if result == "INVALID_USER":
                self.logger.debug(f"  {username}: invalid")
            elif result == "SUCCESS":
                # Finalize progress, and key the finding per-user so multiple
                # open users each print/export (dedup is by title+category).
                self.logger.progress(p1_idx, p1_total, end="\n")
                self.logger.security_finding(
                    f"No authentication (user '{username}')",
                    detail=f"SNMPv3 noAuthNoPriv access: user '{username}'",
                )
                valid_users.append({"username": username, "level": "noAuthNoPriv"})
                credentials.append(
                    {
                        "username": username,
                        "security_level": "noAuthNoPriv",
                    }
                )
            elif result == "WRONG_LEVEL":
                # Finalize the progress line before printing so it isn't clobbered.
                self.logger.progress(p1_idx, p1_total, end="\n")
                self.logger.success(f"Valid SNMPv3 user: '{username}' (requires auth)")
                valid_users.append({"username": username, "level": "authRequired"})
            elif result == "WRONG_AUTH":
                # Shouldn't happen at noAuthNoPriv, but treat as valid
                self.logger.progress(p1_idx, p1_total, end="\n")
                self.logger.success(f"Valid SNMPv3 user: '{username}' (requires auth)")
                valid_users.append({"username": username, "level": "authRequired"})

            if self.brute_rate > 0:
                time.sleep(self.brute_rate)

        if p1_total > 0:
            self.logger.progress(p1_total, p1_total, end="\n")

        return {
            "valid_users": valid_users,
            "credentials": credentials,
            "host_responded": host_responded,
            "probe_errors": probe_errors,
        }

    def _enum_v3(self) -> Dict:
        """Orchestrate 3-phase SNMPv3 enumeration.

        Phase 1: Username enumeration (noAuthNoPriv probes)
        Phase 2: Auth protocol + password brute-force
        Phase 3: Priv protocol + key brute-force

        Returns dict with valid_users and credentials lists.
        """
        from oida.utils.default_credentials import (
            GENERIC_ICS_DEFAULTS,
            SNMP_COMMUNITY_DEFAULTS,
            SNMP_V3_USERNAMES,
            parse_credential_input,
        )
        from oida.utils.export_utils import export_table

        # Load username list -- -u accepts string or file path
        if self.username:
            usernames, is_file = parse_credential_input(self.username)
            if is_file:
                self.logger.info(f"SNMP v3 enum: loaded {len(usernames)} usernames from file")
        else:
            usernames = list(SNMP_V3_USERNAMES)

        # Load auth passwords -- -A accepts string or file path
        auth_pass_given = bool(self.auth_pass)
        priv_pass_given = bool(self.priv_pass)

        if auth_pass_given:
            passwords, is_file = parse_credential_input(self.auth_pass)
            if is_file:
                self.logger.info(f"SNMP v3 enum: loaded {len(passwords)} auth passwords from file")
            else:
                self.logger.info("SNMP v3 enum: using provided auth password (-A)")
        else:
            # Reuse community strings + generic ICS passwords (common reuse in ICS)
            passwords = list(SNMP_COMMUNITY_DEFAULTS)
            seen = set(passwords)
            for _, pwd in GENERIC_ICS_DEFAULTS:
                if pwd and pwd not in seen:
                    passwords.append(pwd)
                    seen.add(pwd)

        # Load priv passwords -- -X accepts string or file
        if priv_pass_given:
            priv_pass_list, is_file = parse_credential_input(self.priv_pass)
            if is_file:
                self.logger.info(
                    f"SNMP v3 enum: loaded {len(priv_pass_list)} priv passwords from file"
                )
        else:
            priv_pass_list = None  # will use passwords list in phase 3

        # Auth protocols -- if -a was explicitly set, use only that
        all_auth_protos = ["SHA", "MD5", "SHA256", "SHA384", "SHA512"]
        if auth_pass_given and self.auth_protocol:
            auth_protos = [self.auth_protocol]
        else:
            auth_protos = all_auth_protos

        # Priv protocols -- if -x was explicitly set, use only that
        all_priv_protos = ["AES128", "DES", "AES256", "AES192", "3DES"]
        if priv_pass_given and self.priv_protocol:
            priv_protos = [self.priv_protocol]
        else:
            priv_protos = all_priv_protos

        valid_users = []
        credentials = []

        # -- Phase 1: Username Enumeration (skip if target user given) --
        if self.enum_v3_target_user:
            # -E accepts a username string or a file of usernames
            target_users, is_file = parse_credential_input(self.enum_v3_target_user)
            if is_file:
                self.logger.info(f"SNMP v3 enum: loaded {len(target_users)} target users from file")
                # File of users -> use as phase 1 candidates instead of built-in list
                usernames = target_users
                self.enum_v3_target_user = None  # fall through to normal phase 1
            else:
                self.logger.info(f"SNMP v3 brute: targeting user '{self.enum_v3_target_user}'")
                for u in target_users:
                    valid_users.append({"username": u, "level": "authRequired"})

        host_responded = True
        probe_errors = 0
        if not self.enum_v3_target_user:
            p1_result = self._enum_v3_users(usernames)
            valid_users.extend(p1_result["valid_users"])
            credentials.extend(p1_result["credentials"])
            host_responded = p1_result.get("host_responded", True)
            probe_errors = p1_result.get("probe_errors", 0)

        if not valid_users:
            if probe_errors:
                self.logger.fail(
                    f"SNMP v3 enum: probes against {self.host}:{self.port} failed with "
                    f"errors (last: {getattr(self, '_last_v3_error', 'unknown')}) -- "
                    "not a network timeout; check the target/options"
                )
            elif not host_responded:
                self.logger.fail(
                    f"SNMP v3 enum: no response from {self.host}:{self.port} -- "
                    "host is down, the port is wrong, or SNMP is filtered "
                    "(no UDP reply to any probe)"
                )
            else:
                self.logger.info("SNMP v3 enum: host responded but no valid usernames found")
            return {"valid_users": [], "credentials": [], "host_responded": host_responded}

        # Users that need auth brute-force
        auth_needed = [u for u in valid_users if u["level"] == "authRequired"]

        if not auth_needed:
            self.logger.info(
                f"SNMP v3 enum: {len(valid_users)} user(s) found, all with noAuthNoPriv access"
            )
            return {"valid_users": valid_users, "credentials": credentials}

        # -- Phase 2: Auth Protocol + Password Brute --
        # Skip --confirm only for single known credential; wordlists still need it
        is_single_auth = auth_pass_given and len(passwords) == 1 and len(auth_protos) == 1
        if not is_single_auth and not self.confirm_brute:
            self.logger.fail(
                f"SNMP v3 enum: phase 2 would brute-force {len(passwords)} passwords "
                f"x {len(auth_protos)} protocols -- add --confirm to proceed"
            )
            return {"valid_users": valid_users, "credentials": credentials}

        phase2_label = "testing" if is_single_auth else "brute-forcing"
        self.logger.info(
            f"SNMP v3 enum: phase 2 -- {phase2_label} auth for {len(auth_needed)} user(s) "
            f"({len(passwords)} passwords x {len(auth_protos)} protocols)"
        )

        priv_needed = []  # Users where auth succeeded but priv is required
        p2_total = len(auth_needed) * len(passwords) * len(auth_protos)
        p2_current = 0

        for user_info in auth_needed:
            username = user_info["username"]
            found = False

            for password in passwords:
                if found:
                    break
                for auth_proto in auth_protos:
                    p2_current += 1
                    self.logger.progress(p2_current, p2_total)
                    result = self._probe_v3(
                        username,
                        auth_pass=password,
                        auth_proto_name=auth_proto,
                        sec_level="authNoPriv",
                    )

                    self.logger.debug(
                        f"Phase 2: user={username}, proto={auth_proto}, "
                        f"pass='{password}' -> {result}"
                    )

                    if result == "SUCCESS":
                        self.logger.progress(p2_current, p2_total, end="\n")
                        self.logger.success(
                            f"{username}: auth found (proto={auth_proto}, pass='{password}')"
                        )
                        credentials.append(
                            {
                                "username": username,
                                "auth_pass": password,
                                "auth_protocol": auth_proto,
                                "security_level": "authNoPriv",
                            }
                        )
                        self.logger.security_finding(
                            "Credential disclosure",
                            category="INFO_DISCLOSURE",
                            detail=f"SNMPv3 credentials found: user '{username}' pass '{password}'",
                        )
                        found = True
                        break

                    if result == "WRONG_LEVEL":
                        # Auth succeeded but user requires priv
                        self.logger.progress(p2_current, p2_total, end="\n")
                        self.logger.success(
                            f"{username}: auth found, needs priv "
                            f"(proto={auth_proto}, pass='{password}')"
                        )
                        priv_needed.append(
                            {
                                "username": username,
                                "auth_pass": password,
                                "auth_protocol": auth_proto,
                            }
                        )
                        # Record the proven auth credential immediately so it
                        # survives even if phase 3 never cracks the priv key.
                        # Phase 3 upgrades this entry to authPriv on SUCCESS.
                        credentials.append(
                            {
                                "username": username,
                                "auth_pass": password,
                                "auth_protocol": auth_proto,
                                "security_level": "authRequired-priv",
                            }
                        )
                        self.logger.security_finding(
                            "Credential disclosure",
                            category="INFO_DISCLOSURE",
                            detail=f"SNMPv3 auth credentials found (priv required): "
                            f"user '{username}' pass '{password}'",
                        )
                        found = True
                        break

                    # Rate-limit every probe (incl. timeouts) -- a slow/filtered
                    # host is exactly where backing off matters most.
                    if self.brute_rate > 0:
                        time.sleep(self.brute_rate)

                    if result == "TIMEOUT":
                        self.logger.debug(f"  {username}: timeout with {auth_proto}")
                        continue
                    # WRONG_AUTH / SHORT_KEY -- continue trying

        if p2_total > 0:
            self.logger.progress(p2_total, p2_total, end="\n")

        # -- Phase 3: Priv Protocol + Key Brute --
        if priv_needed:
            # Skip --confirm only for single known credential; wordlists still need it
            is_single_priv = (
                priv_pass_list is not None and len(priv_pass_list) == 1 and len(priv_protos) == 1
            )
            if not is_single_priv and not self.confirm_brute:
                self.logger.fail(
                    f"SNMP v3 enum: phase 3 would brute-force priv for {len(priv_needed)} user(s) "
                    f"-- add --confirm to proceed"
                )
                return {"valid_users": valid_users, "credentials": credentials}

            phase3_label = "testing" if is_single_priv else "brute-forcing"
            self.logger.info(
                f"SNMP v3 enum: phase 3 -- {phase3_label} priv for {len(priv_needed)} user(s)"
            )

            # priv_passwords is per-user; estimate total for progress bar
            if priv_pass_list is not None:
                priv_pw_count = len(priv_pass_list)
            else:
                priv_pw_count = len(passwords) + 1  # +1 for auth_pass dedup
            p3_total = len(priv_needed) * priv_pw_count * len(priv_protos)
            p3_current = 0

            for user_info in priv_needed:
                username = user_info["username"]
                auth_pass = user_info["auth_pass"]
                auth_proto = user_info["auth_protocol"]
                found = False

                # If -X was provided, use that list; otherwise try auth_pass first
                if priv_pass_list is not None:
                    priv_passwords = priv_pass_list
                else:
                    priv_passwords = [auth_pass] + [p for p in passwords if p != auth_pass]

                for priv_pass in priv_passwords:
                    if found:
                        break
                    for priv_proto in priv_protos:
                        p3_current += 1
                        self.logger.progress(p3_current, p3_total)
                        result = self._probe_v3(
                            username,
                            auth_pass=auth_pass,
                            priv_pass=priv_pass,
                            auth_proto_name=auth_proto,
                            priv_proto_name=priv_proto,
                            sec_level="authPriv",
                        )

                        self.logger.debug(
                            f"Phase 3: user={username}, priv_proto={priv_proto}, "
                            f"priv_pass='{priv_pass}' -> {result}"
                        )

                        if result == "SUCCESS":
                            self.logger.progress(p3_current, p3_total, end="\n")
                            self.logger.success(
                                f"{username}: full creds found "
                                f"(auth={auth_proto}/{auth_pass}, "
                                f"priv={priv_proto}/{priv_pass})"
                            )
                            # Upgrade the auth-only entry recorded in phase 2
                            # (security_level 'authRequired-priv') to authPriv
                            # in place; fall back to appending if not present.
                            full_cred = {
                                "username": username,
                                "auth_pass": auth_pass,
                                "auth_protocol": auth_proto,
                                "priv_pass": priv_pass,
                                "priv_protocol": priv_proto,
                                "security_level": "authPriv",
                            }
                            existing = next(
                                (
                                    c
                                    for c in credentials
                                    if c["username"] == username
                                    and c.get("security_level") == "authRequired-priv"
                                ),
                                None,
                            )
                            if existing is not None:
                                existing.clear()
                                existing.update(full_cred)
                            else:
                                credentials.append(full_cred)
                            self.logger.security_finding(
                                "Credential disclosure",
                                category="INFO_DISCLOSURE",
                                detail=f"SNMPv3 full credentials: user '{username}' "
                                f"auth='{auth_pass}' priv='{priv_pass}'",
                            )
                            found = True
                            break

                        # Rate-limit every probe, including timeouts.
                        if self.brute_rate > 0:
                            time.sleep(self.brute_rate)

                        if result == "TIMEOUT":
                            self.logger.debug(f"  {username}: timeout with {priv_proto}")
                            continue
                        # WRONG_PRIV / WRONG_AUTH / SHORT_KEY -- continue

            if p3_total > 0:
                self.logger.progress(p3_total, p3_total, end="\n")

        self.logger.info(
            f"SNMP v3 enum: done -- {len(valid_users)} user(s), "
            f"{len(credentials)} credential set(s)"
        )

        # Map the internal 'authRequired-priv' sentinel (used above to find the
        # phase-2 entries phase 3 upgrades) to a user-facing label for any entry
        # whose priv key was never cracked, so the sentinel doesn't leak into the
        # exported summary table or the returned results.
        for cred in credentials:
            if cred.get("security_level") == "authRequired-priv":
                cred["security_level"] = "authNoPriv (priv key not recovered)"

        if valid_users:
            host_sfx = self.host.replace(".", "_")
            headers = [
                "Username",
                "Security Level",
                "Auth Protocol",
                "Auth Password",
                "Priv Protocol",
                "Priv Password",
            ]
            rows = []
            for u in valid_users:
                cred = next((c for c in credentials if c["username"] == u["username"]), {})
                rows.append(
                    [
                        u["username"],
                        cred.get("security_level", u["level"]),
                        cred.get("auth_protocol", ""),
                        cred.get("auth_pass", ""),
                        cred.get("priv_protocol", ""),
                        cred.get("priv_pass", ""),
                    ]
                )
            export_table(f"snmp_v3_enum_{host_sfx}", headers, rows, title="SNMPv3 Enumeration")

        return {"valid_users": valid_users, "credentials": credentials}
