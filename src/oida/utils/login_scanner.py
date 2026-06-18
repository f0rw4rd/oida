# -*- coding: utf-8 -*-
"""
Login scanner utility for ICS protocol modules.

Provides scanner factories for different authentication patterns:
- make_scanner: Standard username:password authentication
- make_password_scanner: Password-only protocols (S7, etc.)
- make_sa_scanner: DNP3 Secure Authentication (user_id:key)

All scanners support:
- Loading credentials from files
- Rate limiting to avoid lockouts
- Automatic fallback to default credentials
"""

import time
from typing import List, Callable, Dict, Any, Optional

from .ics_logger import log, get_module_logger

_logger = get_module_logger(__name__)


def _load_file_lines(filepath: str) -> List[str]:
    """Load non-empty, non-comment lines from a file."""
    lines = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    except Exception as e:
        log(f"Failed to read file {filepath}: {e}", level="error")
    return lines


def load_passwords(source: Optional[str], protocol: str = "generic") -> List[str]:
    """Load passwords from source or fall back to protocol defaults.

    Args:
        source: File path (file:path), comma-separated list, or None for defaults
        protocol: Protocol name for default credentials lookup

    Returns:
        List of passwords to test
    """
    from .default_credentials import get_protocol_defaults

    if source is None:
        # Fall back to protocol defaults
        defaults = get_protocol_defaults(protocol)
        if defaults:
            log(f"Using {len(defaults)} built-in default passwords for {protocol}")
            return defaults
        return []

    if source.startswith("file:"):
        return _load_file_lines(source[5:])

    return [p.strip() for p in source.split(",") if p.strip()]


def make_password_scanner(
    login_function: Callable[[str, int, str], bool],
    protocol: str = "generic",
    rate_limit: float = 0.0,
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Create scanner for password-only protocols (S7, etc.).

    Args:
        login_function: func(host, port, password) -> bool
        protocol: Protocol name for default credentials (s7, snap7, etc.)
        rate_limit: Delay between attempts in seconds

    Returns:
        Scanner function that processes args dict
    """

    def scanner(args: Dict[str, Any]) -> Dict[str, Any]:
        host = args.get("rhost", args.get("host", ""))
        port = args.get("rport", args.get("port", 102))
        password_source = args.get("passwords", args.get("wordlist"))
        stop_on_success = args.get("stop_on_success", True)
        custom_rate = args.get("rate_limit", rate_limit)

        # Load passwords - falls back to defaults if None
        passwords = load_passwords(password_source, protocol)

        if not passwords:
            log("No passwords to test", level="error")
            return {"success": False, "tested": 0}

        log(f"Testing {len(passwords)} passwords against {host}:{port}")

        results = {
            "success": False,
            "tested": 0,
            "password": None,
            "found": [],
        }

        for password in passwords:
            results["tested"] += 1

            try:
                if login_function(host, port, password):
                    log(f"[+] Password found: '{password}'", level="good")
                    _logger.info("Valid password found: %s:%d", host, port)
                    results["success"] = True
                    results["password"] = password
                    results["found"].append(password)

                    if stop_on_success:
                        return results
                else:
                    log(f"[-] Failed: '{password}'", level="debug")
                    _logger.debug("Password attempt failed: %s:%d", host, port)

            except Exception as e:
                log(f"Error testing '{password}': {e}", level="debug")

            if custom_rate > 0:
                time.sleep(custom_rate)

        if not results["success"]:
            log(f"Password not found after {results['tested']} attempts", level="warning")

        return results

    return scanner


def make_scanner(login_function):
    """
    Create a scanner function that uses the provided login check function
    to test username/password combinations

    Args:
        login_function: A function that takes (host, port, username, password)
                       and returns True if the login is successful

    Returns:
        A scanner function that processes scan arguments
    """

    def scanner(args):
        host = args["rhost"]
        port = args["rport"]
        userpass_value = args["userpass"]
        sleep_interval = args.get("sleep_interval", 0)

        # Process credentials
        credentials = []
        if userpass_value.startswith("file:"):
            file_path = userpass_value[5:]
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if ":" in line:
                                username, password = line.split(":", 1)
                                credentials.append((username, password))
            except Exception as e:
                log(f"Failed to read credentials file: {e}", level="error")
                return
        else:
            for cred in userpass_value.split(","):
                if ":" in cred:
                    username, password = cred.split(":", 1)
                    credentials.append((username, password))

        if not credentials:
            log("No valid credentials provided", level="error")
            return

        # Try each credential
        for username, password in credentials:
            try:
                if login_function(host, port, username, password):
                    log(f"Success: {username}:{password}", level="good")
                    _logger.info("Valid credential: %s@%s:%s", username, host, port)
                else:
                    log(f"Failed: {username}:{password}", level="info")
                    _logger.debug("Credential failed: %s@%s:%s", username, host, port)

                # Sleep if interval specified
                if sleep_interval > 0:
                    time.sleep(sleep_interval)

            except Exception as e:
                log(f"Error testing {username}:{password} - {str(e)}", level="error")

    return scanner
