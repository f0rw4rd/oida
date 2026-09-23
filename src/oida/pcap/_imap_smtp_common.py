"""Shared credential-bookkeeping helpers for the IMAP and SMTP passive listeners.

Both listeners track credential-bearing sessions with dataclasses
(``IMAPCredential`` / ``SMTPCredential``) that expose the identical shape --
``auth_method``, ``credential_type``, ``username``, ``password``, ``hash_value``,
``challenge``, ``server_ip``, ``server_port``, ``client_ip``, ``timestamp``.
This module centralizes the dedup lookups and credential-dict builders that
were previously copy-pasted identically between ``imap.py`` and ``smtp.py``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence


def is_new_credential(
    credentials: Sequence[Any], server_ip: str, method: str, username: str, password: str
) -> bool:
    """Check whether (server_ip, method, username, password) is already recorded."""
    for cred in credentials:
        if (
            cred.server_ip == server_ip
            and cred.auth_method == method
            and cred.username == username
            and cred.password == password
        ):
            return False
    return True


def is_new_hash(
    credentials: Sequence[Any], server_ip: str, method: str, username: str, hash_value: str
) -> bool:
    """Check whether (server_ip, method, username, hash_value) is already recorded."""
    for cred in credentials:
        if (
            cred.server_ip == server_ip
            and cred.auth_method == method
            and cred.username == username
            and cred.hash_value == hash_value
        ):
            return False
    return True


def build_credential_entry(cred: Any) -> Dict[str, Any]:
    """Build the device-record credential dict used by IMAP/SMTP ``_update_devices``."""
    entry: Dict[str, Any] = {
        "auth_method": cred.auth_method,
        "credential_type": cred.credential_type,
        "username": cred.username,
        "timestamp": cred.timestamp,
    }
    if cred.credential_type == "plaintext":
        entry["password"] = cred.password
    else:
        entry["hash"] = cred.hash_value
        entry["challenge"] = cred.challenge
    return entry


def credentials_summary(credentials: Sequence[Any], protocol: str) -> List[Dict[str, Any]]:
    """Build the ``get_credentials_summary()`` list shared by IMAP/SMTP."""
    result: List[Dict[str, Any]] = []
    for cred in credentials:
        entry: Dict[str, Any] = {
            "protocol": protocol,
            "auth_method": cred.auth_method,
            "credential_type": cred.credential_type,
            "username": cred.username,
            "server_ip": cred.server_ip,
            "client_ip": cred.client_ip,
            "timestamp": cred.timestamp,
        }
        if cred.credential_type == "plaintext":
            entry["password"] = cred.password
        else:
            entry["hash"] = cred.hash_value
            entry["challenge"] = cred.challenge
        result.append(entry)
    return result


def hashcat_hashes(credentials: Sequence[Any]) -> List[str]:
    """CRAM-MD5 credentials in hashcat mode-10200 format; plaintext creds are skipped."""
    return [c.hashcat_format for c in credentials if c.hashcat_format]
