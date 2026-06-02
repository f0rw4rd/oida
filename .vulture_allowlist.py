"""Vulture allowlist — callback parameters required by external APIs.

These names look unused to vulture but are signature requirements imposed
by third-party libraries (paho-mqtt, pysnmp, signal handlers, argparse
actions, etc.). Touching them breaks the contract with the library.

Used by pre-push hook:
    vulture --min-confidence 80 src/oida/ .vulture_allowlist.py

Add new entries here, NOT by renaming the callback parameters — the
library passes them positionally and a rename in our code is
load-bearing for clarity.

Vulture's "whitelist" format: each `<name>` line tells vulture that any
unused `<name>` symbol it finds is intentional. The leading underscore
attribute access is the convention vulture documents.
"""

# paho-mqtt callbacks (on_connect, on_message, on_disconnect, etc.)
_.userdata  # noqa: F821 — vulture-whitelist sentinel

# pysnmp callbacks
_.cbCtx  # noqa: F821
_.execpoint  # noqa: F821

# Python signal handlers (signal.signal(signum, frame))
_.signum  # noqa: F821

# argparse custom action `__call__(self, parser, namespace, values, option_string=None)`
_.option_string  # noqa: F821

# DNP3 task callback hooks (pydnp3)
_.task_id  # noqa: F821
_.task_type  # noqa: F821

# CIP / GOOSE message-source identifier on multicast paths
_.originator  # noqa: F821

# Boofuzz / fuzzer feature flags that surface in CLI but are read elsewhere
_.prefer_native  # noqa: F821

# UDP echo-server probe — name documents the protocol semantics
_.max_messages  # noqa: F821

# Discovery probe response parsing — the IP is captured for log context
# but the canonical IP came from the IP layer earlier
_.ip_from_response  # noqa: F821
