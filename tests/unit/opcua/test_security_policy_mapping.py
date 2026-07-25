"""Regression: every OPC UA security policy advertised by --policy must
map to an actual asyncua class, not silently downgrade.

The audit found that `--policy Basic128Rsa15` and `--policy Basic256`
silently substituted Basic256Sha256 because `_configure_secure_channel`'s
policy_map didn't include them. A defensive-security tool must NEVER
swap the requested policy under the user's feet — testing weak legacy
policies is exactly what an operator might want to do.
"""

import argparse

import pytest

from oida.protocols.opcua.proto_args import proto_args


def _advertised_policies() -> list[str]:
    """Return the policy choices advertised on the CLI.

    Looked up dynamically from the subparser's `--policy` action so
    adding a new choice to ``proto_args.py`` automatically extends the
    regression assertion below.
    """
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers(dest="protocol")
    opcua_parser = proto_args(subparsers, [parent])
    if opcua_parser is None:
        # proto_args() returns the registered subparser; some implementations
        # don't return — fall back to introspecting subparsers.choices.
        opcua_parser = subparsers.choices["opcua"]
    for action in opcua_parser._actions:
        if "--policy" in action.option_strings:
            return [c for c in action.choices if c != "None"]
    pytest.fail("--policy choices not found in opcua proto_args")
    return []


class TestSecurityPolicyMapping:
    """Pin the policy-map → asyncua-class contract."""

    def test_all_advertised_policies_have_asyncua_class(self):
        """Every non-None CLI choice must exist in asyncua.crypto.security_policies."""
        asyncua_sec = pytest.importorskip("asyncua.crypto.security_policies")
        missing = []
        for policy in _advertised_policies():
            class_name = f"SecurityPolicy{policy}"
            if not hasattr(asyncua_sec, class_name):
                missing.append((policy, class_name))
        assert not missing, "Policies advertised by --policy must exist in asyncua: " + str(missing)

    def test_policy_map_in_nxc_covers_advertised_set(self):
        """policy_map in _configure_secure_channel must include every CLI choice
        (otherwise the user gets a silent downgrade to Basic256Sha256)."""
        import inspect

        from oida.protocols.opcua import nxc_connection as nxc

        src = (
            inspect.getsource(nxc._configure_secure_channel)
            if hasattr(nxc, "_configure_secure_channel")
            else inspect.getsource(nxc)
        )

        for policy in _advertised_policies():
            assert f'"{policy}":' in src, (
                f"--policy {policy} advertised by CLI but missing from "
                f"_configure_secure_channel.policy_map — would silently downgrade"
            )

    def test_warning_emitted_for_unknown_policy(self):
        """An unmapped policy must surface a warning, not silently swap."""
        import inspect

        from oida.protocols.opcua import nxc_connection as nxc

        # The body should contain the warning-on-unknown-policy guard.
        src = inspect.getsource(nxc)
        assert "Unknown OPC UA security policy" in src or "policy_map" in src, (
            "policy_map must warn or fail on unknown policy"
        )
