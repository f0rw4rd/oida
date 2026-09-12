"""Contract: the framework reserves -p/-P/-u for a single meaning everywhere.

`proto_args_factory` hands every protocol the same short flags for the common
network/auth options:

    -p / --port        -P / --password        -u / --username

A protocol that rebinds one of those short flags to something else (an ADS
port on -P, a Modbus unit-id on -u, a listener filter on -p, ...) produces
exactly the port/password confusion this contract exists to prevent: a user
who types `-p 4841` meaning "port" must never have it silently mean something
else, and a tool that tells them to "use -p for the password" is a bug.

When a protocol-specific option would otherwise want one of these letters, the
convention (see the iec104 "W5 fix" and ethercat commit fa61b286) is to drop
the short flag and keep the long flag only -- never to repurpose the reserved
letter.

This test fails CI if any protocol subparser binds -p/-P/-u to a
non-canonical destination.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from oida.loader import ProtocolLoader

# Reserved short flag -> the argparse dest(s) it is allowed to write.
# snmp_user is the SNMPv3 username; snmp keeps -u to stay snmpget-compatible,
# and it *is* the username, so it is an explicit, documented allowance.
RESERVED_SHORT_FLAGS: dict[str, set[str]] = {
    "-p": {"port"},
    "-P": {"password"},
    "-u": {"username", "snmp_user"},
}

_PROTOCOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols"


def _build_all_subparsers() -> dict[str, argparse.ArgumentParser]:
    """Register every protocol's proto_args into one parser, mirroring cli.py,
    and return {subcommand_name: subparser}."""
    loader = ProtocolLoader(str(_PROTOCOLS_DIR))
    parent = argparse.ArgumentParser(add_help=False)
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()

    for name in sorted(loader.get_protocols()):
        module = loader.load_proto_args(name)
        if module is None or not hasattr(module, "proto_args"):
            continue
        module.proto_args(subparsers, [parent])

    return dict(subparsers.choices)


def _reserved_violations(parser: argparse.ArgumentParser) -> list[str]:
    violations = []
    for action in parser._actions:
        for opt in action.option_strings:
            allowed = RESERVED_SHORT_FLAGS.get(opt)
            if allowed is not None and action.dest not in allowed:
                violations.append(
                    f"{opt} -> --{action.dest.replace('_', '-')} "
                    f"(reserved for {'/'.join(sorted(allowed))})"
                )
    return violations


@pytest.fixture(scope="module")
def subparsers() -> dict[str, argparse.ArgumentParser]:
    return _build_all_subparsers()


def test_some_protocols_registered(subparsers):
    """Guard against the sweep silently registering nothing."""
    assert len(subparsers) >= 20


def test_no_protocol_rebinds_reserved_short_flag(subparsers):
    """-p/-P/-u must mean port/password/username in every protocol that uses them."""
    offenders: dict[str, list[str]] = {}
    for name, parser in subparsers.items():
        bad = _reserved_violations(parser)
        if bad:
            offenders[name] = bad

    assert not offenders, "Reserved short flags rebound:\n" + "\n".join(
        f"  {proto}: {', '.join(items)}" for proto, items in sorted(offenders.items())
    )
