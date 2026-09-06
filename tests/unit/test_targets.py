#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for oida.targets.

Focus: count_targets() must agree with what parse_targets() /
expand_targets_lazy() actually produce, and file expansion must survive a
targets file that includes itself.
"""

import pytest

from oida.targets import (
    count_targets,
    expand_targets_lazy,
    parse_cidr,
    parse_target_file,
    parse_targets,
)


@pytest.mark.parametrize(
    "spec",
    [
        "192.168.1.100",
        "192.168.1.0/30",
        "192.168.1.0/31",
        "192.168.1.0/32",
        "192.168.1.1-5",
        "10.0.0.1,10.0.0.2",
        "2001:db8::1",
        "2001:db8::/126",
        "2001:db8::/127",
        "2001:db8::/128",
        "[2001:db8::1]-[2001:db8::4]",
        "opc.tcp://host:4840",
        "example.com",
    ],
)
def test_count_matches_expansion(spec):
    """count_targets() is used to size progress bars — it must not lie."""
    assert count_targets(spec) == len(parse_targets(spec))
    assert count_targets(spec) == len(list(expand_targets_lazy(spec)))


def test_ipv6_cidr_keeps_every_usable_address():
    """IPv6 has no broadcast address: only the subnet-router anycast drops out."""
    assert parse_cidr("2001:db8::/126") == ["2001:db8::1", "2001:db8::2", "2001:db8::3"]


def test_ipv4_cidr_drops_network_and_broadcast():
    hosts = parse_cidr("192.168.1.0/29")
    assert hosts[0] == "192.168.1.1"
    assert hosts[-1] == "192.168.1.6"
    assert len(hosts) == 6


def test_self_including_target_file_does_not_recurse(tmp_path):
    """A targets file that lists itself must not blow the stack."""
    f = tmp_path / "targets.txt"
    f.write_text(f"{f}\n192.168.1.1\n")

    assert parse_target_file(str(f)) == ["192.168.1.1"]
    assert count_targets(str(f)) == 1


def test_mutually_including_target_files_do_not_recurse(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text(f"{b}\n10.0.0.1\n")
    b.write_text(f"{a}\n10.0.0.2\n")

    assert sorted(parse_target_file(str(a))) == ["10.0.0.1", "10.0.0.2"]
    assert count_targets(str(a)) == 2
