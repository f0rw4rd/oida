"""Tests for the fuzzer combinatorial-depth controls (--max-depth / --only-depth).

Covers three things:
  1. The boofuzz contract the feature rests on (depth-scoped generation, and
     that a depth cap terminates) so a boofuzz upgrade that breaks it fails here.
  2. CLI parsing of --max-depth / --only-depth / --depth / -D, incl. mutual
     exclusion.
  3. Config plumbing: FuzzerConfig carries the new fields (default None).
"""

import argparse

import pytest


def _build_session(nfields=4):
    """Small in-memory boofuzz Session with `nfields` fuzzable fields, no network."""
    boofuzz = pytest.importorskip("boofuzz")
    from boofuzz.connections import TCPSocketConnection

    kids = []
    for i in range(nfields):
        kids.append(boofuzz.Bytes(name=f"b{i}", default_value=b"AAAA"))
    req = boofuzz.Request("t", children=tuple(kids))
    # fuzz_loggers=[] + web_port=None keep the Session silent so boofuzz's stdout
    # logger / web thread don't race pytest's capture teardown (colorama I/O error).
    s = boofuzz.Session(
        target=boofuzz.Target(connection=TCPSocketConnection("127.0.0.1", 9)),
        fuzz_loggers=[],
        web_port=None,
    )
    s.connect(req)
    return s


class TestBoofuzzDepthContract:
    def test_generate_n_mutations_yields_only_that_depth(self):
        s = _build_session(nfields=4)
        s.total_mutant_index = 0
        gen = s._generate_n_mutations(depth=2, path=None)
        # Sample the head of the depth-2 stream; every case mutates exactly 2 fields.
        for _ in range(200):
            mc = next(gen)
            assert len(mc.mutations) == 2

    def test_only_depth_starts_immediately(self):
        s = _build_session(nfields=4)
        s.total_mutant_index = 0
        gen = s._generate_n_mutations(depth=3, path=None)
        first = next(gen)  # must not require walking depths 1/2 first
        assert len(first.mutations) == 3

    def test_depth1_count_matches_num_mutations(self):
        s = _build_session(nfields=4)
        d1 = s.num_mutations(max_depth=1)
        assert isinstance(d1, int) and d1 > 0
        s.total_mutant_index = 0
        count = sum(1 for _ in s._generate_n_mutations(depth=1, path=None))
        assert count == d1

    def test_default_space_has_no_finite_total(self):
        # The whole point: a default (combinatorial) run has no practical total.
        s = _build_session(nfields=4)
        assert s.num_mutations(max_depth=None) is None


def _fuzz_parser():
    from oida.fuzz_cli import fuzz_args

    root = argparse.ArgumentParser(prog="oida")
    sub = root.add_subparsers(dest="command")
    fuzz_args(sub, parents=[])
    return root


class TestDepthCLIParsing:
    def test_max_depth(self):
        a = _fuzz_parser().parse_args(["fuzz", "modbus", "127.0.0.1", "--max-depth", "2"])
        assert a.max_depth == 2
        assert a.only_depth is None

    @pytest.mark.parametrize("flag", ["--only-depth", "--depth", "-D"])
    def test_only_depth_and_aliases(self, flag):
        a = _fuzz_parser().parse_args(["fuzz", "modbus", "127.0.0.1", flag, "3"])
        assert a.only_depth == 3
        assert a.max_depth is None

    def test_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            _fuzz_parser().parse_args(
                ["fuzz", "modbus", "127.0.0.1", "--max-depth", "2", "--only-depth", "3"]
            )

    def test_default_absent(self):
        a = _fuzz_parser().parse_args(["fuzz", "modbus", "127.0.0.1"])
        assert getattr(a, "max_depth", None) is None
        assert getattr(a, "only_depth", None) is None


class TestConfigPlumbing:
    def test_config_fields_default_none(self):
        from oida.fuzz.core.config import FuzzerConfig

        cfg = FuzzerConfig(target_ip="127.0.0.1", target_port=502)
        assert cfg.max_depth is None
        assert cfg.only_depth is None

    def test_config_accepts_depth(self):
        from oida.fuzz.core.config import FuzzerConfig

        cfg = FuzzerConfig(target_ip="127.0.0.1", target_port=502, only_depth=3)
        assert cfg.only_depth == 3
