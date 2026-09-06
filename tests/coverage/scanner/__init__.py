"""Axis 1: scanner field-coverage %.

For each protocol, run the scanner against the docker mock target,
compare the populated ``results["data"]`` surface against an expected
set (curated in ``surface.py``) plus the wire-level dissector field
set (``ref/<proto>/tshark_fields.json``). Output a per-protocol
coverage % to ``tests/coverage/results/scanner_<date>.json``.
"""
