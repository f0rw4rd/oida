"""Real-coverage test suite.

These tests measure how much of a real target's surface OIDA actually
covers. They depend on the docker mock stack (``python services.py up``)
and are designed to run as a separate nightly job, not on every PR.

The three axes are scanner field-%, fuzzer CVE replication, and
Conpot-vs-mock fidelity.
"""
