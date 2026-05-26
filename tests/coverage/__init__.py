"""Real-coverage test suite.

These tests measure how much of a real target's surface OIDA actually
covers. They depend on the docker mock stack (``python services.py up``)
and are designed to run as a separate nightly job, not on every PR.

See ``docs/REAL_COVERAGE_PROPOSAL.md`` for the design and the three axes
(scanner field-%, fuzzer CVE replication, Conpot-vs-mock fidelity).
"""
