"""End-to-end hash test on a REAL captured HTTP Digest auth exchange.

Fixture ``http/oida_http_digest.pcap`` was captured from a real
``curl --digest`` -> ``httpd:2.4`` (mod_auth_digest) exchange (see
docker/capture/). Account ``oida`` / ``S3cretHt1``, realm ``testrealm``.

hashcat has NO HTTP-digest mode (11400 is SIP); the crackable format is John's
``hdaa`` (``user:$response$...``). This test:

  1. asserts OIDA emits a valid hdaa line (the $digest-md5$ -> hdaa fix), and
  2. proves crackability directly by recomputing the RFC 2617 digest response
     from the known password and the line's own fields, asserting it equals the
     captured response. (That recomputation is exactly what ``john --format=hdaa``
     does internally; we verify it here so the test needs no jumbo-John build.)
"""

import hashlib

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

KNOWN_PASSWORD = "S3cretHt1"


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def test_http_digest_hdaa_is_crackable():
    listener, _devices, _result = _run_listener_test(
        "http",
        "HTTPPassiveListener",
        "http",
        "http/oida_http_digest.pcap",
        min_interactions=0,
    )
    lines = [h for h in listener.get_hashcat_hashes() if ":$response$" in h]
    assert lines, f"no hdaa digest line extracted: {listener.get_hashcat_hashes()}"

    for line in lines:
        assert "$digest-md5$" not in line  # fabricated format must be gone
        user_part, rest = line.split(":$response$", 1)
        response, user, realm, method, uri, nonce, nc, cnonce, qop = rest.split("$")
        assert user_part == user

        # Recompute the RFC 2617 response with the KNOWN password -> must match,
        # proving the captured fields are correct and the password is recoverable.
        ha1 = _md5(f"{user}:{realm}:{KNOWN_PASSWORD}")
        ha2 = _md5(f"{method}:{uri}")
        expected = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        assert expected == response, (
            f"recomputed response {expected} != captured {response}; hdaa fields are wrong"
        )
