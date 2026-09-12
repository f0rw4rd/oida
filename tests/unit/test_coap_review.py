"""Regression tests for RFC 6690 quoted-string handling in parse_link_format.

Bug: the attribute regex `[^";]*` excludes ';' unconditionally, even inside
a quoted-string value, and the entry splitter doesn't account for commas
inside quoted values either. A quoted attribute value containing ';' or ','
(both legal per RFC 5988 quoted-string) truncates the value and corrupts
parsing of subsequent attributes/entries.
"""

from oida.protocols.coap import helpers


def test_quoted_value_with_semicolon_and_multiple_entries():
    payload = '</sensors/temp>;rt="temperature";title="Room A; Zone 1";ct=0,</s/h>;ct=50'
    out = helpers.parse_link_format(payload)

    assert len(out) == 2

    first = out[0]
    assert first["path"] == "/sensors/temp"
    assert first["rt"] == "temperature"
    assert first["title"] == "Room A; Zone 1"
    assert first["ct"] == 0

    second = out[1]
    assert second["path"] == "/s/h"
    assert second["ct"] == 50


def test_quoted_value_with_comma():
    payload = '</a>;title="A, B";rt="x"'
    out = helpers.parse_link_format(payload)

    assert len(out) == 1
    assert out[0]["path"] == "/a"
    assert out[0]["title"] == "A, B"
    assert out[0]["rt"] == "x"


def test_unquoted_value_still_parses():
    out = helpers.parse_link_format("</b>;rt=sensor;ct=40")
    assert len(out) == 1
    assert out[0]["path"] == "/b"
    assert out[0]["rt"] == "sensor"
    assert out[0]["ct"] == 40


def test_valueless_attribute_obs():
    out = helpers.parse_link_format("</c>;obs;rt=sensor")
    assert len(out) == 1
    assert out[0]["path"] == "/c"
    assert out[0]["obs"] is True
    assert out[0]["rt"] == "sensor"


def test_multiple_simple_entries_unaffected():
    payload = (
        '</sensor/temperature>;obs;rt="temperature";ct=0,</actuator/led>;rt="led";if="actuator"'
    )
    out = helpers.parse_link_format(payload)

    assert len(out) == 2
    assert out[0]["path"] == "/sensor/temperature"
    assert out[0]["obs"] is True
    assert out[0]["rt"] == "temperature"
    assert out[0]["ct"] == 0

    assert out[1]["path"] == "/actuator/led"
    assert out[1]["rt"] == "led"
    assert out[1]["if"] == "actuator"
