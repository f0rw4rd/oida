#!/usr/bin/env python3
"""Unit tests for the MMS/IEC 61850 device fingerprinting engine.

These exercise the pure-Python FingerprintMatcher (no native pyiec61850
binding needed): domain-pattern matching, verify rules (literal + regex),
attribute extraction (plain / regex-group / default), priority ordering,
and the end-to-end fingerprint_device() walk against a mocked read_func.
"""

import json

import pytest

from oida.protocols.mms.fingerprint import (
    FingerprintMatch,
    FingerprintMatcher,
    FingerprintRule,
    load_mms_fingerprints,
)


def _reader(table):
    """Build a read_func(domain, attr) that looks values up in a dict.

    table maps (domain, attr) -> value, or attr -> value (domain ignored).
    """

    def read(domain, attr):
        if (domain, attr) in table:
            return table[(domain, attr)]
        return table.get(attr)

    return read


class TestFingerprintRuleFromDict:
    def test_defaults_when_keys_absent(self):
        rule = FingerprintRule.from_dict({})
        assert rule.name == "Unknown"
        assert rule.vendor_id == "unknown"
        assert rule.domain_pattern == ".*"
        assert rule.device_type == "IED"
        assert rule.priority == 0
        assert rule.attributes == {}
        assert rule.verify == {}

    def test_populates_all_fields(self):
        rule = FingerprintRule.from_dict(
            {
                "name": "ACME Relay",
                "vendor_id": "acme",
                "domain_pattern": "ACME.*",
                "attributes": {"vendor": "LLN0$DC$NamPlt$vendor"},
                "verify": {"LLN0$DC$NamPlt$vendor": "ACME"},
                "custom": {"order": "X"},
                "device_type": "Protection Relay",
                "priority": 5,
            }
        )
        assert rule.name == "ACME Relay"
        assert rule.domain_pattern == "ACME.*"
        assert rule.device_type == "Protection Relay"
        assert rule.priority == 5
        assert rule.custom == {"order": "X"}


class TestDomainMatching:
    def test_get_matching_rules_filters_by_pattern(self):
        m = FingerprintMatcher()
        m.add_rule(FingerprintRule.from_dict({"name": "siemens", "domain_pattern": "SIPApp.*"}))
        m.add_rule(FingerprintRule.from_dict({"name": "wild", "domain_pattern": ".*"}))

        matches = m.get_matching_rules("SIPApplication")
        names = {r.name for r in matches}
        assert names == {"siemens", "wild"}

        # A domain that only the wildcard matches.
        only_wild = m.get_matching_rules("RandomDomain")
        assert {r.name for r in only_wild} == {"wild"}

    def test_invalid_regex_pattern_is_skipped_not_raised(self):
        m = FingerprintMatcher()
        m.add_rule(FingerprintRule.from_dict({"name": "bad", "domain_pattern": "([unclosed"}))
        m.add_rule(FingerprintRule.from_dict({"name": "good", "domain_pattern": "GOOD.*"}))
        matches = m.get_matching_rules("GOODdomain")
        assert {r.name for r in matches} == {"good"}

    def test_add_rule_sorts_by_priority(self):
        m = FingerprintMatcher()
        m.add_rule(FingerprintRule.from_dict({"name": "low", "priority": 10}))
        m.add_rule(FingerprintRule.from_dict({"name": "high", "priority": 1}))
        m.add_rule(FingerprintRule.from_dict({"name": "mid", "priority": 5}))
        assert [r.name for r in m.rules] == ["high", "mid", "low"]


class TestVerifyRule:
    def test_no_verify_block_passes(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"name": "x"})
        assert m.verify_rule(rule, _reader({}), "DOM") is True

    def test_literal_match_passes(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"verify": {"vendorAttr": "SIEMENS"}})
        read = _reader({"vendorAttr": "SIEMENS"})
        assert m.verify_rule(rule, read, "DOM") is True

    def test_literal_mismatch_fails(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"verify": {"vendorAttr": "SIEMENS"}})
        read = _reader({"vendorAttr": "ABB"})
        assert m.verify_rule(rule, read, "DOM") is False

    def test_missing_attribute_fails(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"verify": {"vendorAttr": "SIEMENS"}})
        # read returns None for unknown attr
        assert m.verify_rule(rule, _reader({}), "DOM") is False

    def test_regex_anchored_expected_matches(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"verify": {"model": "^7.*"}})
        assert m.verify_rule(rule, _reader({"model": "7SJ80"}), "DOM") is True
        assert m.verify_rule(rule, _reader({"model": "ABB123"}), "DOM") is False

    def test_all_checks_must_pass(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"verify": {"vendor": "SIEMENS", "model": "^7.*"}})
        ok = _reader({"vendor": "SIEMENS", "model": "7SJ"})
        bad = _reader({"vendor": "SIEMENS", "model": "BAD"})
        assert m.verify_rule(rule, ok, "DOM") is True
        assert m.verify_rule(rule, bad, "DOM") is False


class TestExtractAttributes:
    def test_plain_attribute_mapping_to_known_fields(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict(
            {
                "name": "ACME",
                "vendor_id": "acme",
                "device_type": "Relay",
                "attributes": {
                    "vendor": "v",
                    "model": "mo",
                    "serial": "se",
                    "firmware": "fw",
                    "hardware_rev": "hw",
                    "config_rev": "cf",
                },
            }
        )
        read = _reader(
            {
                "v": "ACME",
                "mo": "M1",
                "se": "SN1",
                "fw": "1.2.3",
                "hw": "RevA",
                "cf": "C1",
            }
        )
        match = m.extract_attributes(rule, read, "DOM")
        assert match.vendor == "ACME"
        assert match.model == "M1"
        assert match.serial == "SN1"
        assert match.firmware == "1.2.3"
        assert match.hardware_rev == "RevA"
        assert match.config_rev == "C1"
        assert match.raw_attributes["vendor"] == "ACME"

    def test_regex_group_extraction(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict(
            {
                "attributes": {
                    "model": {"attribute": "swRev", "regex": 'FID=([^"]+)'},
                }
            }
        )
        read = _reader({"swRev": "FID=SEL-487-R100;"})
        match = m.extract_attributes(rule, read, "DOM")
        assert match.model == "SEL-487-R100;"

    def test_regex_no_match_yields_none(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict(
            {"attributes": {"model": {"attribute": "swRev", "regex": 'FID=([^"]+)'}}}
        )
        read = _reader({"swRev": "no fid here"})
        match = m.extract_attributes(rule, read, "DOM")
        assert match.model is None

    def test_default_value_used_without_reading(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"attributes": {"vendor": {"default": "HardcodedVendor"}}})
        # read_func would return None for everything; default wins.
        match = m.extract_attributes(rule, _reader({}), "DOM")
        assert match.vendor == "HardcodedVendor"

    def test_custom_attributes_collected(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"custom": {"order_number": "ord"}})
        read = _reader({"ord": "7SJ8011"})
        match = m.extract_attributes(rule, read, "DOM")
        assert match.custom["order_number"] == "7SJ8011"

    def test_unreadable_attribute_omitted(self):
        m = FingerprintMatcher()
        rule = FingerprintRule.from_dict({"attributes": {"vendor": "v"}})
        match = m.extract_attributes(rule, _reader({}), "DOM")
        assert match.vendor is None
        assert "vendor" not in match.raw_attributes


class TestFingerprintDevice:
    def test_first_matching_verified_rule_wins(self):
        m = FingerprintMatcher()
        # priority 0 rule requires ABB and won't verify; priority 1 requires SIEMENS and will.
        m.add_rule(
            FingerprintRule.from_dict(
                {
                    "name": "abb",
                    "priority": 0,
                    "domain_pattern": ".*",
                    "verify": {"v": "ABB"},
                    "attributes": {"vendor": "v"},
                }
            )
        )
        m.add_rule(
            FingerprintRule.from_dict(
                {
                    "name": "siemens",
                    "priority": 1,
                    "domain_pattern": ".*",
                    "verify": {"v": "SIEMENS"},
                    "attributes": {"vendor": "v"},
                }
            )
        )
        read = _reader({"v": "SIEMENS"})
        match = m.fingerprint_device(["SIPApplication"], read)
        assert match is not None
        assert match.fingerprint_name == "siemens"
        assert match.vendor == "SIEMENS"

    def test_no_match_returns_none(self):
        m = FingerprintMatcher()
        m.add_rule(
            FingerprintRule.from_dict(
                {"name": "abb", "domain_pattern": ".*", "verify": {"v": "ABB"}}
            )
        )
        assert m.fingerprint_device(["DOM"], _reader({"v": "OTHER"})) is None

    def test_walks_multiple_domains(self):
        m = FingerprintMatcher()
        m.add_rule(
            FingerprintRule.from_dict(
                {
                    "name": "siemens",
                    "domain_pattern": "SIP.*",
                    "verify": {"v": "SIEMENS"},
                    "attributes": {"vendor": "v"},
                }
            )
        )
        # First domain doesn't match the pattern; second does.
        read = _reader({("SIPApp", "v"): "SIEMENS"})
        match = m.fingerprint_device(["UnrelatedDomain", "SIPApp"], read)
        assert match is not None
        assert match.fingerprint_name == "siemens"


class TestFingerprintMatchToDict:
    def test_to_dict_includes_only_present_fields(self):
        fm = FingerprintMatch(
            fingerprint_name="ACME",
            vendor_id="acme",
            device_type="Relay",
            vendor="ACME",
            firmware="1.0",
            custom={"order": "X"},
        )
        d = fm.to_dict()
        assert d["fingerprint"] == "ACME"
        assert d["vendor_id"] == "acme"
        assert d["device_type"] == "Relay"
        assert d["vendor"] == "ACME"
        assert d["firmware"] == "1.0"
        assert d["custom"] == {"order": "X"}
        # absent optional fields are not serialized
        assert "model" not in d
        assert "serial" not in d
        assert "hardware_rev" not in d


class TestLoadFingerprints:
    def test_load_missing_file_returns_false(self):
        m = FingerprintMatcher()
        assert m.load_fingerprints("does_not_exist_xyz.json") is False
        assert m.rules == []

    def test_load_from_absolute_path(self, tmp_path):
        data = {
            "fingerprints": [
                {"name": "Z", "priority": 9, "domain_pattern": ".*"},
                {"name": "A", "priority": 1, "domain_pattern": ".*"},
            ]
        }
        f = tmp_path / "fp.json"
        f.write_text(json.dumps(data))

        m = FingerprintMatcher()
        assert m.load_fingerprints(str(f)) is True
        # sorted by priority
        assert [r.name for r in m.rules] == ["A", "Z"]
        assert str(f) in m.loaded_files[0]

    def test_load_real_bundled_fingerprints(self):
        # mms_fingerprints.json ships in src/oida/data and is resolved via
        # _pkg_root(); this guards that the packaged file parses and loads.
        m = load_mms_fingerprints()
        assert len(m.rules) > 0
        # bundled file contains a Siemens rule
        assert any("siemens" in r.vendor_id.lower() for r in m.rules)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
