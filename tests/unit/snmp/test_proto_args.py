"""Feature-flag coverage for SNMP proto_args."""

import argparse


from oida.protocols.snmp.proto_args import proto_args


def _parse(*flags):
    parent = argparse.ArgumentParser(add_help=False)
    main = argparse.ArgumentParser()
    subparsers = main.add_subparsers()
    proto_args(subparsers, [parent])
    return main.parse_args(["snmp", "127.0.0.1", *flags])


class TestSNMPProtoArgs:
    def test_target_positional(self):
        assert _parse().target == "127.0.0.1"

    def test_default_port(self):
        assert _parse().port == 161

    def test_auth_flag(self):
        args = _parse("--auth", "public")
        assert args.auth == "public"

    def test_snmp_version_default(self):
        assert _parse().snmp_version == "auto"

    def test_snmp_version_v1(self):
        args = _parse("--snmp-version", "1")
        assert args.snmp_version == "1"

    def test_walk_default_falsey(self):
        assert not _parse().walk

    def test_walk_flag(self):
        args = _parse("--walk")
        assert args.walk is True or args.walk == "1.3.6.1" or args.walk

    def test_walk_with_oid(self):
        args = _parse("--walk", "1.3.6.1.2.1.1")
        assert args.walk == "1.3.6.1.2.1.1"

    def test_get_oid(self):
        # SNMP uses dest='get_oids' (comma-separated form)
        args = _parse("--get", "1.3.6.1.2.1.1.1.0")
        assert args.get_oids == "1.3.6.1.2.1.1.1.0"

    def test_walk_all_flag(self):
        assert _parse("--walk-all").walk_all is True

    def test_set_value(self):
        # --set takes 3 args (OID TYPE VALUE) into dest='set_oid'
        args = _parse("--set", "1.3.6.1.2.1.1.5.0", "s", "newname")
        assert args.set_oid == ["1.3.6.1.2.1.1.5.0", "s", "newname"]

    def test_bulk_flag(self):
        # --bulk is store_true (use GETBULK instead of GETNEXT)
        assert _parse("--bulk").bulk is True

    def test_mib_dir(self):
        # SNMP uses dest='mib_dirs' (append, repeatable)
        args = _parse("--mib-dir", "/tmp/mibs")
        assert args.mib_dirs == ["/tmp/mibs"]

    def test_default_creds_flag(self):
        assert _parse("--default-creds").default_creds is True

    def test_snmp_user(self):
        args = _parse("--snmp-user", "alice")
        assert args.snmp_user == "alice"

    def test_snmp_auth_protocol(self):
        args = _parse("--snmp-auth-protocol", "SHA")
        assert args.snmp_auth_protocol == "SHA"

    def test_snmp_priv_protocol(self):
        # Valid choices: DES, 3DES, AES128, AES192, AES256
        args = _parse("--snmp-priv-protocol", "AES128")
        assert args.snmp_priv_protocol == "AES128"

    def test_snmp_security_level(self):
        args = _parse("--snmp-security-level", "authPriv")
        assert args.snmp_security_level == "authPriv"
