"""Behavioral tests for the CLI --confirm preflight (issue #51).

Dangerous flags must be refused in oida.cli.main() BEFORE any scan runs -
previously the gate only fired inside post-connect feature methods, so a run
with e.g. `oida modbus <ip> --write 1=5` connected, enumerated, printed host
info, and only then refused. These tests drive main() for real and assert the
scan boundary is never reached without --confirm.
"""

import pytest

from oida import cli

pytestmark = pytest.mark.core


def _stub_scan_never_called(monkeypatch):
    """Fail the test if any scan is attempted."""

    def boom(protocol_class, args, target):
        raise AssertionError("scan ran despite missing --confirm")

    monkeypatch.setattr(cli, "scan_target", boom)


class TestConfirmPreflight:
    def test_modbus_write_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["modbus", "192.0.2.1", "--write", "1=5"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "--write requires --confirm" in err
        assert "No traffic was sent" in err

    def test_iec104_write_single_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["iec104", "192.0.2.1", "-W", "100:on"])
        assert rc == 1
        assert "--write-single requires --confirm" in capsys.readouterr().err

    def test_snmp_set_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["snmp", "192.0.2.1", "--set", "1.3.6.1.2.1.1.5.0", "s", "x"])
        assert rc == 1
        assert "--set requires --confirm" in capsys.readouterr().err

    def test_snmp_enum_v3_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["snmp", "192.0.2.1", "-E"])
        assert rc == 1
        assert "--enum-v3 requires --confirm" in capsys.readouterr().err

    def test_ethernetip_write_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["ethernetip", "192.0.2.1", "--write"])
        assert rc == 1
        assert "--write requires --confirm" in capsys.readouterr().err

    def test_bacnet_write_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["bacnet", "192.0.2.1", "--write", "AV:1:pv:72.5"])
        assert rc == 1
        assert "--write requires --confirm" in capsys.readouterr().err

    def test_fhir_delete_refused_without_confirm(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["fhir", "http://192.0.2.1/fhir", "--delete-patient", "5"])
        assert rc == 1
        assert "--delete-patient requires --confirm" in capsys.readouterr().err

    def test_dnp3_control_refused_without_confirm(self, monkeypatch, capsys):
        # dnp3 also has its own validate_args() gate; the preflight must fire
        # first, before any connection.
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["dnp3", "192.0.2.1", "-o", "10", "--bo-direct", "0"])
        assert rc == 1
        assert "requires --confirm" in capsys.readouterr().err

    def test_multiple_dangerous_flags_all_listed(self, monkeypatch, capsys):
        _stub_scan_never_called(monkeypatch)
        rc = cli.main(["modbus", "192.0.2.1", "--write-coil", "5=1", "--write-multiple", "10=1,2"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "--write-coil" in err
        assert "--write-multiple" in err

    def test_confirm_allows_scan_to_proceed(self, monkeypatch):
        recorder = []

        def fake_scan(protocol_class, args, target):
            recorder.append(target)
            return {"host": target, "success": True, "protocol": "modbus"}

        monkeypatch.setattr(cli, "scan_target", fake_scan)
        rc = cli.main(["modbus", "192.0.2.1", "--write", "1=5", "--confirm"])
        assert rc == 0
        assert recorder == ["192.0.2.1"]

    def test_benign_scan_untouched(self, monkeypatch):
        recorder = []

        def fake_scan(protocol_class, args, target):
            recorder.append(target)
            return {"host": target, "success": True, "protocol": "modbus"}

        monkeypatch.setattr(cli, "scan_target", fake_scan)
        rc = cli.main(["modbus", "192.0.2.1"])
        assert rc == 0
        assert recorder == ["192.0.2.1"]

    def test_snmp_confirm_brute_dest_satisfied(self, monkeypatch):
        # snmp's --confirm writes dest="confirm_brute", not "confirm"; the
        # preflight must honor any confirm* key.
        recorder = []

        def fake_scan(protocol_class, args, target):
            recorder.append(target)
            return {"host": target, "success": True, "protocol": "snmp"}

        monkeypatch.setattr(cli, "scan_target", fake_scan)
        rc = cli.main(["snmp", "192.0.2.1", "-E", "--confirm"])
        assert rc == 0
        assert recorder == ["192.0.2.1"]

    def test_config_merged_before_preflight(self, monkeypatch, tmp_path, capsys):
        # A YAML config can carry the dangerous flag; the preflight runs after
        # merge_config_with_args, so the refusal still fires. --config is a
        # top-level flag, so it goes before the protocol subcommand.
        _stub_scan_never_called(monkeypatch)
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("write: 1=5\n")
        rc = cli.main(["--config", str(cfg), "modbus", "192.0.2.1"])
        assert rc == 1
        assert "--write requires --confirm" in capsys.readouterr().err
