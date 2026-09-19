"""Behavioral tests for oida.cli dispatch, config, targets, and export.

The CLI dispatch (main) is driven for real with crafted argv. The only thing
mocked is the scan execution boundary: oida.cli.scan_target (the per-target
protocol-class call). Everything else — argparse, alias resolution, target
parsing, special-subcommand routing, config merge, export — runs unmodified, so
assertions verify routing and arg wiring rather than re-stating the source.
"""

import json

import pytest

from oida import cli

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_scan(monkeypatch, recorder):
    """Replace the per-target scan boundary; record (args, target) per call.

    Returns a success result so main() reports rc=0 unless overridden.
    """

    def fake_scan_target(protocol_class, args, target):
        recorder.append((protocol_class, args, target))
        return {"host": target, "success": True, "protocol": getattr(args, "protocol", "?")}

    monkeypatch.setattr(cli, "scan_target", fake_scan_target)
    return recorder


# ---------------------------------------------------------------------------
# load_config_file
# ---------------------------------------------------------------------------


class TestLoadConfigFile:
    def test_json_config(self, tmp_path):
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"timeout": 9, "threads": 3}))
        cfg = cli.load_config_file(str(p))
        assert cfg == {"timeout": 9, "threads": 3}

    def test_yaml_config(self, tmp_path):
        p = tmp_path / "c.yaml"
        p.write_text("timeout: 7\nport: 502\n")
        cfg = cli.load_config_file(str(p))
        assert cfg["timeout"] == 7
        assert cfg["port"] == 502

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            cli.load_config_file(str(tmp_path / "nope.yaml"))

    def test_unsupported_extension_raises(self, tmp_path):
        p = tmp_path / "c.ini"
        p.write_text("x=1")
        with pytest.raises(ValueError, match="Unsupported"):
            cli.load_config_file(str(p))

    def test_malformed_json_raises(self, tmp_path):
        p = tmp_path / "c.json"
        p.write_text("{not valid json")
        with pytest.raises(ValueError, match="parse"):
            cli.load_config_file(str(p))

    def test_empty_yaml_returns_empty_dict(self, tmp_path):
        p = tmp_path / "c.yaml"
        p.write_text("")
        assert cli.load_config_file(str(p)) == {}


# ---------------------------------------------------------------------------
# _sanitize_table_filename
# ---------------------------------------------------------------------------


class TestSanitizeTableFilename:
    @pytest.mark.parametrize(
        "title,expected",
        [
            (
                "MODBUS 10.0.0.1:502 <-> 10.0.0.2:1234 (5 ops)",
                "modbus_10.0.0.1-502--10.0.0.2-1234",
            ),
            ("OPCUA ::1:4840 <-> ::1:60012 (5 ops)", "opcua_loopback-4840--loopback-60012"),
            ("MMS Sessions", "mms_sessions"),
            ("NTLM Hashes", "ntlm_hashes"),
        ],
    )
    def test_known_titles(self, title, expected):
        assert cli._sanitize_table_filename(title) == expected

    def test_127_loopback_normalized(self):
        out = cli._sanitize_table_filename("PCAP 127.0.0.1:80 <-> 127.0.0.1:1 (1 op)")
        assert "loopback" in out
        assert "127.0.0.1" not in out

    def test_empty_title_falls_back(self):
        assert cli._sanitize_table_filename("()") == "table"


# ---------------------------------------------------------------------------
# export_results / _export_tables
# ---------------------------------------------------------------------------


class TestExportResults:
    def _results(self):
        return [
            {
                "host": "10.0.0.1",
                "ip": "10.0.0.1",
                "protocol": "modbus",
                "port": 502,
                "success": True,
                "data": {"vendor": "ACME", "registers": [1, 2, 3]},
            }
        ]

    def test_json_export_writes_file(self, tmp_path):
        cli.export_results(self._results(), str(tmp_path), "json", protocol_name="modbus")
        out = tmp_path / "modbus.json"
        assert out.exists()
        dumped = json.loads(out.read_text())
        assert dumped[0]["data"]["vendor"] == "ACME"

    def test_csv_export_flattens_data(self, tmp_path):
        cli.export_results(self._results(), str(tmp_path), "csv", protocol_name="modbus")
        out = tmp_path / "modbus.csv"
        assert out.exists()
        text = out.read_text()
        assert "data_vendor" in text
        assert "ACME" in text
        # list value is JSON-encoded into the cell
        assert "registers" in text

    def test_all_format_writes_all(self, tmp_path):
        cli.export_results(self._results(), str(tmp_path), "all", protocol_name="modbus")
        assert (tmp_path / "modbus.json").exists()
        assert (tmp_path / "modbus.csv").exists()
        assert (tmp_path / "modbus.xml").exists()

    def test_empty_results_writes_nothing(self, tmp_path):
        cli.export_results([], str(tmp_path), "json", protocol_name="modbus")
        assert not (tmp_path / "modbus.json").exists()

    def test_xml_export_writes_file(self, tmp_path):
        # XML export writes a well-formed protocol.xml with one <record> per result.
        cli.export_results(self._results(), str(tmp_path), "xml", protocol_name="modbus")
        xml_path = tmp_path / "modbus.xml"
        assert xml_path.exists()
        text = xml_path.read_text()
        assert "<modbus>" in text
        assert "<record>" in text

    def test_tables_exported_to_dedicated_csv(self, tmp_path):
        results = [
            {
                "host": "10.0.0.1",
                "protocol": "pcap",
                "port": 0,
                "success": True,
                "data": {
                    "tables": [
                        {
                            "title": "NTLM Hashes",
                            "headers": ["user", "hash"],
                            "rows": [["admin", "deadbeef"]],
                        }
                    ]
                },
            }
        ]
        # --format json -> only the .json table file, no .csv sibling.
        cli.export_results(results, str(tmp_path), "json", protocol_name="pcap")
        assert (tmp_path / "ntlm_hashes.json").exists()
        assert not (tmp_path / "ntlm_hashes.csv").exists()
        json_data = json.loads((tmp_path / "ntlm_hashes.json").read_text())
        assert json_data[0]["user"] == "admin" and json_data[0]["hash"] == "deadbeef"

    def test_tables_respect_csv_format(self, tmp_path):
        results = [
            {
                "host": "10.0.0.1",
                "protocol": "pcap",
                "port": 0,
                "success": True,
                "data": {
                    "tables": [
                        {
                            "title": "NTLM Hashes",
                            "headers": ["user", "hash"],
                            "rows": [["admin", "deadbeef"]],
                        }
                    ]
                },
            }
        ]
        # --format csv -> only the .csv table file, no .json sibling.
        cli.export_results(results, str(tmp_path), "csv", protocol_name="pcap")
        assert (tmp_path / "ntlm_hashes.csv").exists()
        assert not (tmp_path / "ntlm_hashes.json").exists()
        csv_text = (tmp_path / "ntlm_hashes.csv").read_text()
        assert "admin" in csv_text and "deadbeef" in csv_text

    def test_tables_all_format_writes_both(self, tmp_path):
        results = [
            {
                "host": "10.0.0.1",
                "protocol": "pcap",
                "port": 0,
                "success": True,
                "data": {
                    "tables": [
                        {
                            "title": "NTLM Hashes",
                            "headers": ["user", "hash"],
                            "rows": [["admin", "deadbeef"]],
                        }
                    ]
                },
            }
        ]
        cli.export_results(results, str(tmp_path), "all", protocol_name="pcap")
        assert (tmp_path / "ntlm_hashes.csv").exists()
        assert (tmp_path / "ntlm_hashes.json").exists()

    def test_duplicate_table_titles_deduped(self, tmp_path):
        tbl = {
            "title": "Creds",
            "headers": ["u"],
            "rows": [["a"]],
        }
        results = [
            {
                "host": "h",
                "protocol": "pcap",
                "port": 0,
                "success": True,
                "data": {"tables": [dict(tbl), dict(tbl)]},
            }
        ]
        cli.export_results(results, str(tmp_path), "csv", protocol_name="pcap")
        assert (tmp_path / "creds.csv").exists()
        assert (tmp_path / "creds_1.csv").exists()


# ---------------------------------------------------------------------------
# setup_logging
# ---------------------------------------------------------------------------


class TestSetupLogging:
    def test_debug_flag_enables_debug_level(self):
        import argparse
        import logging

        args = argparse.Namespace(debug=True, verbose=0)
        cli.setup_logging(args)
        assert logging.getLogger("oida").level == logging.DEBUG

    def test_quiet_default_is_error_level(self):
        import argparse
        import logging

        args = argparse.Namespace(debug=False, verbose=0)
        cli.setup_logging(args)
        assert logging.getLogger("oida").level == logging.ERROR

    def test_verbose_enables_debug(self):
        import argparse
        import logging

        args = argparse.Namespace(debug=False, verbose=2)
        cli.setup_logging(args)
        assert logging.getLogger("oida").level == logging.DEBUG


# ---------------------------------------------------------------------------
# _resolve_targets
# ---------------------------------------------------------------------------


class TestResolveTargets:
    def test_ip_range_expanded(self):
        import argparse

        args = argparse.Namespace(target="10.0.0.1-3", list_maps=False)
        targets = cli._resolve_targets(args, "modbus")
        assert targets == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_serial_passthrough(self):
        import argparse

        args = argparse.Namespace(target="/dev/ttyUSB0", list_maps=False)
        targets = cli._resolve_targets(args, "iec101")
        assert targets == ["/dev/ttyUSB0"]

    def test_file_target_protocol_passthrough(self):
        import argparse

        args = argparse.Namespace(target="capture.pcap", list_maps=False)
        targets = cli._resolve_targets(args, "pcap")
        assert targets == ["capture.pcap"]

    def test_list_maps_without_target(self):
        import argparse

        args = argparse.Namespace(target=None, list_maps=True)
        targets = cli._resolve_targets(args, "knx")
        assert targets == ["list-maps"]

    def test_parse_failure_returns_none(self, monkeypatch):
        import argparse

        def boom(_):
            raise ValueError("bad target")

        monkeypatch.setattr(cli, "parse_targets", boom)
        args = argparse.Namespace(target="???", list_maps=False)
        assert cli._resolve_targets(args, "modbus") is None


# ---------------------------------------------------------------------------
# _execute_scans concurrency + aggregation
# ---------------------------------------------------------------------------


class TestExecuteScans:
    def test_counts_success_and_failure(self, monkeypatch):
        import argparse

        def fake_scan(protocol_class, args, target):
            return {"host": target, "success": target != "bad"}

        monkeypatch.setattr(cli, "scan_target", fake_scan)

        class FakeProto:
            default_port = 502

        args = argparse.Namespace(threads=4, quiet=True)
        results, ok, failed = cli._execute_scans(
            FakeProto, args, ["good1", "good2", "bad"], "modbus"
        )
        assert ok == 2
        assert failed == 1
        assert len(results) == 3

    def test_exception_in_scan_counted_as_failure(self, monkeypatch):
        import argparse

        def fake_scan(protocol_class, args, target):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(cli, "scan_target", fake_scan)

        class FakeProto:
            default_port = 0

        args = argparse.Namespace(threads=2, quiet=True)
        results, ok, failed = cli._execute_scans(FakeProto, args, ["a", "b"], "modbus")
        assert ok == 0
        assert failed == 2


# ---------------------------------------------------------------------------
# scan_target Layer-1 vs Layer-2 dispatch
# ---------------------------------------------------------------------------


class TestScanTarget:
    """scan_target uses a single dispatch model: every protocol class is a
    Layer-2 ``connection`` taking (args, db, host) and exposing get_results().
    (The former Layer-1 ``issubclass(BaseScanner)`` branch was removed — no
    protocol resolves to a bare BaseScanner at the dispatch seam.)
    """

    def test_layer2_connection_path_uses_get_results(self):
        import argparse

        class L2:
            def __init__(self, args, db, host):
                self.host = host

            def get_results(self):
                return {"host": self.host, "success": True, "from": "get_results"}

        args = argparse.Namespace(protocol="l2")
        result = cli.scan_target(L2, args, "9.9.9.9")
        assert result["from"] == "get_results"
        assert result["host"] == "9.9.9.9"

    def test_layer2_args_are_deep_copied(self):
        """Per-target host/rhost must be set on a copy, not the shared args."""
        import argparse

        captured = {}

        class L2:
            def __init__(self, args, db, host):
                captured["host_attr"] = args.host
                captured["rhost_attr"] = args.rhost

        shared = argparse.Namespace(protocol="l2", shared_list=[])
        cli.scan_target(L2, shared, "7.7.7.7")
        assert captured["host_attr"] == "7.7.7.7"
        assert captured["rhost_attr"] == "7.7.7.7"
        # The original args object must NOT have gained host/rhost (deep copy).
        assert not hasattr(shared, "host")

    def test_exception_returns_error_result(self):
        import argparse

        class Boom:
            def __init__(self, args, db, host):
                raise RuntimeError("nope")

        args = argparse.Namespace(protocol="boom")
        result = cli.scan_target(Boom, args, "1.1.1.1")
        assert result["success"] is False
        assert "nope" in result["error"]


# ---------------------------------------------------------------------------
# main() end-to-end routing (scan_target mocked)
# ---------------------------------------------------------------------------


class TestMainDispatch:
    def test_no_args_shows_usage(self, capsys):
        assert cli.main([]) == 0
        out = capsys.readouterr().out
        assert "Usage:" in out
        assert "modbus" in out

    def test_bug_flag_short_circuits(self, monkeypatch):
        called = {}
        monkeypatch.setattr(cli, "print_bug_report", lambda: called.setdefault("yes", True))
        assert cli.main(["--bug"]) == 0
        assert called.get("yes") is True

    def test_serial_subcommand_routed(self, monkeypatch):
        seen = {}

        def fake_serial(args):
            seen["protocol"] = args.protocol
            return 0

        monkeypatch.setattr(cli, "handle_serial_command", fake_serial)
        # serial subparser requires its own subcommand; just route + return.
        rc = cli.main(["serial", "list"])
        assert rc == 0
        assert seen["protocol"] == "serial"

    def test_fuzz_subcommand_routed(self, monkeypatch):
        seen = {}

        def fake_fuzz(args):
            seen["protocol"] = args.protocol
            seen["fuzz_protocol"] = args.fuzz_protocol
            return 0

        monkeypatch.setattr(cli, "handle_fuzz_command", fake_fuzz)
        rc = cli.main(["fuzz", "modbus", "127.0.0.1"])
        assert rc == 0
        assert seen["protocol"] == "fuzz"
        assert seen["fuzz_protocol"] == "modbus"

    def test_protocol_scan_routes_to_scan_target(self, monkeypatch):
        rec = []
        _stub_scan(monkeypatch, rec)
        rc = cli.main(["modbus", "10.0.0.1"])
        assert rc == 0
        # exactly one target scanned, with the parsed protocol on args.
        assert len(rec) == 1
        _, args, target = rec[0]
        assert target == "10.0.0.1"
        assert args.protocol == "modbus"

    def test_alias_s7_resolves_to_snap7_class(self, monkeypatch):
        rec = []
        _stub_scan(monkeypatch, rec)
        # 's7' alias -> snap7 protocol class loaded; scan still runs.
        rc = cli.main(["s7", "10.0.0.2"])
        assert rc == 0
        assert len(rec) == 1
        proto_class = rec[0][0]
        # The loaded class comes from the snap7 module, not a literal 's7'.
        assert "snap7" in proto_class.__module__.lower() or proto_class.__name__.lower() in (
            "snap7",
            "s7",
        )

    def test_cidr_expands_to_multiple_scans(self, monkeypatch):
        rec = []
        _stub_scan(monkeypatch, rec)
        rc = cli.main(["-t", "2", "-q", "modbus", "10.0.0.1-4"])
        assert rc == 0
        scanned = sorted(t for _, _, t in rec)
        assert scanned == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

    def test_failed_scan_returns_exit_code_1(self, monkeypatch):
        def fake_scan(protocol_class, args, target):
            return {"host": target, "success": False, "error": "refused"}

        monkeypatch.setattr(cli, "scan_target", fake_scan)
        assert cli.main(["modbus", "10.0.0.9"]) == 1

    def test_config_file_merged_into_args(self, monkeypatch, tmp_path):
        rec = []
        _stub_scan(monkeypatch, rec)
        cfg = tmp_path / "scan.yaml"
        cfg.write_text("threads: 3\n")
        rc = cli.main(["-c", str(cfg), "modbus", "10.0.0.1"])
        assert rc == 0
        _, args, _ = rec[0]
        # Config value applied because operator left --threads at its default.
        assert args.threads == 3

    def test_config_timeout_merged_for_active_protocol(self, monkeypatch, tmp_path):
        """A config `timeout:` must merge using the ACTIVE protocol's own default
        as the baseline. modbus's --timeout default is 2; the merge must not
        compare against some other protocol's default (e.g. ads's 5) or the value
        is silently dropped. Regression guard for the timeout-shadowing fix.
        """
        rec = []
        _stub_scan(monkeypatch, rec)
        cfg = tmp_path / "scan.yaml"
        cfg.write_text("timeout: 30\n")
        # Force modbus to be fully registered (gen_cli_args keys mode off argv).
        monkeypatch.setattr("sys.argv", ["oida", "-c", str(cfg), "modbus", "10.0.0.1"])
        rc = cli.main(["-c", str(cfg), "modbus", "10.0.0.1"])
        assert rc == 0
        _, args, _ = rec[0]
        assert args.timeout == 30

    def test_bad_config_file_returns_1(self, tmp_path):
        # A missing config path triggers a ValueError -> exit code 1.
        rc = cli.main(["-c", str(tmp_path / "missing.yaml"), "modbus", "10.0.0.1"])
        assert rc == 1

    def test_output_triggers_export(self, monkeypatch, tmp_path):
        def fake_scan(protocol_class, args, target):
            return {
                "host": target,
                "success": True,
                "protocol": "modbus",
                "data": {"vendor": "X"},
            }

        monkeypatch.setattr(cli, "scan_target", fake_scan)
        outdir = tmp_path / "out"
        rc = cli.main(["-o", str(outdir), "--format", "json", "modbus", "10.0.0.1"])
        assert rc == 0
        assert (outdir / "modbus.json").exists()

    def test_json_log_path_configured(self, monkeypatch, tmp_path):
        rec = []
        _stub_scan(monkeypatch, rec)
        seen = {}
        import oida.utils.ics_logger as icslog

        monkeypatch.setattr(icslog, "set_json_log_path", lambda p: seen.setdefault("path", p))
        logpath = str(tmp_path / "events.ndjson")
        rc = cli.main(["modbus", "10.0.0.1", "--json-log", logpath])
        assert rc == 0
        assert seen["path"] == logpath

    def test_missing_target_returns_1(self):
        # opcua takes a target positional; omitting it (and not list-maps) fails.
        rc = cli.main(["modbus"])
        assert rc == 1

    def test_goose_mms_enum_derives_target(self, monkeypatch):
        rec = []
        _stub_scan(monkeypatch, rec)
        # `oida goose --mms-enum <ip>` carries its target in --mms-enum, not the
        # positional; main() must derive args.target from it.
        rc = cli.main(["goose", "--mms-enum", "10.0.0.7"])
        assert rc == 0
        assert len(rec) == 1
        _, args, target = rec[0]
        assert target == "10.0.0.7"
        assert args.target == "10.0.0.7"

    def test_iec104_list_ports_routed(self, monkeypatch):
        seen = {}

        def fake_list_ports(for_iec101=False):
            seen["for_iec101"] = for_iec101
            return 0

        monkeypatch.setattr(cli, "_list_serial_ports", fake_list_ports)
        # iec104 requires the target positional; --list-ports short-circuits in
        # main() before any scan, routing to the IEC-101 serial-port listing.
        rc = cli.main(["iec104", "127.0.0.1", "--list-ports"])
        assert rc == 0
        assert seen["for_iec101"] is True


# ---------------------------------------------------------------------------
# print_bug_report smoke (real, no network)
# ---------------------------------------------------------------------------


class TestPrintBugReport:
    def test_emits_diagnostic_block(self, capsys):
        cli.print_bug_report()
        out = capsys.readouterr().out
        assert "OIDA Bug Report Info" in out
        assert "Python:" in out
        assert "Protocol Modules:" in out
        # Fenced for easy paste into an issue.
        assert out.strip().startswith("```")


# ---------------------------------------------------------------------------
# _list_serial_ports
# ---------------------------------------------------------------------------


class TestListSerialPorts:
    def test_lists_ports(self, monkeypatch, capsys):
        class FakePort:
            device = "/dev/ttyUSB0"
            description = "USB Serial"
            hwid = "USB VID:PID=1234"

        import serial.tools.list_ports as lp

        monkeypatch.setattr(lp, "comports", lambda: [FakePort()])
        rc = cli._list_serial_ports(for_iec101=True)
        assert rc == 0
        out = capsys.readouterr().out
        assert "/dev/ttyUSB0" in out
        assert "iec101" in out  # header notes the --iec101 mode

    def test_no_ports(self, monkeypatch, capsys):
        import serial.tools.list_ports as lp

        monkeypatch.setattr(lp, "comports", lambda: [])
        rc = cli._list_serial_ports()
        assert rc == 0
        assert "No serial ports found" in capsys.readouterr().out
