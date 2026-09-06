#!/usr/bin/env python3
"""
Unit tests for the external register-map converters.

Exercises the Solarman YAML, Nymea JSON and mbmd Go converters plus the
batch `convert_directory` driver against real temp files, asserting the
concrete OIDA-format output values (addresses, types, scales, function
codes, byte/word order, enums) rather than just shapes.
"""

import json

import pytest

from oida.protocols.modbus import convert_maps


# ---------------------------------------------------------------------------
# Solarman YAML converter
# ---------------------------------------------------------------------------


def _write(path, text):
    path.write_text(text)
    return path


class TestSolarmanConverter:
    def test_basic_conversion(self, tmp_path):
        yaml_text = """
parameters:
  - group: solar
    items:
      - name: "PV1 Power"
        uom: "W"
        scale: 1
        rule: 1
        registers: [0x00BA]
      - name: "Battery Voltage"
        uom: "V"
        scale: 0.1
        rule: 2
        registers: [187]
"""
        f = _write(tmp_path / "deye_hybrid.yaml", yaml_text)
        result = convert_maps.convert_solarman_yaml(f)

        assert result is not None
        # vendor/model derived from filename deye_hybrid -> Deye / Hybrid
        assert result["vendor"] == "Deye"
        assert result["model"] == "Hybrid"
        assert result["byte_order"] == "big"
        # No rule-4 item -> word order stays big
        assert result["word_order"] == "big"
        assert result["source"] == "home_assistant_solarman/deye_hybrid.yaml"

        regs = result["registers"]
        assert set(regs) == {"pv1_power", "battery_voltage"}

        pv1 = regs["pv1_power"]
        assert pv1["address"] == 0x00BA  # hex int register kept verbatim
        assert pv1["type"] == "u16"  # rule 1
        assert pv1["access"] == "ro"
        assert pv1["unit"] == "W"
        # scale == 1 is the default, so it is omitted
        assert "scale" not in pv1

        bat = regs["battery_voltage"]
        assert bat["address"] == 187
        assert bat["type"] == "i16"  # rule 2
        assert bat["unit"] == "V"
        assert bat["scale"] == 0.1

    def test_rule4_sets_little_word_order(self, tmp_path):
        yaml_text = """
parameters:
  - group: energy
    items:
      - name: "Total Energy"
        uom: "kWh"
        rule: 4
        registers: ["0x0010"]
"""
        f = _write(tmp_path / "growatt_mic.yaml", yaml_text)
        result = convert_maps.convert_solarman_yaml(f)

        assert result["word_order"] == "little"
        reg = result["registers"]["total_energy"]
        # rule 4 -> u32, address parsed from "0x0010" hex string
        assert reg["type"] == "u32"
        assert reg["address"] == 16

    def test_offset_negated_and_enum_lookup(self, tmp_path):
        yaml_text = """
parameters:
  - group: status
    items:
      - name: "Temp Sensor"
        uom: "C"
        rule: 2
        offset: 100
        registers: [50]
      - name: "Run Mode"
        rule: 1
        isstr: true
        registers: [60]
        lookup:
          - key: 0
            value: "Standby"
          - key: 1
            value: "Running"
"""
        f = _write(tmp_path / "sofar.yaml", yaml_text)
        result = convert_maps.convert_solarman_yaml(f)

        temp = result["registers"]["temp_sensor"]
        assert temp["offset"] == -100  # negated for standard formula

        mode = result["registers"]["run_mode"]
        assert mode["enum"] == {"0": "Standby", "1": "Running"}

    def test_single_part_filename_uses_stem_for_model(self, tmp_path):
        yaml_text = """
parameters:
  - group: g
    items:
      - name: "X"
        rule: 1
        registers: [1]
"""
        f = _write(tmp_path / "deye.yaml", yaml_text)
        result = convert_maps.convert_solarman_yaml(f)
        assert result["vendor"] == "Deye"
        assert result["model"] == "Deye"

    def test_items_without_name_or_registers_skipped(self, tmp_path):
        yaml_text = """
parameters:
  - group: g
    items:
      - name: ""
        rule: 1
        registers: [1]
      - name: "No Regs"
        rule: 1
        registers: []
      - name: "Valid"
        rule: 1
        registers: [5]
"""
        f = _write(tmp_path / "vendor_model.yaml", yaml_text)
        result = convert_maps.convert_solarman_yaml(f)
        assert list(result["registers"]) == ["valid"]

    def test_empty_or_missing_parameters_returns_none(self, tmp_path):
        f = _write(tmp_path / "empty.yaml", "other: 1\n")
        assert convert_maps.convert_solarman_yaml(f) is None

        # parameters present but produce no registers -> None
        f2 = _write(
            tmp_path / "noregs.yaml",
            "parameters:\n  - group: g\n    items: []\n",
        )
        assert convert_maps.convert_solarman_yaml(f2) is None

    def test_invalid_yaml_returns_none(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", "parameters: [unclosed\n")
        assert convert_maps.convert_solarman_yaml(f) is None

    def test_unknown_rule_defaults_to_u16(self, tmp_path):
        yaml_text = """
parameters:
  - group: g
    items:
      - name: "Mystery"
        rule: 99
        registers: [7]
"""
        f = _write(tmp_path / "ven_mod.yaml", yaml_text)
        result = convert_maps.convert_solarman_yaml(f)
        assert result["registers"]["mystery"]["type"] == "u16"


# ---------------------------------------------------------------------------
# Nymea JSON converter
# ---------------------------------------------------------------------------


class TestNymeaConverter:
    def test_basic_conversion(self, tmp_path):
        data = {
            "className": "Sdm630",
            "endianness": "BigEndian",
            "registers": [
                {
                    "id": "voltagePhaseA",
                    "address": 0,
                    "size": 2,
                    "type": "float",
                    "access": "RO",
                    "unit": "V",
                    "registerType": "inputRegister",
                    "description": "Voltage phase A",
                }
            ],
            "blocks": [
                {
                    "registers": [
                        {
                            "id": "currentSum",
                            "address": 48,
                            "size": 2,
                            "type": "float",
                            "access": "RW",
                            "scaleFactor": 0.001,
                            "registerType": "holdingRegister",
                        }
                    ]
                }
            ],
        }
        d = tmp_path / "bgetech"
        d.mkdir()
        f = d / "sdm630-registers.json"
        f.write_text(json.dumps(data))

        result = convert_maps.convert_nymea_json(f)
        assert result is not None
        assert result["vendor"] == "Sdm630"
        assert result["byte_order"] == "big"
        assert result["word_order"] == "big"

        regs = result["registers"]
        assert set(regs) == {"voltagePhaseA", "currentSum"}

        v = regs["voltagePhaseA"]
        assert v["address"] == 0
        assert v["type"] == "f32"  # float + size 2
        assert v["access"] == "ro"
        assert v["unit"] == "V"
        # inputRegister -> FC 4 (non-default), so emitted
        assert v["function_code"] == 4

        c = regs["currentSum"]
        assert c["address"] == 48
        assert c["access"] == "rw"
        assert c["scale"] == 0.001
        # holdingRegister -> FC 3 (default) so function_code omitted
        assert "function_code" not in c

    def test_little_endian_and_float64(self, tmp_path):
        data = {
            "className": "Acme",
            "endianness": "LittleEndian",
            "registers": [
                {"id": "bigval", "address": 10, "size": 4, "type": "float"},
                {"id": "counter", "address": 20, "type": "uint64"},
            ],
        }
        f = tmp_path / "acme-registers.json"
        f.write_text(json.dumps(data))
        result = convert_maps.convert_nymea_json(f)

        assert result["byte_order"] == "little"
        assert result["word_order"] == "little"
        assert result["registers"]["bigval"]["type"] == "f64"  # float + size != 2
        assert result["registers"]["counter"]["type"] == "u64"  # uint64 map

    def test_type_map_and_coil_fc(self, tmp_path):
        data = {
            "className": "Mix",
            "registers": [
                {"id": "a", "address": 1, "type": "int32"},
                {"id": "b", "address": 2, "type": "string"},
                {"id": "c", "address": 3, "type": "weirdtype"},
                {"id": "d", "address": 4, "type": "uint16", "registerType": "coil"},
            ],
        }
        f = tmp_path / "mix-registers.json"
        f.write_text(json.dumps(data))
        result = convert_maps.convert_nymea_json(f)
        regs = result["registers"]
        assert regs["a"]["type"] == "i32"
        assert regs["b"]["type"] == "str"
        assert regs["c"]["type"] == "u16"  # unknown -> default u16
        assert regs["d"]["function_code"] == 1  # coil

    def test_registers_missing_id_or_address_skipped(self, tmp_path):
        data = {
            "className": "Skip",
            "registers": [
                {"id": "", "address": 1, "type": "uint16"},
                {"id": "noaddr", "type": "uint16"},
                {"id": "strAddr", "address": "0x10", "type": "uint16"},
                {"id": "ok", "address": 9, "type": "uint16"},
            ],
        }
        f = tmp_path / "skip-registers.json"
        f.write_text(json.dumps(data))
        result = convert_maps.convert_nymea_json(f)
        # only "ok" survives: empty id, missing address, and non-int address dropped
        assert list(result["registers"]) == ["ok"]

    def test_enums_collected(self, tmp_path):
        data = {
            "className": "WithEnums",
            "registers": [{"id": "state", "address": 0, "type": "uint16"}],
            "enums": [
                {
                    "name": "OperatingState",
                    "values": [
                        {"value": 1, "key": "On"},
                        {"value": 2, "key": "Off"},
                    ],
                }
            ],
        }
        f = tmp_path / "withenums-registers.json"
        f.write_text(json.dumps(data))
        result = convert_maps.convert_nymea_json(f)
        assert result["enums"]["OperatingState"] == {"1": "On", "2": "Off"}

    def test_no_registers_returns_none(self, tmp_path):
        f = tmp_path / "none-registers.json"
        f.write_text(json.dumps({"className": "Empty", "registers": []}))
        assert convert_maps.convert_nymea_json(f) is None

    def test_invalid_json_returns_none(self, tmp_path):
        f = tmp_path / "bad-registers.json"
        f.write_text("{not valid json")
        assert convert_maps.convert_nymea_json(f) is None

    def test_scalefactor_one_omitted(self, tmp_path):
        data = {
            "className": "S",
            "registers": [
                {"id": "x", "address": 0, "type": "uint16", "scaleFactor": 1},
            ],
        }
        f = tmp_path / "s-registers.json"
        f.write_text(json.dumps(data))
        result = convert_maps.convert_nymea_json(f)
        assert "scale" not in result["registers"]["x"]


# ---------------------------------------------------------------------------
# mbmd Go converter
# ---------------------------------------------------------------------------


class TestMbmdConverter:
    def test_basic_conversion_input_registers(self, tmp_path):
        go_src = """
package rs485

func init() {
    Register("ABB", NewABBProducer)
}

func (p *ABBProducer) Description() string {
    return "ABB B-Series meters"
}

var opcodes = map[Measurement]uint16{
    Power:        0x5B14, // Total active power
    VoltageL1:    0x5B00, // Voltage L1
}
"""
        f = tmp_path / "abb.go"
        f.write_text(go_src)
        result = convert_maps.convert_mbmd_go(f)

        assert result is not None
        assert result["vendor"] == "ABB"
        assert result["model"] == "ABB B-Series meters"
        assert result["byte_order"] == "big"
        assert result["source"] == "mbmd/meters/rs485/abb.go"

        regs = result["registers"]
        # CamelCase -> snake_case
        assert "power" in regs
        assert "voltage_l1" in regs

        power = regs["power"]
        assert power["address"] == 0x5B14
        assert power["type"] == "f32"
        assert power["access"] == "ro"
        assert power["description"] == "Total active power"
        # no ReadHoldingReg in source -> input registers FC 4
        assert power["function_code"] == 4

    def test_holding_register_fc_when_present(self, tmp_path):
        go_src = """
func init() { Register("SDM", NewSDMProducer) }
// uses ReadHoldingReg for everything
var opcodes = map[Measurement]uint16{
    Frequency: 70, // Grid frequency
}
"""
        f = tmp_path / "sdm.go"
        f.write_text(go_src)
        result = convert_maps.convert_mbmd_go(f)
        freq = result["registers"]["frequency"]
        assert freq["function_code"] == 3  # holding registers
        assert freq["address"] == 70  # decimal address

    def test_comment_optional_defaults_to_name(self, tmp_path):
        # A trailing "//" with nothing after it (EOF, no newline) leaves the
        # comment group empty so the converter falls back to the opcode name.
        go_src = (
            'func init() { Register("Meter", X) }\nvar opcodes = map[M]uint16{ Current: 0x10, //'
        )
        f = tmp_path / "meter.go"
        f.write_text(go_src)
        result = convert_maps.convert_mbmd_go(f)
        cur = result["registers"]["current"]
        # empty comment -> falls back to the opcode name
        assert cur["description"] == "Current"

    def test_no_register_call_returns_none(self, tmp_path):
        f = tmp_path / "registry.go"
        f.write_text("package rs485\n// no Register call here\n")
        assert convert_maps.convert_mbmd_go(f) is None

    def test_no_opcodes_returns_none(self, tmp_path):
        go_src = 'func init() { Register("Empty", X) }\n'
        f = tmp_path / "empty.go"
        f.write_text(go_src)
        assert convert_maps.convert_mbmd_go(f) is None

    def test_description_falls_back_to_meter_name(self, tmp_path):
        go_src = """
func init() { Register("NoDesc", X) }
var opcodes = map[M]uint16{ Power: 1, // p
}
"""
        f = tmp_path / "nodesc.go"
        f.write_text(go_src)
        result = convert_maps.convert_mbmd_go(f)
        assert result["model"] == "NoDesc"


# ---------------------------------------------------------------------------
# Batch directory conversion
# ---------------------------------------------------------------------------


class TestConvertDirectory:
    def test_solarman_directory(self, tmp_path):
        src = tmp_path / "src"
        defs = src / "custom_components" / "solarman" / "inverter_definitions"
        defs.mkdir(parents=True)
        (defs / "deye_hybrid.yaml").write_text(
            "parameters:\n  - group: g\n    items:\n"
            '      - name: "Power"\n        rule: 1\n        registers: [1]\n'
        )
        # services.yaml must be skipped
        (defs / "services.yaml").write_text(
            "parameters:\n  - group: g\n    items:\n"
            '      - name: "X"\n        rule: 1\n        registers: [2]\n'
        )
        out = tmp_path / "out"

        success, total = convert_maps.convert_directory(src, out, "solarman")
        assert (success, total) == (1, 1)  # services.yaml not counted

        produced = out / "solar" / "solarman-deye_hybrid.json"
        assert produced.exists()
        loaded = json.loads(produced.read_text())
        assert loaded["registers"]["power"]["address"] == 1

    def test_nymea_directory_subdir_routing(self, tmp_path):
        src = tmp_path / "src"
        sma = src / "sma"
        sma.mkdir(parents=True)
        (sma / "inverter-registers.json").write_text(
            json.dumps(
                {
                    "className": "SmaInv",
                    "registers": [{"id": "p", "address": 0, "type": "uint16"}],
                }
            )
        )
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "nymea")
        assert (success, total) == (1, 1)
        # 'sma' parent -> routed to solar/
        assert (out / "solar" / "sma-inverter.json").exists()

    def test_nymea_directory_misc_routing(self, tmp_path):
        src = tmp_path / "src"
        unknown = src / "weirdvendor"
        unknown.mkdir(parents=True)
        (unknown / "x-registers.json").write_text(
            json.dumps(
                {
                    "className": "X",
                    "registers": [{"id": "r", "address": 0, "type": "uint16"}],
                }
            )
        )
        out = tmp_path / "out"
        convert_maps.convert_directory(src, out, "nymea")
        assert (out / "misc" / "weirdvendor-x.json").exists()

    def test_mbmd_directory_skips_infrastructure(self, tmp_path):
        src = tmp_path / "src"
        rs485 = src / "meters" / "rs485"
        rs485.mkdir(parents=True)
        (rs485 / "abb.go").write_text(
            'func init() { Register("ABB", X) }\nvar o = map[M]uint16{ Power: 0x10, // p\n}\n'
        )
        # infra files that must be skipped
        for skip in ("registry.go", "rs485.go", "producer.go", "transform.go"):
            (rs485 / skip).write_text('func init() { Register("Y", X) }\n')
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "mbmd")
        assert (success, total) == (1, 1)
        assert (out / "meters" / "mbmd-abb.json").exists()

    def test_solarman_skipped_when_no_registers(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "deye_skip.yaml").write_text("parameters:\n  - group: g\n    items: []\n")
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "solarman")
        assert success == 0
        assert total == 1
        assert not (out / "solar").exists() or not any((out / "solar").iterdir())

    def test_mbmd_skipped_when_no_registers(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        # Register() present but no opcodes -> convert_mbmd_go returns None
        (src / "empty.go").write_text('func init() { Register("Empty", X) }\n')
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "mbmd")
        assert success == 0
        assert total == 1

    def test_skipped_file_not_counted_as_success(self, tmp_path):
        # nymea file with no registers -> total increments, success does not
        src = tmp_path / "src"
        d = src / "vendor"
        d.mkdir(parents=True)
        (d / "empty-registers.json").write_text(json.dumps({"className": "E", "registers": []}))
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "nymea")
        assert success == 0
        assert total == 1

    def test_unknown_format_returns_zero(self, tmp_path):
        out = tmp_path / "out"
        assert convert_maps.convert_directory(tmp_path, out, "bogus") == (0, 0)

    @pytest.mark.parametrize(
        "parent,subdir",
        [
            ("mennekes", "evchargers"),
            ("idm", "heatpumps"),
            ("inepro", "meters"),
        ],
    )
    def test_nymea_subdir_routing_categories(self, tmp_path, parent, subdir):
        src = tmp_path / "src"
        d = src / parent
        d.mkdir(parents=True)
        (d / "dev-registers.json").write_text(
            json.dumps(
                {
                    "className": "Dev",
                    "registers": [{"id": "r", "address": 0, "type": "uint16"}],
                }
            )
        )
        out = tmp_path / "out"
        convert_maps.convert_directory(src, out, "nymea")
        assert (out / subdir / f"{parent}-dev.json").exists()

    def test_solarman_direct_path_fallback(self, tmp_path):
        # No custom_components/.../inverter_definitions tree -> source dir used directly
        src = tmp_path / "src"
        src.mkdir()
        (src / "deye_x.yaml").write_text(
            "parameters:\n  - group: g\n    items:\n"
            '      - name: "P"\n        rule: 1\n        registers: [1]\n'
        )
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "solarman")
        assert (success, total) == (1, 1)
        assert (out / "solar" / "solarman-deye_x.json").exists()

    def test_mbmd_direct_path_fallback(self, tmp_path):
        # No meters/rs485 tree -> source dir used directly
        src = tmp_path / "src"
        src.mkdir()
        (src / "x.go").write_text(
            'func init() { Register("X", Y) }\nvar o = map[M]uint16{ Power: 0x10, // p\n}\n'
        )
        out = tmp_path / "out"
        success, total = convert_maps.convert_directory(src, out, "mbmd")
        assert (success, total) == (1, 1)


# ---------------------------------------------------------------------------
# mbmd read error path
# ---------------------------------------------------------------------------


def test_mbmd_unreadable_file_returns_none(tmp_path):
    # A directory cannot be read as text -> read_text raises -> None
    d = tmp_path / "notafile.go"
    d.mkdir()
    assert convert_maps.convert_mbmd_go(d) is None


# ---------------------------------------------------------------------------
# CLI main()
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_end_to_end_nymea(self, tmp_path, monkeypatch, capsys):
        src = tmp_path / "src"
        d = src / "bgetech"
        d.mkdir(parents=True)
        (d / "meter-registers.json").write_text(
            json.dumps(
                {
                    "className": "M",
                    "registers": [{"id": "v", "address": 0, "type": "uint16"}],
                }
            )
        )
        out = tmp_path / "out"
        argv = ["convert_maps", "nymea", str(src), "-o", str(out)]
        monkeypatch.setattr("sys.argv", argv)

        # main() runs the converter and then validate_maps; both should succeed
        convert_maps.main()

        produced = out / "meters" / "bgetech-meter.json"
        assert produced.exists()
        loaded = json.loads(produced.read_text())
        assert loaded["registers"]["v"]["address"] == 0

    def test_main_missing_source_exits(self, tmp_path, monkeypatch):
        missing = tmp_path / "does_not_exist"
        argv = ["convert_maps", "nymea", str(missing)]
        monkeypatch.setattr("sys.argv", argv)
        with pytest.raises(SystemExit) as exc:
            convert_maps.main()
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# Type-map constants sanity
# ---------------------------------------------------------------------------


def test_constant_maps_round_trip():
    assert convert_maps.SOLARMAN_RULE_TO_TYPE[3] == "u32"
    assert convert_maps.NYMEA_TYPE_MAP["int64"] == "i64"
    assert convert_maps.NYMEA_REGTYPE_TO_FC["discreteInput"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
