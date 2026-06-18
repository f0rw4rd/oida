# OIDA Modbus Register Map Specification

Version: 1.0

## Overview

Register maps are JSON files that define the Modbus register layout for specific devices. They enable:
- Automatic decoding of registers with correct data types and scaling
- Human-readable field names and descriptions
- Enum/status code translation
- SunSpec-style dynamic scale factors
- Coil and discrete input definitions

## File Location

Maps are loaded from (in order):
1. Direct file path
2. `src/oida/protocols/modbus/register_maps/`
3. `~/.oida/modbus/register_maps/`
4. `/etc/oida/modbus/register_maps/`

Subdirectories are supported for organization (e.g., `solar/`, `meters/`, `sunspec/`).

---

## Top-Level Fields

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `vendor` | string | Manufacturer name (e.g., "Huawei", "SunSpec") |
| `model` | string | Device model or family (e.g., "SUN2000 15-100kW") |
| `registers` | object | Register definitions (see below) |

### Optional Metadata

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `description` | string | "" | Human-readable description |
| `version` | string | "" | Map version (for tracking updates) |
| `standard` | string | null | Protocol standard: `"sunspec"`, `"modbus"`, etc. Displayed in output |
| `default_unit_id` | int | 1 | Default Modbus unit/slave ID. Used when `--unit-id` not specified |
| `byte_order` | string | "big" | Byte order: `"big"` or `"little"` |
| `word_order` | string | "big" | Word order for multi-register values: `"big"` or `"little"` |
| `notes` | string | "" | Implementation notes, quirks, update rates |
| `source` | string | "" | Documentation URL or reference |
| `base_address` | int | 0 | Base address offset (for SunSpec models) |
| `sunspec_model_id` | int | null | SunSpec model ID (1, 101, 103, etc.) |

### Optional Sections

| Field | Type | Description |
|-------|------|-------------|
| `coils` | object | Coil definitions (FC 1/5/15) |
| `discrete_inputs` | object | Discrete input definitions (FC 2) |
| `models` | object | Device variant metadata |
| `memory_layout` | object | Memory region documentation |
| `supported_function_codes` | array | Supported FC documentation |

---

## Register Definition

Each register is defined as a key-value pair in the `registers` object:

```json
"registers": {
  "register_name": {
    "address": 100,
    "type": "u16",
    ...
  }
}
```

### Required Register Fields

| Field | Type | Description |
|-------|------|-------------|
| `address` | int | Modbus register address (0-based) |

### Optional Register Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | "u16" | Data type (see Data Types below) |
| `access` | string | "r" | Access mode: `"r"`, `"w"`, `"rw"` |
| `description` | string | "" | Human-readable description |
| `unit` | string | "" | Engineering unit: `"V"`, `"A"`, `"kWh"`, `"C"`, `"%"`, etc. |
| `scale` | float | 1.0 | Multiply raw value by this factor |
| `offset` | float | 0.0 | Add to scaled value: `final = raw * scale + offset` |
| `function_code` | int | 3 | Modbus function code: `3` (holding) or `4` (input) |
| `hex_address` | string | auto | Display address in hex (e.g., `"0x1000"`) |
| `length` | int | 2 | **For strings only:** Character count. Registers = `(length + 1) // 2` |
| `enum` | object | null | Value-to-label mapping (see Enums below) |
| `bitfield` | object | null | Bit-to-label mapping (see Bitfields below) |
| `scale_factor_register` | int | null | Address of SunSpec scale factor register |
| `expected_value` | string | null | Expected value for validation (e.g., `"0x53756E53"`) |

---

## Data Types

| Type | Aliases | Registers | Description |
|------|---------|-----------|-------------|
| `u16` | `uint`, `uint16` | 1 | Unsigned 16-bit integer |
| `i16` | `int`, `int16` | 1 | Signed 16-bit integer |
| `u32` | `uint32` | 2 | Unsigned 32-bit integer |
| `i32` | `int32` | 2 | Signed 32-bit integer |
| `u64` | `uint64` | 4 | Unsigned 64-bit integer |
| `i64` | `int64` | 4 | Signed 64-bit integer |
| `f32` | `float`, `float32` | 2 | IEEE 754 32-bit float |
| `f64` | `double`, `float64` | 4 | IEEE 754 64-bit float |
| `str` | `string`, `text` | varies | ASCII string (use `length` field) |
| `hex` | `binary`, `raw` | varies | Raw hex display |
| `bits` | `bit` | 1 | Binary bit representation |
| `bcd` | | 1 | Binary Coded Decimal |

---

## Enums

Map numeric values to human-readable labels:

```json
"device_status": {
  "address": 32089,
  "type": "u16",
  "enum": {
    "0": "STANDBY",
    "1": "STARTING",
    "512": "ON_GRID",
    "768": "SHUTDOWN"
  }
}
```

**Output:** `512 (ON_GRID)` instead of just `512`

Keys must be strings (JSON limitation). The decoder converts the value to string for lookup.

---

## Bitfields

Document individual bits in a status/event register:

```json
"event_flags": {
  "address": 40,
  "type": "u32",
  "bitfield": {
    "0": "GROUND_FAULT",
    "1": "DC_OVER_VOLT",
    "2": "AC_DISCONNECT",
    "7": "OVER_TEMP"
  }
}
```

**Note:** Bitfield decoding display is not yet implemented in the scanner output; this field is for documentation.

---

## Scale Factors

### Static Scale Factor

Apply a fixed multiplier and offset:

```json
"temperature": {
  "address": 100,
  "type": "i16",
  "scale": 0.1,
  "offset": -40,
  "unit": "C"
}
```

Formula: `displayed_value = raw_value * scale + offset`

### Dynamic Scale Factor (SunSpec)

SunSpec devices store scale factors in separate registers as signed int16 exponents:

```json
"ac_current": {
  "address": 2,
  "type": "u16",
  "scale_factor_register": 6,
  "unit": "A"
},
"ac_current_sf": {
  "address": 6,
  "type": "i16",
  "description": "Current scale factor (A_SF)"
}
```

If register 6 contains `-2`, the scale is `10^-2 = 0.01`.

Formula: `displayed_value = raw_value * (10 ^ sf_register_value)`

**Note:** When using `scale_factor_register`, the `scale` and `offset` fields are ignored.

---

## String Registers

For ASCII strings, specify the character length:

```json
"model_name": {
  "address": 30000,
  "type": "string",
  "length": 15,
  "description": "Device model name"
}
```

The decoder reads `(length + 1) // 2` registers (2 characters per register).

---

## Coils and Discrete Inputs

Define single-bit I/O points:

```json
"coils": {
  "digital_output_0": {
    "address": 512,
    "access": "rw",
    "description": "Digital output bit 0"
  }
},
"discrete_inputs": {
  "digital_input_0": {
    "address": 0,
    "access": "r",
    "description": "Digital input bit 0"
  }
}
```

Coils use FC 1 (read) / FC 5 (write single) / FC 15 (write multiple).
Discrete inputs use FC 2 (read-only).

---

## Complete Example

```json
{
  "vendor": "ExampleCorp",
  "model": "PowerMeter 3000",
  "description": "Three-phase power meter with Modbus RTU/TCP",
  "version": "1.0",
  "standard": "modbus",
  "default_unit_id": 1,
  "byte_order": "big",
  "word_order": "big",
  "notes": "Update rate 1s. Addresses are 0-based.",
  "source": "https://example.com/docs/pm3000-modbus.pdf",

  "registers": {
    "voltage_l1": {
      "address": 0,
      "type": "f32",
      "access": "r",
      "unit": "V",
      "description": "Phase L1 voltage"
    },
    "voltage_l2": {
      "address": 2,
      "type": "f32",
      "access": "r",
      "unit": "V",
      "description": "Phase L2 voltage"
    },
    "total_energy": {
      "address": 100,
      "type": "u32",
      "access": "r",
      "unit": "kWh",
      "scale": 0.01,
      "description": "Total energy consumed"
    },
    "device_status": {
      "address": 200,
      "type": "u16",
      "access": "r",
      "description": "Device operating status",
      "enum": {
        "0": "IDLE",
        "1": "MEASURING",
        "2": "ERROR"
      }
    },
    "serial_number": {
      "address": 300,
      "type": "string",
      "length": 16,
      "access": "r",
      "description": "Device serial number"
    },
    "baud_rate": {
      "address": 400,
      "type": "u16",
      "access": "rw",
      "description": "Modbus baud rate setting",
      "enum": {
        "0": "9600",
        "1": "19200",
        "2": "38400",
        "3": "115200"
      }
    }
  },

  "coils": {
    "relay_output": {
      "address": 0,
      "access": "rw",
      "description": "Alarm relay output"
    }
  }
}
```

---

## Usage

```bash
# Read all registers from a map
oida modbus 192.168.1.100 --register-map powermeter-3000

# List available maps
oida modbus --list-maps

# Use map from subdirectory
oida modbus 192.168.1.100 --register-map solar/huawei-sun2000

# Combine with other options
oida modbus 192.168.1.100 --register-map sunspec-common -v --unit-id 2
```

---

## Validation

When creating maps, verify:

1. **Addresses are correct** - Check vendor documentation
2. **Data types match** - Wrong types cause decode errors
3. **Scale factors are accurate** - Test against known values
4. **Byte/word order is correct** - Common source of garbled data
5. **Enum values are complete** - Cover all documented states

---

## Contributing

Place new maps in the appropriate subdirectory:
- `solar/` - Solar inverters and charge controllers
- `meters/` - Energy meters
- `battery/` - Battery management systems
- `sunspec/` - SunSpec standard models
- `vfd/` - Variable frequency drives
- `evchargers/` - EV charging stations
- `heatpumps/` - Heat pumps and HVAC
- Root directory - PLCs and general devices

Use lowercase filenames with hyphens: `vendor-model.json`
