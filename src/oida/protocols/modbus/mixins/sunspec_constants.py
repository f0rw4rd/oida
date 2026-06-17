"""
SunSpec protocol constants for the SunSpec discovery and security assessment mixin.

Contains model names, sentinel values, security-critical control register
definitions, and protocol markers used by SunSpecMixin.
"""

from typing import Dict

# SunSpec magic marker: "SunS" = 0x53756E53
SUNSPEC_MARKER = 0x53756E53

# Well-known base addresses to probe (in priority order)
SUNSPEC_BASE_ADDRESSES = [40000, 0, 50000]

# End-of-model-chain sentinel
SUNSPEC_END_MODEL_ID = 0xFFFF

# SunSpec security models (Secure Dataset protocol)
SUNSPEC_SECURITY_MODELS = {3, 4, 5, 6, 7, 8, 9}

# Security-critical control models with their writable registers that have
# direct operational impact on DER devices. Keys are model IDs, values are
# dicts mapping register names to an impact description. (These are all
# "rw" control-class registers per the SunSpec spec, but the actual access
# is read from each device's register map at scan time.)
SUNSPEC_CRITICAL_CONTROLS: Dict[int, Dict[str, str]] = {
    123: {
        "conn": "Connect/disconnect inverter from grid",
        "w_max_lim_pct": "Active power curtailment (% of WMax)",
        "w_max_lim_ena": "Enable/disable power limiting",
        "out_pf_set": "Output power factor setpoint",
        "out_pf_set_ena": "Enable/disable PF control",
        "var_pct_ena": "Enable/disable reactive power control",
        "var_w_max_pct": "Reactive power as % of WMax",
        "var_max_pct": "Reactive power as % of VArMax",
        "var_aval_pct": "Reactive power as % of available",
    },
    124: {
        "stor_ctl_mod": "Storage charge/discharge control mode",
        "wcha_max": "Maximum charge power setpoint",
        "out_w_rte": "Discharge rate (% of max)",
        "in_w_rte": "Charge rate (% of max)",
        "cha_gri_set": "Charging source (PV vs grid)",
        "min_rsv_pct": "Minimum reserve percentage",
        "vacha_max": "Maximum charging VA",
    },
    121: {
        "w_max": "Maximum active power setting",
        "v_ref": "Voltage reference setpoint",
        "v_ref_ofs": "Voltage reference offset",
    },
    802: {
        "set_op": "Battery connect/disconnect command",
        "set_inv_state": "Set inverter state (stop/standby/start)",
        "soc_rsv_max": "Max operational reserve setpoint",
        "soc_rsv_min": "Min operational reserve setpoint",
        "ctrl_hb": "Controller heartbeat",
        "alm_rst": "Alarm reset",
    },
}

# Inverter operating states indicating active production
SUNSPEC_ACTIVE_STATES = {4, 5}  # MPPT, THROTTLED

# SunSpec "Not Implemented" sentinel values by data type
SUNSPEC_NOT_IMPLEMENTED = {
    "u16": 0xFFFF,
    "i16": 0x8000,
    "u32": 0xFFFFFFFF,
    "i32": 0x80000000,
    "u64": 0xFFFFFFFFFFFFFFFF,
    "i64": 0x8000000000000000,
    "f32": float("nan"),
    "str": "",
    "sunssf": 0x8000,
    "acc16": 0x0000,
    "acc32": 0x00000000,
    "acc64": 0x0000000000000000,
}

# Well-known SunSpec model names (for models without a JSON map)
SUNSPEC_MODEL_NAMES = {
    1: "Common",
    2: "Basic Aggregator",
    3: "Secure Dataset Read Request",
    4: "Secure Dataset Read Response",
    5: "Secure Dataset Write Request",
    6: "Secure Dataset Write Response",
    7: "Secure Dataset Read Request (Sequenced)",
    8: "Secure Dataset Read Response (Sequenced)",
    9: "Secure Dataset Write Request (Sequenced)",
    11: "Ethernet Link Layer",
    12: "IPv4",
    13: "IPv6",
    14: "Proxy Server",
    17: "Serial Interface",
    101: "Single Phase Inverter (Integer)",
    102: "Split Phase Inverter (Integer)",
    103: "Three Phase Inverter (Integer)",
    111: "Single Phase Inverter (Float)",
    112: "Split Phase Inverter (Float)",
    113: "Three Phase Inverter (Float)",
    120: "Nameplate Ratings",
    121: "Basic Settings",
    122: "Extended Measurements and Status",
    123: "Immediate Controls",
    124: "Basic Storage Control",
    126: "Static Volt-VAR",
    127: "Freq-Watt Param",
    128: "Dynamic Reactive Current",
    129: "LVRT",
    130: "HVRT",
    131: "Watt-PF",
    132: "Volt-Watt",
    133: "Basic Scheduling",
    134: "Freq-Watt Curve",
    135: "LF Trip",
    136: "HF Trip",
    137: "LV Trip",
    138: "HV Trip",
    141: "String Combiner (Integer)",
    142: "String Combiner (Float)",
    143: "String Combiner (Advanced)",
    160: "Multiple MPPT Inverter Extension",
    201: "Single Phase Meter (Integer)",
    202: "Split Phase Meter (Integer)",
    203: "Three Phase Meter (Integer)",
    204: "Three Phase Meter (Delta) (Integer)",
    211: "Single Phase Meter (Float)",
    212: "Split Phase Meter (Float)",
    213: "Three Phase Meter (Float)",
    214: "Three Phase Meter (Delta) (Float)",
    220: "Autoconfiguration",
    302: "Irradiance",
    303: "Back of Module Temperature",
    304: "Inclinometer",
    305: "GPS",
    306: "Reference Point",
    307: "Base Met",
    308: "Mini Met",
    401: "String Combiner",
    402: "String Combiner (Advanced)",
    403: "String Combiner (Current)",
    404: "String Combiner (Current + Voltage)",
    501: "Solar Module",
    502: "Solar Module (Two)",
    601: "Tracker Controller",
    63001: "SunSpec Test Model 1",
    63002: "SunSpec Test Model 2",
    64110: "SolarEdge Inverter",
    64111: "SolarEdge Meter",
    64112: "SolarEdge Battery",
    802: "Battery Base Model",
}
