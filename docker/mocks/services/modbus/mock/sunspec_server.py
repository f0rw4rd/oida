#!/usr/bin/env python3
"""
Mock SunSpec Modbus TCP Server for testing OIDA --sunspec scanner

Simulates a SunSpec-compliant three-phase PV inverter with battery storage.
Builds a proper SunSpec model chain at base address 40000:

  40000-40001: SunS marker (0x53756E53)
  40002: Model 1   (Common)         - 66 registers
  40070: Model 103  (Inverter 3ph)  - 50 registers
  40122: Model 120  (Nameplate)     - 26 registers
  40150: Model 123  (Controls)      - 24 registers
  40176: Model 124  (Storage)       - 24 registers
  40202: Model 160  (MPPT)          - 28 registers
  40232: Model 802  (Battery)       - 62 registers
  40296: End marker (0xFFFF, 0x0000)

All scale factor registers are populated. SunSpec "not implemented" sentinels
are used for optional fields. Realistic values for a 10kW three-phase PV
inverter with battery.

Security assessment test values:
  - No security models (3-9) present --> triggers "no security models" finding
  - Model 103 operating_state = 4 (MPPT) + ac_power = 9850W --> active production
  - Model 120 WRtg = 10000W --> rated capacity (10 kW, not high-capacity)
  - Model 123 Conn = 1 (writable) --> connect/disconnect finding
  - Model 124 StorCtl_Mod = 0 (writable) --> storage control finding
  - Model 802 SetOp = 1 (writable) --> battery disconnect finding
  - Model 802 loc_rem_ctl = 0 (REMOTE) --> remote control finding

Port: 5502 (configurable via SUNSPEC_PORT env var)
"""

import asyncio
import logging
import os
import struct

from pymodbus.server import ModbusTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

try:
    from pymodbus.datastore import ModbusSlaveContext
except ImportError:
    from pymodbus.datastore import ModbusDeviceContext as ModbusSlaveContext

try:
    from pymodbus.device import ModbusDeviceIdentification
except ImportError:
    from pymodbus import ModbusDeviceIdentification

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# SunSpec constants
SUNSPEC_MARKER_HI = 0x5375  # "Su"
SUNSPEC_MARKER_LO = 0x6E53  # "nS"
SUNSPEC_END_MODEL = 0xFFFF
NOT_IMPL_U16 = 0xFFFF
NOT_IMPL_I16 = 0x8000
NOT_IMPL_U32 = [0xFFFF, 0xFFFF]
NOT_IMPL_I32 = [0x8000, 0x0000]
NOT_IMPL_F32 = [0x7FC0, 0x0000]  # NaN


def f32(value):
    """Encode float32 as two big-endian u16 registers."""
    packed = struct.pack(">f", value)
    return [(packed[0] << 8) | packed[1], (packed[2] << 8) | packed[3]]


def u32(value):
    """Encode uint32 as two big-endian u16 registers."""
    return [(value >> 16) & 0xFFFF, value & 0xFFFF]


def i16(value):
    """Encode signed int16 as u16 register."""
    return value & 0xFFFF


def sunspec_string(text, num_registers):
    """Encode a string into SunSpec registers (big-endian, null-padded)."""
    encoded = text.encode("ascii")[: num_registers * 2]
    encoded = encoded.ljust(num_registers * 2, b"\x00")
    regs = []
    for i in range(0, len(encoded), 2):
        regs.append((encoded[i] << 8) | encoded[i + 1])
    return regs


def build_sunspec_registers():
    """Build the complete SunSpec register map for a mock PV inverter."""

    # We need registers from 40000 onwards. Allocate enough space.
    # Last model ends at ~40296, plus end marker = ~40298
    size = 300
    regs = [0] * size

    off = 0  # offset from 40000

    # =========================================================================
    # SunS Marker (2 registers)
    # =========================================================================
    regs[off] = SUNSPEC_MARKER_HI
    regs[off + 1] = SUNSPEC_MARKER_LO
    off += 2

    # =========================================================================
    # Model 1: Common (66 data registers)
    # =========================================================================
    regs[off] = 1  # Model ID
    regs[off + 1] = 66  # Model Length
    base = off + 2

    # Mn (Manufacturer): 16 registers (32 chars)
    regs[base : base + 16] = sunspec_string("OIDA Test Devices", 16)
    # Md (Model): 16 registers
    regs[base + 16 : base + 32] = sunspec_string("SunSpec-Mock-10kW", 16)
    # Opt (Options): 8 registers
    regs[base + 32 : base + 40] = sunspec_string("3ph+bat", 8)
    # Vr (Version): 8 registers
    regs[base + 40 : base + 48] = sunspec_string("1.2.3", 8)
    # SN (Serial Number): 16 registers
    regs[base + 48 : base + 64] = sunspec_string("OIDA-SS-2025-001", 16)
    # DA (Device Address): 1 register
    regs[base + 64] = 1
    # Pad: 1 register
    regs[base + 65] = NOT_IMPL_U16

    off += 2 + 66  # = 70

    # =========================================================================
    # Model 103: Three-Phase Inverter Integer (50 data registers)
    # =========================================================================
    regs[off] = 103
    regs[off + 1] = 50
    base = off + 2

    # Scale factors: A_SF=-2, V_SF=-1, W_SF=0, Hz_SF=-2, VA_SF=0,
    #                VAr_SF=0, PF_SF=-2, WH_SF=0, DCA_SF=-2, DCV_SF=-1,
    #                DCW_SF=0, Tmp_SF=-1
    a_sf = i16(-2)
    v_sf = i16(-1)
    w_sf = i16(0)
    hz_sf = i16(-2)

    # AC Current: 14.50A total, 4.85A per phase (with SF=-2: raw=1450)
    regs[base + 0] = 1450  # A (total)
    regs[base + 1] = 485  # AphA
    regs[base + 2] = 483  # AphB
    regs[base + 3] = 482  # AphC
    regs[base + 4] = a_sf  # A_SF = -2

    # AC Voltage: 400V line-line, 230V line-neutral (SF=-1: raw=4000/2300)
    regs[base + 5] = 4000  # PPVphAB
    regs[base + 6] = 3998  # PPVphBC
    regs[base + 7] = 4002  # PPVphCA
    regs[base + 8] = 2301  # PhVphA
    regs[base + 9] = 2299  # PhVphB
    regs[base + 10] = 2303  # PhVphC
    regs[base + 11] = v_sf  # V_SF = -1

    # AC Power: 9850W (SF=0)
    regs[base + 12] = i16(9850)  # W
    regs[base + 13] = w_sf  # W_SF = 0

    # Frequency: 50.01Hz (SF=-2: raw=5001)
    regs[base + 14] = 5001  # Hz
    regs[base + 15] = hz_sf  # Hz_SF = -2

    # Apparent Power: 10000 VA
    regs[base + 16] = i16(10000)  # VA
    regs[base + 17] = i16(0)  # VA_SF = 0

    # Reactive Power: 1200 var
    regs[base + 18] = i16(1200)  # VAr
    regs[base + 19] = i16(0)  # VAr_SF = 0

    # Power Factor: 98.50% (SF=-2: raw=9850)
    regs[base + 20] = i16(9850)  # PF
    regs[base + 21] = i16(-2)  # PF_SF = -2

    # Lifetime Energy: 12345678 Wh (acc32, SF=0)
    regs[base + 22 : base + 24] = u32(12345678)  # WH
    regs[base + 24] = i16(0)  # WH_SF = 0

    # DC Current: 28.50A (SF=-2: raw=2850)
    regs[base + 25] = 2850  # DCA
    regs[base + 26] = i16(-2)  # DCA_SF = -2

    # DC Voltage: 360.5V (SF=-1: raw=3605)
    regs[base + 27] = 3605  # DCV
    regs[base + 28] = i16(-1)  # DCV_SF = -1

    # DC Power: 10260W
    regs[base + 29] = i16(10260)  # DCW
    regs[base + 30] = i16(0)  # DCW_SF = 0

    # Temperatures: Cabinet=42.5C, Heatsink=55.3C (SF=-1)
    regs[base + 31] = i16(425)  # TmpCab
    regs[base + 32] = i16(553)  # TmpSnk
    regs[base + 33] = NOT_IMPL_I16  # TmpTrns (not implemented)
    regs[base + 34] = NOT_IMPL_I16  # TmpOt (not implemented)
    regs[base + 35] = i16(-1)  # Tmp_SF = -1

    # Operating State: 4 = MPPT (tracking)
    regs[base + 36] = 4  # St = MPPT
    regs[base + 37] = 0  # StVnd

    # Event flags: no events
    regs[base + 38 : base + 40] = u32(0)  # Evt1
    regs[base + 40 : base + 42] = u32(0)  # Evt2
    regs[base + 42 : base + 44] = u32(0)  # EvtVnd1
    regs[base + 44 : base + 46] = u32(0)  # EvtVnd2
    regs[base + 46 : base + 48] = u32(0)  # EvtVnd3
    regs[base + 48 : base + 50] = u32(0)  # EvtVnd4

    off += 2 + 50  # = 122

    # =========================================================================
    # Model 120: Nameplate Ratings (26 data registers)
    # =========================================================================
    regs[off] = 120
    regs[off + 1] = 26
    base = off + 2

    regs[base + 0] = 4  # DERTyp = PV
    regs[base + 1] = 10000  # WRtg = 10000W
    regs[base + 2] = i16(0)  # WRtg_SF = 0
    regs[base + 3] = 11000  # VARtg = 11000VA
    regs[base + 4] = i16(0)  # VARtg_SF = 0
    regs[base + 5] = i16(5000)  # VArRtgQ1 = 5000var
    regs[base + 6] = i16(5000)  # VArRtgQ2
    regs[base + 7] = i16(-5000)  # VArRtgQ3
    regs[base + 8] = i16(-5000)  # VArRtgQ4
    regs[base + 9] = i16(0)  # VArRtg_SF = 0
    regs[base + 10] = 160  # ARtg = 16.0A (SF=-1)
    regs[base + 11] = i16(-1)  # ARtg_SF = -1
    regs[base + 12] = i16(900)  # PFRtgQ1 = 0.900 (SF=-3)
    regs[base + 13] = i16(900)  # PFRtgQ2
    regs[base + 14] = i16(-900)  # PFRtgQ3
    regs[base + 15] = i16(-900)  # PFRtgQ4
    regs[base + 16] = i16(-3)  # PFRtg_SF = -3
    regs[base + 17] = NOT_IMPL_U16  # WHRtg (not implemented - no storage rated here)
    regs[base + 18] = i16(0)  # WHRtg_SF
    regs[base + 19] = NOT_IMPL_U16  # AhrRtg
    regs[base + 20] = i16(0)  # AhrRtg_SF
    regs[base + 21] = NOT_IMPL_U16  # MaxChaRte
    regs[base + 22] = i16(0)  # MaxChaRte_SF
    regs[base + 23] = NOT_IMPL_U16  # MaxDisChaRte
    regs[base + 24] = i16(0)  # MaxDisChaRte_SF
    regs[base + 25] = 0  # Pad

    off += 2 + 26  # = 150

    # =========================================================================
    # Model 123: Immediate Controls (24 data registers)
    # =========================================================================
    regs[off] = 123
    regs[off + 1] = 24
    base = off + 2

    regs[base + 0] = NOT_IMPL_U16  # Conn_WinTms
    regs[base + 1] = NOT_IMPL_U16  # Conn_RvrtTms
    regs[base + 2] = 1  # Conn = CONNECT
    regs[base + 3] = 1000  # WMaxLimPct = 100.0% (SF=-1)
    regs[base + 4] = NOT_IMPL_U16  # WMaxLimPct_WinTms
    regs[base + 5] = NOT_IMPL_U16  # WMaxLimPct_RvrtTms
    regs[base + 6] = NOT_IMPL_U16  # WMaxLimPct_RmpTms
    regs[base + 7] = 0  # WMaxLim_Ena = DISABLED
    regs[base + 8] = i16(1000)  # OutPFSet = 1.000 (SF=-3)
    regs[base + 9] = NOT_IMPL_U16  # OutPFSet_WinTms
    regs[base + 10] = NOT_IMPL_U16  # OutPFSet_RvrtTms
    regs[base + 11] = NOT_IMPL_U16  # OutPFSet_RmpTms
    regs[base + 12] = 0  # OutPFSet_Ena = DISABLED
    regs[base + 13] = NOT_IMPL_I16  # VArWMaxPct
    regs[base + 14] = NOT_IMPL_I16  # VArMaxPct
    regs[base + 15] = NOT_IMPL_I16  # VArAvalPct
    regs[base + 16] = NOT_IMPL_U16  # VArPct_WinTms
    regs[base + 17] = NOT_IMPL_U16  # VArPct_RvrtTms
    regs[base + 18] = NOT_IMPL_U16  # VArPct_RmpTms
    regs[base + 19] = NOT_IMPL_U16  # VArPct_Mod
    regs[base + 20] = 0  # VArPct_Ena = DISABLED
    regs[base + 21] = i16(-1)  # WMaxLimPct_SF = -1
    regs[base + 22] = i16(-3)  # OutPFSet_SF = -3
    regs[base + 23] = i16(-1)  # VArPct_SF = -1

    off += 2 + 24  # = 176

    # =========================================================================
    # Model 124: Basic Storage Control (24 data registers)
    # =========================================================================
    regs[off] = 124
    regs[off + 1] = 24
    base = off + 2

    regs[base + 0] = 5000  # WChaMax = 5000W (SF=0)
    regs[base + 1] = 100  # WChaGra = 100% WChaMax/sec (SF=0)
    regs[base + 2] = 100  # WDisChaGra = 100%
    regs[base + 3] = 0  # StorCtl_Mod = none
    regs[base + 4] = 5500  # VAChaMax = 5500VA (SF=0)
    regs[base + 5] = 100  # MinRsvPct = 10.0% (SF=-1)
    regs[base + 6] = 750  # ChaState = 75.0% (SF=-1)
    regs[base + 7] = 90  # StorAval = 90Ah (SF=0)
    regs[base + 8] = 518  # InBatV = 51.8V (SF=-1)
    regs[base + 9] = 4  # ChaSt = CHARGING
    regs[base + 10] = i16(0)  # OutWRte = 0%
    regs[base + 11] = i16(50)  # InWRte = 50% (SF=0)
    regs[base + 12] = NOT_IMPL_U16  # InOutWRte_WinTms
    regs[base + 13] = NOT_IMPL_U16  # InOutWRte_RvrtTms
    regs[base + 14] = NOT_IMPL_U16  # InOutWRte_RmpTms
    regs[base + 15] = 0  # ChaGriSet = PV
    regs[base + 16] = i16(0)  # WChaMax_SF = 0
    regs[base + 17] = i16(0)  # WChaDisChaGra_SF = 0
    regs[base + 18] = i16(0)  # VAChaMax_SF = 0
    regs[base + 19] = i16(-1)  # MinRsvPct_SF = -1
    regs[base + 20] = i16(-1)  # ChaState_SF = -1
    regs[base + 21] = i16(0)  # StorAval_SF = 0
    regs[base + 22] = i16(-1)  # InBatV_SF = -1
    regs[base + 23] = i16(0)  # InOutWRte_SF = 0

    off += 2 + 24  # = 202

    # =========================================================================
    # Model 160: MPPT (28 data registers = 8 fixed + 1*20 repeating)
    # =========================================================================
    regs[off] = 160
    regs[off + 1] = 28
    base = off + 2

    # Fixed block (8 registers)
    regs[base + 0] = i16(-2)  # DCA_SF
    regs[base + 1] = i16(-1)  # DCV_SF
    regs[base + 2] = i16(0)  # DCW_SF
    regs[base + 3] = i16(0)  # DCWH_SF
    regs[base + 4 : base + 6] = u32(0)  # Evt (no events)
    regs[base + 6] = 1  # N = 1 module
    regs[base + 7] = 28  # TmsPer (timestamp period)
    # Module 1 repeating block (20 registers: ID + IDStr[8] + DCA + DCV + DCW
    #   + DCWH[2] + Tms[2] + Tmp + DCSt + DCEvt[2])
    regs[base + 8] = 1  # ID = 1
    regs[base + 9 : base + 17] = sunspec_string("String 1", 8)  # IDStr
    regs[base + 17] = 2850  # DCA (28.50A, SF=-2)
    regs[base + 18] = 3605  # DCV (360.5V, SF=-1)
    regs[base + 19] = 10260  # DCW (10260W, SF=0)
    regs[base + 20 : base + 22] = u32(12345678)  # DCWH (lifetime Wh)
    regs[base + 22 : base + 24] = u32(0)  # Tms
    regs[base + 24] = i16(425)  # Tmp (42.5C, SF=-1)
    regs[base + 25] = 4  # DCSt = MPPT
    regs[base + 26 : base + 28] = u32(0)  # DCEvt

    off += 2 + 28  # = 232

    # =========================================================================
    # Model 802: Battery Base Model (62 data registers)
    # Per SunSpec Model 802 spec - maps to IEC 61850 DBAT logical node
    # Security-critical: SetOp, SetInvState are writable; loc_rem_ctl=0 (REMOTE)
    # =========================================================================
    regs[off] = 802
    regs[off + 1] = 62
    base = off + 2

    # Scale factors (at end of model, addresses 52-63 relative to data start):
    # AHRtg_SF=-1, WHRtg_SF=0, WChaDisChaMax_SF=0, DisChaRte_SF=-1,
    # SoC_SF=-1, DoD_SF=-1, SoH_SF=-1, V_SF=-1, CellV_SF=-3,
    # A_SF=-2, AMax_SF=-2, W_SF=0

    # Ratings
    regs[base + 0] = 1000  # AHRtg = 100.0Ah (SF=-1)
    regs[base + 1] = 5000  # WHRtg = 5000Wh (SF=0)
    regs[base + 2] = 5000  # WChaRteMax = 5000W (SF=0)
    regs[base + 3] = 5000  # WDisChaRteMax = 5000W (SF=0)
    regs[base + 4] = 50  # DisChaRte = 5.0 %WHRtg/day (SF=-1)
    regs[base + 5] = 1000  # SoCMax = 100.0% (SF=-1)
    regs[base + 6] = 100  # SoCMin = 10.0% (SF=-1)

    # Operational reserve setpoints (writable)
    regs[base + 7] = 950  # SocRsvMax = 95.0% (SF=-1)
    regs[base + 8] = 150  # SoCRsvMin = 15.0% (SF=-1)

    # State of charge / health
    regs[base + 9] = 750  # SoC = 75.0% (SF=-1)
    regs[base + 10] = 250  # DoD = 25.0% (SF=-1)
    regs[base + 11] = 980  # SoH = 98.0% (SF=-1)

    # Cycle count (u32)
    regs[base + 12 : base + 14] = u32(1250)  # NCyc = 1250 cycles

    # Charge status
    regs[base + 14] = 4  # ChaSt = CHARGING

    # Control mode: 0 = REMOTE (security-critical!)
    regs[base + 15] = 0  # LocRemCtl = REMOTE

    # Heartbeats
    regs[base + 16] = 42  # Hb (battery heartbeat)
    regs[base + 17] = 0  # CtrlHb (controller heartbeat, writable)
    regs[base + 18] = 0  # AlmRst (alarm reset, writable)

    # Battery type and state
    regs[base + 19] = 4  # Typ = LITHIUM_ION
    regs[base + 20] = 3  # State = CONNECTED
    regs[base + 21] = 0  # StateVnd

    # Warranty date (u32, days since 2000-01-01)
    regs[base + 22 : base + 24] = u32(10950)  # WarrDt ~= 2030-01-01

    # Events (u32 each)
    regs[base + 24 : base + 26] = u32(0)  # Evt1
    regs[base + 26 : base + 28] = u32(0)  # Evt2
    regs[base + 28 : base + 30] = u32(0)  # EvtVnd1
    regs[base + 30 : base + 32] = u32(0)  # EvtVnd2

    # Voltages (SF=-1)
    regs[base + 32] = 518  # V = 51.8V DC bus
    regs[base + 33] = 525  # VMax = 52.5V
    regs[base + 34] = 510  # VMin = 51.0V

    # Cell voltages (SF=-3)
    regs[base + 35] = 3650  # CellVMax = 3.650V
    regs[base + 36] = 1  # CellVMaxStr
    regs[base + 37] = 3  # CellVMaxMod
    regs[base + 38] = 3200  # CellVMin = 3.200V
    regs[base + 39] = 1  # CellVMinStr
    regs[base + 40] = 7  # CellVMinMod
    regs[base + 41] = 3420  # CellVAvg = 3.420V

    # Currents (A_SF=-2, AMax_SF=-2)
    regs[base + 42] = i16(2500)  # A = 25.00A (charging, SF=-2)
    regs[base + 43] = 5000  # AChaMax = 50.00A
    regs[base + 44] = 5000  # ADisChaMax = 50.00A

    # Power (W_SF=0)
    regs[base + 45] = i16(1295)  # W = 1295W charging

    # Inverter request
    regs[base + 46] = 0  # ReqInvState = NO_REQUEST
    regs[base + 47] = i16(0)  # ReqW = 0W

    # Writable commands (security-critical!)
    regs[base + 48] = 1  # SetOp = CONNECT (writable)
    regs[base + 49] = 3  # SetInvState = INVERTER_STARTED (writable)

    # Scale factors (addresses 52-63 in JSON map, data offsets 50-61)
    regs[base + 50] = i16(-1)  # AHRtg_SF
    regs[base + 51] = i16(0)  # WHRtg_SF
    regs[base + 52] = i16(0)  # WChaDisChaMax_SF
    regs[base + 53] = i16(-1)  # DisChaRte_SF
    regs[base + 54] = i16(-1)  # SoC_SF
    regs[base + 55] = i16(-1)  # DoD_SF
    regs[base + 56] = i16(-1)  # SoH_SF
    regs[base + 57] = i16(-1)  # V_SF
    regs[base + 58] = i16(-3)  # CellV_SF
    regs[base + 59] = i16(-2)  # A_SF
    regs[base + 60] = i16(-2)  # AMax_SF
    regs[base + 61] = i16(0)  # W_SF

    off += 2 + 62  # = 296

    # =========================================================================
    # End Marker (at 40296)
    # =========================================================================
    regs[off] = SUNSPEC_END_MODEL  # 0xFFFF
    regs[off + 1] = 0x0000

    return regs


def create_device_identity():
    """Create Modbus device identification for MEI (FC43)."""
    identity = ModbusDeviceIdentification()
    identity[0x00] = "OIDA Test Devices"
    identity[0x01] = "SUNSPEC-MOCK-10KW"
    identity[0x02] = "1.0.0"
    identity[0x03] = "https://github.com/oida"
    identity[0x04] = "SunSpec Mock 10kW PV Inverter"
    identity[0x05] = "OIDA-SUNSPEC-SIM"
    identity[0x06] = "SunSpec Test Server"
    return identity


def create_context():
    """Create the Modbus server context with SunSpec registers."""
    sunspec_regs = build_sunspec_registers()

    # SunSpec data lives in holding registers starting at address 40000.
    # ModbusSlaveContext adds +1 to addresses by default (PLC convention),
    # so we start at 40001 so client reads at protocol address 40000 hit index 0.
    hr = ModbusSequentialDataBlock(40001, sunspec_regs)

    # Minimal other register types
    co = ModbusSequentialDataBlock(1, [0] * 10)
    di = ModbusSequentialDataBlock(1, [0] * 10)
    ir = ModbusSequentialDataBlock(1, [0] * 10)

    slave = ModbusSlaveContext(di=di, co=co, hr=hr, ir=ir)

    try:
        return ModbusServerContext(slaves=slave, single=True)
    except TypeError:
        return ModbusServerContext(devices=slave, single=True)


async def main():
    port = int(os.environ.get("SUNSPEC_PORT", "5502"))

    log.info(f"Starting SunSpec Mock Server on port {port}")
    log.info("  SunSpec model chain at base address 40000:")
    log.info("    40000: SunS marker")
    log.info("    40002: Model   1 (Common)          len=66")
    log.info("    40070: Model 103 (Inverter 3ph)     len=50")
    log.info("    40122: Model 120 (Nameplate)        len=26")
    log.info("    40150: Model 123 (Immediate Ctrl)   len=24")
    log.info("    40176: Model 124 (Storage)          len=24")
    log.info("    40202: Model 160 (MPPT)             len=28")
    log.info("    40232: Model 802 (Battery)          len=62")
    log.info("    40296: End marker (0xFFFF)")
    log.info("  Device: 10kW three-phase PV inverter + 5kW/5kWh Li-ion battery")
    log.info("  Security: no auth, REMOTE control, writable Conn/SetOp/StorCtl_Mod")

    context = create_context()

    server = ModbusTcpServer(
        context=context,
        identity=create_device_identity(),
        address=("0.0.0.0", port),
    )

    log.info("Server ready - waiting for connections...")
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
