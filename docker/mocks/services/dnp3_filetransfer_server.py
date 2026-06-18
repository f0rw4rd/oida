#!/usr/bin/env python3
"""
DNP3 Mock Outstation with File Transfer Support (FreyrSCADA dnp3protocol)

Uses the FreyrSCADA dnp3protocol C library (via ctypes) to provide a DNP3
outstation that supports Group 70 file transfer operations.  The pydnp3-stepfunc
library does NOT support outstation-side file transfer, so this server uses an
entirely different backend.

The library handles file transfer internally against a local directory tree.
Test files are created at startup in /app/files/ so a master can list, read,
and write them.

Environment Variables:
    DNP3_PORT              - Bind port (default: 20000)
    DNP3_SLAVE_ADDR        - Outstation/slave address (default: 1)
    DNP3_MASTER_ADDR       - Expected master address (default: 2)
    DNP3_BI_COUNT          - Binary input count (default: 5)
    DNP3_AI_COUNT          - Analog input count (default: 5)
    DNP3_BO_COUNT          - Binary output count (default: 5)
    DNP3_AO_COUNT          - Analog output count (default: 5)
    DNP3_UPDATE_INTERVAL   - Value update interval in seconds (default: 5)
    DNP3_FILE_DIR          - Directory exposed for file transfer (default: /app/files)
    DNP3_VIEW_TRAFFIC      - Show hex TX/RX debug (default: 1)

NOTE: dnp3protocol trial edition limits total points to 100.
"""

import ctypes
import logging
import math
import os
import signal
import sys
import time

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dnp3-filetransfer")

# ---------------------------------------------------------------------------
# Import FreyrSCADA dnp3protocol
# ---------------------------------------------------------------------------

try:
    from dnp3protocol.dnp3api import (
        dnp3_lib,
        DNP3_VERSION,
        sDNP3Parameters,
        sDNP3ConfigurationParameters,
        sDNP3Object,
        sDNP3DataAttributeID,
        sDNP3DataAttributeData,
        sDNP3ErrorCode,
        sDNP3ErrorValue,
        DNP3WriteCallback,
        DNP3ControlSelectCallback,
        DNP3ControlOperateCallback,
        DNP3DebugMessageCallback,
        DNP3ColdRestartCallback,
        DNP3WarmRestartCallback,
        DNP3ReadCallback,
        DNP3UpdateCallback,
        DNP3UpdateIINCallback,
        DNP3ClientPollStatusCallback,
        DNP3ClientStatusCallback,
        DNP3DeviceAttributeCallback,
    )
    from dnp3protocol.tgtcommon import (
        eApplicationFlag,
        eDataTypes,
    )
    from dnp3protocol.tgttypes import eDataSizes
    from dnp3protocol.dnp3types import (
        eDNP3GroupID,
        eDNP3ClassID,
        eDNP3ControlModelConfig,
        eDNP3QualityFlags,
        eCommunicationMode,
        eDebugOptionsFlag,
        eDefaultStaticVariationBinaryInput,
        eDefaultStaticVariationDoubleBitBinaryInput,
        eDefaultStaticVariationBinaryOutput,
        eDefaultStaticVariationCounterInput,
        eDefaultStaticVariationFrozenCounterInput,
        eDefaultStaticVariationAnalogInput,
        eDefaultStaticVariationFrozenAnalogInput,
        eDefaultStaticVariationAnalogInputDeadBand,
        eDefaultStaticVariationAnalogOutput,
        eDefaultEventVariationBinaryInput,
        eDefaultEventVariationDoubleBitBinaryInput,
        eDefaultEventVariationCounterInput,
        eDefaultEventVariationAnalogInput,
        eDefaultEventVariationFrozenCounterInput,
        eDefaultEventVariationFrozenAnalogInput,
        eDefaultEventVariationBinaryOutput,
        eDefaultEventVariationAnalogOutput,
        eAnalogInputDeadbandMethod,
        eAnalogStorageType,
        eUpdateClassID,
        eCommandObjectVariation,
    )
except ImportError as e:
    log.error("Failed to import dnp3protocol: %s", e)
    log.error("Install with: pip install dnp3protocol")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def errorcodestring(errorcode):
    s = sDNP3ErrorCode()
    s.iErrorCode = errorcode
    dnp3_lib.DNP3ErrorCodeString(s)
    return s.LongDes.decode("utf-8")


def errorvaluestring(errorvalue):
    s = sDNP3ErrorValue()
    s.iErrorValue = errorvalue
    dnp3_lib.DNP3ErrorValueString(s)
    return s.LongDes.decode("utf-8")


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


@DNP3ColdRestartCallback
def cb_cold_restart(u16ObjectId, ptWriteID, ptErrorValue):
    log.info("COLD RESTART requested (object %d)", u16ObjectId)
    return 0


@DNP3WarmRestartCallback
def cb_warm_restart(u16ObjectId, ptWriteID, ptErrorValue):
    log.info("WARM RESTART requested (object %d)", u16ObjectId)
    return 0


@DNP3WriteCallback
def cb_write(u16ObjectId, eFunctionID, ptWriteID, ptWriteValue, ptWriteParams, ptErrorValue):
    log.info("WRITE callback (object %d, func %d)", u16ObjectId, eFunctionID)
    if ptWriteValue.contents.sTimeStamp.u16Year != 0:
        log.info(
            "  Time sync: %04d-%02d-%02d %02d:%02d:%02d",
            ptWriteValue.contents.sTimeStamp.u16Year,
            ptWriteValue.contents.sTimeStamp.u8Month,
            ptWriteValue.contents.sTimeStamp.u8Day,
            ptWriteValue.contents.sTimeStamp.u8Hour,
            ptWriteValue.contents.sTimeStamp.u8Minute,
            ptWriteValue.contents.sTimeStamp.u8Seconds,
        )
    return 0


@DNP3ControlSelectCallback
def cb_select(u16ObjectId, psSelectID, psSelectValue, psSelectParams, ptErrorValue):
    log.info(
        "SELECT: object=%d group=%d index=%d",
        u16ObjectId,
        psSelectID.contents.eGroupID,
        psSelectID.contents.u16IndexNumber,
    )
    return 0


@DNP3ControlOperateCallback
def cb_operate(u16ObjectId, psOperateID, psOperateValue, psOperateParams, ptErrorValue):
    log.info(
        "OPERATE: object=%d group=%d index=%d",
        u16ObjectId,
        psOperateID.contents.eGroupID,
        psOperateID.contents.u16IndexNumber,
    )
    return 0


@DNP3DebugMessageCallback
def cb_debug(u16ObjectId, ptDebugData, ptErrorValue):
    if (
        ptDebugData.contents.u32DebugOptions & eDebugOptionsFlag.DEBUG_OPTION_TX
    ) == eDebugOptionsFlag.DEBUG_OPTION_TX:
        tx_bytes = " ".join(
            f"{ptDebugData.contents.au8TxData[i]:02x}"
            for i in range(ptDebugData.contents.u16TxCount)
        )
        log.debug("TX %d bytes: %s", ptDebugData.contents.u16TxCount, tx_bytes)

    if (
        ptDebugData.contents.u32DebugOptions & eDebugOptionsFlag.DEBUG_OPTION_RX
    ) == eDebugOptionsFlag.DEBUG_OPTION_RX:
        rx_bytes = " ".join(
            f"{ptDebugData.contents.au8RxData[i]:02x}"
            for i in range(ptDebugData.contents.u16RxCount)
        )
        log.debug("RX %d bytes: %s", ptDebugData.contents.u16RxCount, rx_bytes)

    if (
        ptDebugData.contents.u32DebugOptions & eDebugOptionsFlag.DEBUG_OPTION_ERROR
    ) == eDebugOptionsFlag.DEBUG_OPTION_ERROR:
        log.warning(
            "Protocol error: %s (code=%d, value=%d)",
            ptDebugData.contents.au8ErrorMessage,
            ptDebugData.contents.i16ErrorCode,
            ptDebugData.contents.tErrorValue,
        )

    return 0


# ---------------------------------------------------------------------------
# Test file creation
# ---------------------------------------------------------------------------


def create_test_files(file_dir: str):
    """Create sample files for file transfer testing."""
    os.makedirs(file_dir, exist_ok=True)

    files = {
        "config.txt": (
            "# DNP3 Outstation Configuration\n"
            "slave_address=1\n"
            "master_address=2\n"
            "application_timeout=20000\n"
            "link_timeout=10000\n"
            "enable_unsolicited=false\n"
        ),
        "firmware_info.txt": (
            "Firmware: OIDA-DNP3-FT v1.0.0\n"
            "Build: 2025-01-15T10:30:00Z\n"
            "Hardware: Rev-B\n"
            "Serial: OIDA-FT-001\n"
        ),
        "event_log.csv": (
            "timestamp,group,index,value,quality\n"
            "2025-01-15T10:00:00,BI,0,1,ONLINE\n"
            "2025-01-15T10:00:01,AI,0,100.5,ONLINE\n"
            "2025-01-15T10:00:02,BI,1,0,ONLINE\n"
            "2025-01-15T10:00:03,AI,1,200.3,ONLINE\n"
            "2025-01-15T10:00:04,CT,0,42,ONLINE\n"
        ),
        "subdir/nested_file.txt": ("This is a nested file for directory listing tests.\n"),
    }

    for name, content in files.items():
        path = os.path.join(file_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        log.info("  Created test file: %s (%d bytes)", name, len(content))

    # Generate a large binary file (~64 KB) to test multi-block transfers
    large_path = os.path.join(file_dir, "historical_data.bin")
    with open(large_path, "wb") as f:
        # Header
        f.write(b"DNP3-HIST-V1\x00\x00\x00\x00")
        # 1000 simulated data records (64 bytes each = ~64 KB)
        import struct as _struct

        for i in range(1000):
            ts = 1705300000 + i * 60  # timestamps 1 min apart
            record = _struct.pack(
                "<I H H f f I 40s",
                ts,  # uint32 timestamp
                i % 10,  # uint16 group
                i % 50,  # uint16 index
                100.0 + i * 0.1,  # float32 value
                0.0,  # float32 quality metric
                1,  # uint32 flags (ONLINE)
                b"\x00" * 40,  # padding
            )
            f.write(record)
    log.info("  Created test file: historical_data.bin (%d bytes)", os.path.getsize(large_path))


# ---------------------------------------------------------------------------
# Data point update
# ---------------------------------------------------------------------------


def update_points(server, cfg, cycle):
    """Periodically update data point values."""
    i16ErrorCode = ctypes.c_short()
    tErrorValue = ctypes.c_short()

    psDAID = sDNP3DataAttributeID()
    psNewValue = sDNP3DataAttributeData()

    psDAID.u16SlaveAddress = cfg["slave_addr"]

    # Update analog inputs with sine wave pattern
    for i in range(cfg["ai_count"]):
        psDAID.eGroupID = eDNP3GroupID.ANALOG_INPUT
        psDAID.u16IndexNumber = i

        f32value = ctypes.c_float(50.0 + i * 10.0 + 5.0 * math.sin(cycle * 0.1 + i))
        psNewValue.eDataSize = eDataSizes.FLOAT32_SIZE
        psNewValue.eDataType = eDataTypes.FLOAT32_DATA
        psNewValue.tQuality = eDNP3QualityFlags.ONLINE
        psNewValue.pvData = ctypes.cast(ctypes.pointer(f32value), ctypes.c_void_p)

        now = time.localtime()
        psNewValue.sTimeStamp.u8Day = now.tm_mday
        psNewValue.sTimeStamp.u8Month = now.tm_mon
        psNewValue.sTimeStamp.u16Year = now.tm_year
        psNewValue.sTimeStamp.u8Hour = now.tm_hour
        psNewValue.sTimeStamp.u8Minute = now.tm_min
        psNewValue.sTimeStamp.u8Seconds = now.tm_sec
        psNewValue.sTimeStamp.u16MilliSeconds = 0
        psNewValue.bTimeInvalid = False

        err = dnp3_lib.DNP3Update(
            server,
            ctypes.byref(psDAID),
            ctypes.byref(psNewValue),
            1,
            eUpdateClassID.UPDATE_DEFAULT_EVENT,
            ctypes.byref(tErrorValue),
        )
        if err != 0:
            log.warning("DNP3Update AI[%d] failed: %d", i, err)

    # Toggle binary inputs
    for i in range(cfg["bi_count"]):
        psDAID.eGroupID = eDNP3GroupID.BINARY_INPUT
        psDAID.u16IndexNumber = i

        val = 1 if ((cycle + i) % 4) < 2 else 0
        u8value = ctypes.c_ubyte(val)
        psNewValue.eDataSize = eDataSizes.SINGLE_POINT_SIZE
        psNewValue.eDataType = eDataTypes.SINGLE_POINT_DATA
        psNewValue.tQuality = eDNP3QualityFlags.ONLINE
        psNewValue.pvData = ctypes.cast(ctypes.pointer(u8value), ctypes.c_void_p)
        psNewValue.bTimeInvalid = False

        err = dnp3_lib.DNP3Update(
            server,
            ctypes.byref(psDAID),
            ctypes.byref(psNewValue),
            1,
            eUpdateClassID.UPDATE_DEFAULT_EVENT,
            ctypes.byref(tErrorValue),
        )
        if err != 0:
            log.warning("DNP3Update BI[%d] failed: %d", i, err)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    # Parse configuration
    port = int(os.environ.get("DNP3_PORT", "20000"))
    slave_addr = int(os.environ.get("DNP3_SLAVE_ADDR", "1"))
    master_addr = int(os.environ.get("DNP3_MASTER_ADDR", "2"))
    bi_count = int(os.environ.get("DNP3_BI_COUNT", "5"))
    ai_count = int(os.environ.get("DNP3_AI_COUNT", "5"))
    bo_count = int(os.environ.get("DNP3_BO_COUNT", "5"))
    ao_count = int(os.environ.get("DNP3_AO_COUNT", "5"))
    update_interval = float(os.environ.get("DNP3_UPDATE_INTERVAL", "5"))
    file_dir = os.environ.get("DNP3_FILE_DIR", "/app/files")
    view_traffic = os.environ.get("DNP3_VIEW_TRAFFIC", "1") in ("1", "true", "yes")

    cfg = {
        "port": port,
        "slave_addr": slave_addr,
        "master_addr": master_addr,
        "bi_count": bi_count,
        "ai_count": ai_count,
        "bo_count": bo_count,
        "ao_count": ao_count,
        "update_interval": update_interval,
        "file_dir": file_dir,
    }

    total_points = bi_count + ai_count + bo_count + ao_count
    if total_points > 100:
        log.warning("Total points (%d) exceeds trial limit of 100!", total_points)

    log.info("=" * 70)
    log.info("DNP3 File Transfer Outstation (FreyrSCADA dnp3protocol)")
    log.info("=" * 70)

    # Check library version
    lib_version = dnp3_lib.DNP3GetLibraryVersion().decode("utf-8")
    lib_build = dnp3_lib.DNP3GetLibraryBuildTime().decode("utf-8")
    lib_license = dnp3_lib.DNP3GetLibraryLicenseInfo().decode("utf-8")
    log.info("  Library version: %s", lib_version)
    log.info("  Library build:   %s", lib_build)
    log.info("  License:         %s", lib_license)
    log.info("  Bind:            0.0.0.0:%d", port)
    log.info("  Slave address:   %d", slave_addr)
    log.info("  Master address:  %d", master_addr)
    log.info(
        "  Points:          %d BI, %d AI, %d BO, %d AO (total: %d)",
        bi_count,
        ai_count,
        bo_count,
        ao_count,
        total_points,
    )
    log.info("  File transfer:   ENABLED (dir: %s)", file_dir)
    log.info("  Update interval: %.1f s", update_interval)
    log.info("-" * 70)
    log.info("SUPPORTED FEATURES:")
    log.info("  - File transfer (G70):   YES (FreyrSCADA dnp3protocol)")
    log.info("  - Integrity poll:        YES (Class 0/1/2/3)")
    log.info("  - Time sync:             YES")
    log.info("  - Cold/Warm restart:     YES")
    log.info("  - Control operations:    YES (Select/Operate)")
    log.info("=" * 70)
    sys.stdout.flush()

    # Create test files
    log.info("Creating test files in %s ...", file_dir)
    create_test_files(file_dir)

    # Change to file directory so the library serves files from there
    os.chdir(file_dir)

    # -----------------------------------------------------------------------
    # Create DNP3 server object
    # -----------------------------------------------------------------------

    i16ErrorCode = ctypes.c_short()
    tErrorValue = ctypes.c_short()

    sParameters = sDNP3Parameters()
    sParameters.eAppFlag = eApplicationFlag.APP_SERVER
    sParameters.ptReadCallback = ctypes.cast(None, DNP3ReadCallback)
    sParameters.ptWriteCallback = DNP3WriteCallback(cb_write)
    sParameters.ptUpdateCallback = ctypes.cast(None, DNP3UpdateCallback)
    sParameters.ptSelectCallback = DNP3ControlSelectCallback(cb_select)
    sParameters.ptOperateCallback = DNP3ControlOperateCallback(cb_operate)
    sParameters.ptDebugCallback = DNP3DebugMessageCallback(cb_debug)
    sParameters.ptUpdateIINCallback = ctypes.cast(None, DNP3UpdateIINCallback)
    sParameters.ptClientPollStatusCallback = ctypes.cast(None, DNP3ClientPollStatusCallback)
    sParameters.ptClientStatusCallback = ctypes.cast(None, DNP3ClientStatusCallback)
    sParameters.ptColdRestartCallback = DNP3ColdRestartCallback(cb_cold_restart)
    sParameters.ptWarmRestartCallback = DNP3WarmRestartCallback(cb_warm_restart)
    sParameters.ptDeviceAttrCallback = ctypes.cast(None, DNP3DeviceAttributeCallback)
    sParameters.u32Options = 0
    sParameters.u16ObjectId = 1

    server = dnp3_lib.DNP3Create(
        ctypes.byref(sParameters),
        ctypes.byref(i16ErrorCode),
        ctypes.byref(tErrorValue),
    )
    if i16ErrorCode.value != 0:
        log.error(
            "DNP3Create failed: %d - %s, %d - %s",
            i16ErrorCode.value,
            errorcodestring(i16ErrorCode),
            tErrorValue.value,
            errorvaluestring(tErrorValue),
        )
        sys.exit(1)
    log.info("DNP3Create: success")

    # -----------------------------------------------------------------------
    # Configure server
    # -----------------------------------------------------------------------

    sDNP3Config = sDNP3ConfigurationParameters()

    # TCP settings
    sDNP3Config.sDNP3ServerSet.sServerCommunicationSet.eCommMode = eCommunicationMode.TCP_IP_MODE
    sDNP3Config.sDNP3ServerSet.sServerCommunicationSet.sEthernetCommsSet.sEthernetportSet.ai8FromIPAddress = "0.0.0.0".encode(
        "utf-8"
    )
    sDNP3Config.sDNP3ServerSet.sServerCommunicationSet.sEthernetCommsSet.sEthernetportSet.u16PortNumber = port

    # Protocol settings
    proto = sDNP3Config.sDNP3ServerSet.sServerProtSet
    proto.u16SlaveAddress = slave_addr
    proto.u16MasterAddress = master_addr
    proto.u32LinkLayerTimeout = 10000
    proto.u32ApplicationLayerTimeout = 20000
    proto.u32TimeSyncIntervalSeconds = 90

    # Static variations
    proto.sStaticVariation.eDeStVarBI = eDefaultStaticVariationBinaryInput.BI_WITH_FLAGS
    proto.sStaticVariation.eDeStVarDBI = eDefaultStaticVariationDoubleBitBinaryInput.DBBI_WITH_FLAGS
    proto.sStaticVariation.eDeStVarBO = eDefaultStaticVariationBinaryOutput.BO_WITH_FLAGS
    proto.sStaticVariation.eDeStVarCI = eDefaultStaticVariationCounterInput.CI_32BIT_WITHFLAG
    proto.sStaticVariation.eDeStVarFzCI = (
        eDefaultStaticVariationFrozenCounterInput.FCI_32BIT_WITHFLAGANDTIME
    )
    proto.sStaticVariation.eDeStVarAI = (
        eDefaultStaticVariationAnalogInput.AI_SINGLEPREC_FLOATWITHFLAG
    )
    proto.sStaticVariation.eDeStVarFzAI = (
        eDefaultStaticVariationFrozenAnalogInput.FAI_SINGLEPRECFLOATWITHFLAG
    )
    proto.sStaticVariation.eDeStVarAID = (
        eDefaultStaticVariationAnalogInputDeadBand.DAI_SINGLEPRECFLOAT
    )
    proto.sStaticVariation.eDeStVarAO = (
        eDefaultStaticVariationAnalogOutput.AO_SINGLEPRECFLOAT_WITHFLAG
    )

    # Event variations
    proto.sEventVariation.eDeEvVarBI = eDefaultEventVariationBinaryInput.BIE_WITH_ABSOLUTETIME
    proto.sEventVariation.eDeEvVarDBI = (
        eDefaultEventVariationDoubleBitBinaryInput.DBBIE_WITH_ABSOLUTETIME
    )
    proto.sEventVariation.eDeEvVarCI = (
        eDefaultEventVariationCounterInput.CIE_32BIT_WITHFLAG_WITHTIME
    )
    proto.sEventVariation.eDeEvVarAI = eDefaultEventVariationAnalogInput.AIE_SINGLEPREC_WITHTIME
    proto.sEventVariation.eDeEvVarFzCI = (
        eDefaultEventVariationFrozenCounterInput.FCIE_32BIT_WITHFLAG_WITHTIME
    )
    proto.sEventVariation.eDeEvVarFzAI = (
        eDefaultEventVariationFrozenAnalogInput.FAIE_SINGLEPREC_WITHTIME
    )
    proto.sEventVariation.eDeEvVarBO = eDefaultEventVariationBinaryOutput.BOE_WITH_TIME
    proto.sEventVariation.eDeEvVarAO = eDefaultEventVariationAnalogOutput.AOE_SINGLEPREC_WITHTIME

    # Event buffer sizes
    proto.u16Class1EventBufferSize = 50
    proto.u8Class1EventBufferOverFlowPercentage = 90
    proto.u16Class2EventBufferSize = 50
    proto.u8Class2EventBufferOverFlowPercentage = 90
    proto.u16Class3EventBufferSize = 50
    proto.u8Class3EventBufferOverFlowPercentage = 90

    # Class 0 membership
    proto.bAddBIinClass0 = True
    proto.bAddDBIinClass0 = False
    proto.bAddBOinClass0 = True
    proto.bAddCIinClass0 = False
    proto.bAddFzCIinClass0 = False
    proto.bAddAIinClass0 = True
    proto.bAddFzAIinClass0 = False
    proto.bAddAIDinClass0 = False
    proto.bAddAOinClass0 = True
    proto.bAddOSinClass0 = False

    # Event class assignments
    proto.bAddBIEvent = True
    proto.bAddDBIEvent = False
    proto.bAddBOEvent = True
    proto.bAddCIEvent = False
    proto.bAddFzCIEvent = False
    proto.bAddAIEvent = True
    proto.bAddFzAIEvent = False
    proto.bAddAIDEvent = False
    proto.bAddAOEvent = True
    proto.bAddOSEvent = False
    proto.bAddVTOEvent = False

    # Feature flags
    proto.eAIDeadbandMethod = eAnalogInputDeadbandMethod.DEADBAND_FIXED
    proto.bFrozenAnalogInputSupport = False
    proto.bEnableSelfAddressSupport = True
    proto.bEnableFileTransferSupport = True  # <-- THE KEY FLAG
    proto.u8IntialdatabaseQualityFlag = eDNP3QualityFlags.ONLINE
    proto.bLocalMode = False
    proto.bUpdateCheckTimestamp = False

    # Unsolicited disabled
    proto.sUnsolicitedResponseSet.bEnableUnsolicited = False
    proto.sUnsolicitedResponseSet.bEnableResponsesonStartup = False
    proto.sUnsolicitedResponseSet.u32Timeout = 5000
    proto.sUnsolicitedResponseSet.u8Retries = 5
    proto.sUnsolicitedResponseSet.u16MaxNumberofEvents = 10

    # Timestamp
    now = time.localtime()
    proto.sTimeStamp.u8Day = now.tm_mday
    proto.sTimeStamp.u8Month = now.tm_mon
    proto.sTimeStamp.u16Year = now.tm_year
    proto.sTimeStamp.u8Hour = now.tm_hour
    proto.sTimeStamp.u8Minute = now.tm_min
    proto.sTimeStamp.u8Seconds = now.tm_sec
    proto.sTimeStamp.u16MilliSeconds = 0
    proto.sTimeStamp.u16MicroSeconds = 0
    proto.sTimeStamp.i8DSTTime = 0
    proto.sTimeStamp.u8DayoftheWeek = now.tm_wday
    proto.bTimeInvalid = False

    # Debug options
    if view_traffic:
        sDNP3Config.sDNP3ServerSet.sDebug.u32DebugOptions = (
            eDebugOptionsFlag.DEBUG_OPTION_RX | eDebugOptionsFlag.DEBUG_OPTION_TX
        )
    else:
        sDNP3Config.sDNP3ServerSet.sDebug.u32DebugOptions = 0

    # -----------------------------------------------------------------------
    # Define data objects (4 groups: BI, AI, BO, AO)
    # -----------------------------------------------------------------------

    num_objects = 4
    sDNP3Config.sDNP3ServerSet.u16NoofObject = num_objects
    sDNP3Config.sDNP3ServerSet.psDNP3Objects = (sDNP3Object * num_objects)()

    # Binary Input
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].ai8Name = f"binary input 0-{bi_count - 1}".encode(
        "utf-8"
    )
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eGroupID = eDNP3GroupID.BINARY_INPUT
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].u16NoofPoints = bi_count
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eClassID = eDNP3ClassID.CLASS_ONE
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[
        0
    ].eControlModel = eDNP3ControlModelConfig.INPUT_STATUS_ONLY
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].u32SBOTimeOut = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].f32AnalogInputDeadband = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eAnalogStoreType = eAnalogStorageType.AS_FLOAT

    # Analog Input
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].ai8Name = f"analog input 0-{ai_count - 1}".encode(
        "utf-8"
    )
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eGroupID = eDNP3GroupID.ANALOG_INPUT
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].u16NoofPoints = ai_count
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eClassID = eDNP3ClassID.CLASS_ONE
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[
        1
    ].eControlModel = eDNP3ControlModelConfig.INPUT_STATUS_ONLY
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].u32SBOTimeOut = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].f32AnalogInputDeadband = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eAnalogStoreType = eAnalogStorageType.AS_FLOAT

    # Binary Output
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].ai8Name = f"binary output 0-{bo_count - 1}".encode(
        "utf-8"
    )
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eGroupID = eDNP3GroupID.BINARY_OUTPUT
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].u16NoofPoints = bo_count
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eClassID = eDNP3ClassID.CLASS_ONE
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[
        2
    ].eControlModel = eDNP3ControlModelConfig.DIRECT_OPERATION
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].u32SBOTimeOut = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].f32AnalogInputDeadband = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eAnalogStoreType = eAnalogStorageType.AS_FLOAT

    # Analog Output
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].ai8Name = f"analog output 0-{ao_count - 1}".encode(
        "utf-8"
    )
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eGroupID = eDNP3GroupID.ANALOG_OUTPUTS
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].u16NoofPoints = ao_count
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eClassID = eDNP3ClassID.CLASS_ONE
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[
        3
    ].eControlModel = eDNP3ControlModelConfig.DIRECT_OPERATION
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].u32SBOTimeOut = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].f32AnalogInputDeadband = 0
    sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eAnalogStoreType = eAnalogStorageType.AS_FLOAT

    # -----------------------------------------------------------------------
    # Load configuration
    # -----------------------------------------------------------------------

    i16ErrorCode = dnp3_lib.DNP3LoadConfiguration(
        server, ctypes.byref(sDNP3Config), ctypes.byref(tErrorValue)
    )
    if i16ErrorCode != 0:
        log.error(
            "DNP3LoadConfiguration failed: %d - %s, %d - %s",
            i16ErrorCode,
            errorcodestring(i16ErrorCode),
            tErrorValue.value,
            errorvaluestring(tErrorValue),
        )
        dnp3_lib.DNP3Free(server, ctypes.byref(tErrorValue))
        sys.exit(1)
    log.info("DNP3LoadConfiguration: success")

    # -----------------------------------------------------------------------
    # Start server
    # -----------------------------------------------------------------------

    i16ErrorCode = dnp3_lib.DNP3Start(server, ctypes.byref(tErrorValue))
    if i16ErrorCode != 0:
        log.error(
            "DNP3Start failed: %d - %s, %d - %s",
            i16ErrorCode,
            errorcodestring(i16ErrorCode),
            tErrorValue.value,
            errorvaluestring(tErrorValue),
        )
        dnp3_lib.DNP3Free(server, ctypes.byref(tErrorValue))
        sys.exit(1)
    log.info("DNP3Start: success - listening on 0.0.0.0:%d", port)
    log.info("File transfer directory: %s", file_dir)
    sys.stdout.flush()

    # -----------------------------------------------------------------------
    # Main loop
    # -----------------------------------------------------------------------

    running = True

    def signal_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    cycle = 0
    try:
        while running:
            time.sleep(update_interval)
            cycle += 1
            update_points(server, cfg, cycle)
    except KeyboardInterrupt:
        pass

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    log.info("Shutting down...")
    dnp3_lib.DNP3Stop(server, ctypes.byref(tErrorValue))
    dnp3_lib.DNP3Free(server, ctypes.byref(tErrorValue))
    log.info("Server stopped")


if __name__ == "__main__":
    main()
