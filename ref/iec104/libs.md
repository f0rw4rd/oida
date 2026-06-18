# IEC 60870-5-104 -- Reference Library Source Code

Open-source libraries implementing IEC 104 APDU/ASDU parsing, useful as reference
for fuzzer development and vulnerability research.

---

## 1. lib60870 (C)

- **Repository**: https://github.com/mz-automation/lib60870
- **Language**: C (C99)
- **License**: GPLv3 / commercial dual-license
- **Maintainer**: MZ Automation GmbH (Michael Zillgith)
- **Version**: 2.4.0 (latest as of 2025)
- **Notes**: The canonical IEC 104 C implementation. Also used as the backend
  for the c104 Python module (iec104-python). Same author as libiec61850.

### Key Source Files

| File | Purpose |
|------|---------|
| `lib60870-C/src/iec60870/cs104/cs104_frame.c` | APCI frame construction, 256-byte buffer, start byte 0x68 |
| `lib60870-C/src/iec60870/cs104/cs104_connection.c` | Connection state machine, `receiveMessage()`, I/S/U frame dispatch |
| `lib60870-C/src/iec60870/cs104/cs104_slave.c` | Server-side (slave) APDU handling |
| `lib60870-C/src/iec60870/cs101/cs101_asdu.c` | ASDU header parsing: TypeID, VSQ, COT, CA, IOA routing |
| `lib60870-C/src/iec60870/cs101/cs101_information_objects.c` | Per-type information object parsers (40+ types) |
| `lib60870-C/src/iec60870/apl/cpXXtime2a.c` | CP56Time2a / CP24Time2a timestamp parsing |
| `lib60870-C/src/inc/api/iec60870_common.h` | Structure definitions, constants, type ID enum |
| `lib60870-C/src/inc/internal/cs104_frame.h` | T104Frame struct (256-byte fixed buffer) |
| `lib60870-C/src/inc/internal/cs101_asdu_internal.h` | Internal ASDU struct layout |

### Notable Parsing Patterns

**APCI Frame buffer (cs104_frame.h)**:
```c
struct sT104Frame {
    FrameVFT virtualFunctionTable;
    uint8_t buffer[256];   /* Fixed 256-byte buffer -- max APDU is 255 bytes */
    int msgSize;
};
```
The 256-byte fixed buffer mirrors the protocol spec (start byte + length byte max 253 +
APCI overhead). Any length value > 253 that bypasses validation is an immediate
overflow target.

**Message reception (cs104_connection.c) -- three-stage read**:
1. Read start byte, validate 0x68
2. Read length byte (single byte, 0-255)
3. Read `length` bytes of remaining frame

The length byte is trusted to determine how many bytes to read from the socket.
No upper-bound clamping to 253 at this stage.

**ASDU header parsing (cs101_asdu.c)**:
```c
/* Header validation */
if (msgLength < asduHeaderLength)
    return NULL;

/* Payload capacity check */
if (self->payloadSize + self->asduHeaderLength + size <= 256)
```
The VSQ (Variable Structure Qualifier) byte contains the sequence bit (bit 7) and
element count (bits 0-6, max 127). The SQ bit changes how IOAs are parsed:
- SQ=0: each information object has its own 3-byte IOA
- SQ=1: only the first object has an IOA, subsequent objects are sequential

**Per-type information object parsing (cs101_information_objects.c)**:
```c
/* Consistent bounds-check pattern across all types */
int minSize = startIndex + typeSpecificSize;
if (!isSequence)
    minSize += parameters->sizeOfIOA;
if (minSize > msgSize)
    return NULL;
```
Each of the 40+ `*_getFromBuffer()` functions follows this pattern. The dispatch
from TypeID to specific parser is done in `CS101_ASDU_getElementEx()` via a switch
statement.

**Application Layer Parameters (iec60870_common.h)**:
```c
struct sCS101_AppLayerParameters {
    int sizeOfTypeId;      /* always 1 */
    int sizeOfVSQ;         /* always 1 */
    int sizeOfCOT;         /* 1 or 2 bytes */
    int originatorAddress;
    int sizeOfCA;          /* 1 or 2 bytes */
    int sizeOfIOA;         /* 1, 2, or 3 bytes */
    int maxSizeOfASDU;     /* max 249 (IEC 104) or 254 (IEC 101) */
};
```
Variable-width fields (COT, CA, IOA) configured at runtime. A fuzzer should test
all width combinations, not just the defaults.

**APCI Parameters**:
```c
struct sCS104_APCIParameters {
    int k;   /* max unacknowledged I-frames (default 12) */
    int w;   /* ack threshold (default 8) */
    int t0;  /* connection timeout (default 10s) */
    int t1;  /* send timeout (default 15s) */
    int t2;  /* ack timeout (default 10s) */
    int t3;  /* test frame interval (default 20s) */
};
```

### Known CVEs in This Library

No CVEs have been assigned specifically to lib60870 itself. However, the library
is used as the backend for c104 (iec104-python) and shares architectural patterns
with libiec61850 (same author), which has numerous CVEs. The fixed 256-byte
buffer in T104Frame is the primary concern -- if any code path bypasses the
length validation and writes into this buffer based on attacker-controlled length,
a stack/heap overflow results.

### Fuzzing Priorities

1. **Length byte**: values 0, 1-5 (too small), 253, 254, 255 (exceeds spec max)
2. **VSQ SQ bit + count**: SQ=1 with count=127, combined with undersized APDU
3. **TypeID dispatch**: undefined type IDs (0, 128-255) reaching the switch default
4. **IOA width mismatch**: send 2-byte IOAs when server expects 3-byte
5. **CP56Time2a**: malformed timestamps with invalid month/day/year values
6. **U-frame state confusion**: I-frames before STARTDT_ACT confirmation

---

## 2. Ebolon/iec104 (Python)

- **Repository**: https://github.com/Ebolon/iec104
- **Language**: Python
- **License**: MIT
- **Notes**: Pure Python IEC 104 client/server using Tornado for async I/O.
  Minimal implementation, easy to read and understand the protocol structure.
  Useful as a reference for understanding the wire format, less useful as a
  production-grade parser to fuzz against.

### Key Source Files

| File | Purpose |
|------|---------|
| `iec104/acpi.py` | APCI frame encoding/decoding (I/S/U frames) |
| `iec104/asdu.py` | ASDU parsing: TypeID, VSQ, COT, IOA, information objects |
| `iec104/types.py` | CP56Time2a timestamp parsing |
| `iec104/client.py` | Client connection and frame reception |
| `iec104/server.py` | Server-side connection handling |

### Notable Parsing Patterns

**APCI frame constants and parsing (acpi.py)**:
```python
TESTFR_CON = '\x83\x00\x00\x00'
TESTFR_ACT = '\x43\x00\x00\x00'
STOPDT_CON = '\x23\x00\x00\x00'
STOPDT_ACT = '\x13\x00\x00\x00'
STARTDT_CON = '\x0b\x00\x00\x00'
STARTDT_ACT = '\x07\x00\x00\x00'

def i_frame(ssn, rsn):
    return struct.pack('<1BHH', 0x64, ssn << 1, rsn << 1)

def s_frame(rsn):
    return struct.pack('<3BH', 0x64, 0x01, 0x00, rsn << 1)

def parse_i_frame(data):
    ssn, rsn = struct.unpack('<2H', data)
    return ssn >> 1, rsn >> 1

def parse_s_frame(data):
    rsn = struct.unpack_from('<2H', data)[1]
    return rsn >> 1
```
Note the U-frame constants encode the control function in the first byte's bits.
The I-frame sequence numbers are shifted left by 1 (bit 0 = 0 for I-format).

**ASDU parsing (asdu.py) -- metaclass-based type registry**:
```python
class InfoObjMeta(type):
    """Metaclass that auto-registers information object subclasses"""
    # Each subclass with a type_id gets registered in a dispatch dict

class ASDU:
    def __init__(self, data):
        self.type_id = data[0]        # Byte 0: Type identification
        sq = data[1] & 0x80           # Bit 7: Sequence flag
        self.count = data[1] & 0x7f   # Bits 0-6: Number of objects
        self.cot = data[2] & 0x3f     # Cause of transmission
        # ... address fields follow
```
The metaclass pattern auto-registers 50+ information object types. Each type
defines `type_id`, `name`, and `description`. Objects are dispatched by looking
up `type_id` in the registry.

**CP56Time2a parsing (types.py)**:
```python
def cp56time2a_to_time(buf):
    ms  = struct.unpack_from('<H', buf, 0)[0] & 0x3FF  # 10-bit ms
    min = buf[2] & 0x3F                                  # 6-bit minutes
    hr  = buf[3] & 0x1F                                  # 5-bit hours
    day = buf[4] & 0x1F                                  # 5-bit day
    mon = (buf[5] & 0x0F) - 1                            # 4-bit month (1-based)
    yr  = (buf[6] & 0x7F) + 2000                         # 7-bit year + 2000
    return datetime(yr, mon, day, hr, min, seconds=..., microseconds=...)
```
Bug note: the milliseconds field is only masked to 10 bits (max 1023) but IEC 104
spec allows 0-59999 (full 16-bit field). Also month is offset by -1 which will
produce month=0 (invalid) for January.

### Known CVEs in This Library

No CVEs assigned to Ebolon/iec104. This is a small pure-Python library without
widespread deployment in production ICS systems.

### Fuzzing Relevance

This library is primarily useful as a **reference implementation** for understanding
the IEC 104 wire format. Its parsing code is simple enough to serve as a template
for building fuzzer harnesses. It is not a realistic fuzz target itself (Python
managed memory prevents buffer overflows), but the patterns reveal what fields
a C/C++ parser would struggle with.

---

## 3. c104 / iec104-python (Python/C++)

- **Repository**: https://github.com/Fraunhofer-FIT-DIEN/iec104-python
- **Language**: C++ with Python bindings (pybind11)
- **License**: GPLv3
- **Maintainer**: Fraunhofer Institute for Applied Information Technology (FIT)
- **PyPI**: `pip install c104`
- **Notes**: Wraps lib60870-C v2 with C++ object-oriented facades and Python
  bindings. Adds TLS support via mbedtls. The C++ layer adds message validation,
  type dispatch, and connection management on top of lib60870's C parsing.

### Key Source Files

| File | Purpose |
|------|---------|
| `src/remote/message/IncomingMessage.cpp` | Message parsing facade, type dispatch, information object extraction |
| `src/remote/message/IncomingMessage.h` | IncomingMessage class: factory pattern, thread-safe iteration |
| `src/remote/message/PointMessage.cpp` | Point data message handling |
| `src/remote/Connection.cpp` | Connection management, frame reception |
| `src/remote/message/OutgoingMessage.cpp` | Outgoing message construction |
| `src/object/DataPoint.cpp` | Data point value storage and conversion |
| `src/types.h` | Type enumerations and constants |
| `src/enums.h` | IEC 104 enum definitions |

### Notable Parsing Patterns

**IncomingMessage type dispatch (IncomingMessage.cpp)**:
The `extractInformation()` method handles 40+ message type IDs through a switch
statement, converting lib60870 C structs into C++ shared_ptr objects
(SingleInfo, DoubleInfo, NormalizedInfo, etc.).

**Validation layer**:
- Rejects CP24Time-based messages (simplified time format)
- Rejects file transfer operations
- Validates cause of transmission per type ID
- Enforces sequence flag constraints

**Thread safety**:
Uses `GilAwareMutex` for position tracking during information object iteration,
preventing race conditions when Python callbacks access message data.

**Raw bytes reconstruction (IncomingMessage.cpp)**:
The `getRawBytes()` method reconstructs the complete frame including APCI headers
and payload, which is useful for protocol-level debugging.

### Known CVEs in This Library

No CVEs assigned specifically to iec104-python/c104. Since it wraps lib60870-C,
any vulnerabilities in lib60870 would propagate unless the C++ validation layer
catches them first. The additional validation (rejecting certain message types,
validating COT) does reduce the attack surface compared to raw lib60870.

### Fuzzing Relevance

The C++ wrapper adds validation that lib60870 alone doesn't perform. Fuzzing
should target both:
1. The lib60870-C layer directly (bypassing C++ validation)
2. The c104 Python module via network (testing the full stack including validation)

The validation gaps are the interesting targets: message types that pass through
without additional checks, and edge cases in the type dispatch where the C++
layer trusts lib60870's parsing output without re-validating lengths.
