# ADS (Beckhoff TwinCAT ADS) - Reference Library Source Code

## Library 1: pyads (stlehmann/pyads)

- **URL**: https://github.com/stlehmann/pyads
- **Language**: Python (with C extension for TcAdsDll/adslib)
- **Stars**: 310
- **License**: MIT
- **Description**: Python wrapper for TwinCAT ADS. Contains a pure-Python test server that implements AMS/ADS wire protocol parsing from scratch -- this is the most useful component for fuzzer development.

### Key Source Files

| File | Purpose |
|------|---------|
| `src/pyads/testserver/testserver.py` | AMS/TCP server: socket I/O, frame reception, `construct_request()` / `construct_response()` with struct.unpack/pack |
| `src/pyads/testserver/handler.py` | `AmsPacket`, `AmsHeader`, `AmsTcpHeader`, `AmsResponseData` namedtuple definitions |
| `src/pyads/testserver/basic_handler.py` | ADS command dispatch: Read, Write, ReadState, ReadDeviceInfo, ReadWrite, AddDeviceNotification |
| `src/pyads/testserver/advanced_handler.py` | Extended command handling with symbol resolution |
| `src/pyads/constants.py` | All ADS command IDs, port numbers, state flags, index groups |
| `src/pyads/structs.py` | ctypes struct definitions: `SAmsNetId`, `SAmsAddr`, `SAdsNotificationAttrib`, `SAdsNotificationHeader`, `SAdsSymbolEntry`, `SAdsSumRequest` |
| `src/pyads/pyads_ex.py` | Low-level ADS operations using ctypes bindings to C library |

### Notable Parsing Patterns

**AMS/TCP frame deserialization** - Raw byte slicing with fixed offsets, no length validation:

```python
# testserver.py - construct_request()
@staticmethod
def construct_request(request_bytes: bytes) -> AmsPacket:
    data = request_bytes

    tcp_header = AmsTcpHeader(data[2:6])

    ams_header = AmsHeader(
        data[6:12],      # target net ID (6 bytes)
        data[12:14],     # target port (2 bytes)
        data[14:20],     # source net ID (6 bytes)
        data[20:22],     # source port (2 bytes)
        data[22:24],     # command ID (2 bytes)
        data[24:26],     # state flags (2 bytes)
        data[26:30],     # data length (4 bytes)
        data[30:34],     # error code (4 bytes)
        data[34:38],     # invoke ID (4 bytes)
        data[38:],       # payload data (variable)
    )

    return AmsPacket(tcp_header, ams_header)
```

**Fuzzer observation**: No bounds checking on input length. If `request_bytes` is shorter than 38 bytes, the slicing silently produces truncated fields rather than raising errors. The `data[38:]` slice for payload data does not validate against the `data_length` field at bytes 26-30.

**ADS command dispatch** - struct.unpack at fixed offsets in payload:

```python
# basic_handler.py
command_id = struct.unpack("<H", request.ams_header.command_id)[0]

if command_id == constants.ADSCOMMAND_READ:
    # index_group at data[0:4], index_offset at data[4:8], read_length at data[8:12]
    response_length = struct.unpack("<I", request.ams_header.data[8:12])[0]

elif command_id == constants.ADSCOMMAND_READWRITE:
    index_group = struct.unpack("<I", request.ams_header.data[:4])[0]
    response_length = struct.unpack("<I", request.ams_header.data[8:12])[0]
    write_length = struct.unpack("<I", request.ams_header.data[12:16])[0]
```

**Fuzzer observation**: The ReadWrite command parses `response_length` and `write_length` from the payload but the test server does not validate that `write_length` matches the actual remaining payload bytes. A fuzzer should send ReadWrite requests with mismatched length fields.

**Packet structure definitions** (ctypes structs with `_pack_ = 1`):

```python
# structs.py
class SAmsNetId(Structure):
    _pack_ = 1
    _fields_ = [("b", c_ubyte * 6)]

class SAmsAddr(Structure):
    _pack_ = 1
    _fields_ = [("netId", SAmsNetId), ("port", c_uint16)]

class SAdsNotificationHeader(Structure):
    _pack_ = 1
    _fields_ = [
        ("hNotification", c_uint32),
        ("nTimeStamp", c_uint64),
        ("cbSampleSize", c_uint32),
        ("data", c_ubyte * 1)  # variable-length
    ]
```

**ADS constants** - command IDs and index groups:

```python
# constants.py
ADSCOMMAND_INVALID          = 0x00
ADSCOMMAND_READDEVICEINFO   = 0x01
ADSCOMMAND_READ             = 0x02
ADSCOMMAND_WRITE            = 0x03
ADSCOMMAND_READSTATE        = 0x04
ADSCOMMAND_WRITECTRL        = 0x05
ADSCOMMAND_ADDDEVICENOTE    = 0x06
ADSCOMMAND_DELDEVICENOTE    = 0x07
ADSCOMMAND_DEVICENOTE       = 0x08
ADSCOMMAND_READWRITE        = 0x09

# System index groups
ADSIGRP_SYMTAB              = 0xF000
ADSIGRP_SYMVAL              = 0xF002
ADSIGRP_SYM_VALBYNAME       = 0xF004

# Memory areas
INDEXGROUP_MEMORYBYTE        = 0x4020
INDEXGROUP_MEMORYBIT         = 0x4021
INDEXGROUP_DATA              = 0x4040
```

### Known CVEs / Security Bugs in This Library

No CVEs filed against pyads itself. The library is a client/test-server -- vulnerabilities exist in the TwinCAT runtime it communicates with (CVE-2019-5636, CVE-2019-5637). The test server's lack of input validation makes it useful as a crash oracle for fuzzer development.

---

## Library 2: Beckhoff/ADS (Official C++ Library)

- **URL**: https://github.com/Beckhoff/ADS
- **Language**: C++ (C++14)
- **Stars**: 605
- **License**: MIT
- **Description**: Official Beckhoff ADS communication library. Implements AMS/TCP client with full protocol framing. This is the reference C++ implementation for AMS/ADS wire format.

### Key Source Files

| File | Purpose |
|------|---------|
| `AdsLib/AmsHeader.h` | Core wire format structs: `AmsTcpHeader`, `AoEHeader`, `AoERequestHeader`, `AoEReadWriteReqHeader`, `AoEResponseHeader` |
| `AdsLib/Frame.h` / `Frame.cpp` | Frame buffer management: prepend/remove operations, endian conversion, buffer bounds |
| `AdsLib/AmsConnection.h` | Frame reception pipeline: socket read, response dispatch, notification handling |
| `AdsLib/AdsLib.cpp` | UDP discovery: cookie validation, frame send/recv, route management |
| `AdsLib/AdsDevice.cpp` / `AdsDevice.h` | High-level ADS device operations: Read, Write, ReadState, ReadWrite |
| `AdsLib/standalone/AdsDef.h` | Protocol constants: AmsNetId struct, command IDs, port enums, index group defines, error codes, ADS state enum |
| `AdsLib/Sockets.cpp` / `Sockets.h` | TCP/UDP socket I/O with receive buffering |

### Notable Parsing Patterns

**AMS/TCP + AMS Header wire format** (`#pragma pack(push, 1)` for byte-aligned serialization):

```cpp
// AmsHeader.h
struct AmsTcpHeader {
    uint16_t reserved;     // 2 bytes, should be 0
    uint32_t leLength;     // 4 bytes, little-endian total AMS data length
};

struct AoEHeader {
    // Command ID constants
    static const uint16_t AMS_REQUEST  = 0x0004;
    static const uint16_t AMS_RESPONSE = 0x0005;
    static const uint16_t READ         = 0x0002;
    static const uint16_t WRITE        = 0x0003;
    static const uint16_t READ_WRITE   = 0x0009;
    static const uint16_t READ_STATE   = 0x0004;
    static const uint16_t WRITE_CONTROL = 0x0005;
    static const uint16_t ADD_DEVICE_NOTIFICATION = 0x0006;
    static const uint16_t DEL_DEVICE_NOTIFICATION = 0x0007;
    static const uint16_t DEVICE_NOTIFICATION = 0x0008;

    AmsNetId targetNetId;      // 6 bytes
    uint16_t leTargetPort;     // 2 bytes LE
    AmsNetId sourceNetId;      // 6 bytes
    uint16_t leSourcePort;     // 2 bytes LE
    uint16_t leCmdId;          // 2 bytes LE
    uint16_t leStateFlags;     // 2 bytes LE
    uint32_t leLength;         // 4 bytes LE - data length
    uint32_t leErrorCode;      // 4 bytes LE
    uint32_t leInvokeId;       // 4 bytes LE
};
// Total AoEHeader = 32 bytes
```

**Request/Response structures** - tightly packed with no padding:

```cpp
// AmsHeader.h
struct AoERequestHeader {
    uint32_t leGroup;      // Index Group
    uint32_t leOffset;     // Index Offset
    uint32_t leLength;     // Read length
};

struct AoEReadWriteReqHeader : AoERequestHeader {
    uint32_t leWriteLength;  // Additional write length field
};
// ReadWrite header = 16 bytes (4+4+4+4)
```

**Fuzzer observation**: The `AoEReadWriteReqHeader` has both `leLength` (read length) and `leWriteLength` (write length). A server must allocate a response buffer of `leLength` bytes and consume `leWriteLength` bytes of write data from the request payload. Mismatched values between these fields and the actual AMS data length (in `AoEHeader.leLength`) are the primary buffer overflow vector.

**Frame buffer management** - template-based extraction with endian conversion:

```cpp
// Frame.h
template <typename T> T pop()          // Extract typed value from front
template <typename T> T pop_letoh()    // Extract with little-endian conversion
template <class T> T remove()          // Remove header struct from frame
Frame &prepend(const void *const data, const size_t size);

// Frame.cpp - removal advances read pointer
Frame& Frame::remove(size_t numBytes) {
    m_Pos = std::min<uint8_t*>(m_Pos + numBytes, m_Data.get() + m_Size);
    return *this;
}
```

**Protocol definitions** - core types and constants:

```cpp
// standalone/AdsDef.h
struct AmsNetId {
    uint8_t b[6];
    AmsNetId(uint32_t ipv4Addr = 0);
    AmsNetId(const std::string &addr);
    operator bool() const;
};

struct AmsAddr {
    AmsNetId netId;
    uint16_t port;
};

// Command IDs
#define ADSSRVID_READDEVICEINFO  0x01
#define ADSSRVID_READ            0x02
#define ADSSRVID_WRITE           0x03
#define ADSSRVID_READSTATE       0x04
#define ADSSRVID_WRITECTRL       0x05
#define ADSSRVID_READWRITE       0x09

// System Index Groups
#define ADSIGRP_SYMTAB           0xF000
#define ADSIGRP_SYMNAME          0xF001
#define ADSIGRP_SYM_VALBYNAME    0xF004
#define ADSIGRP_SUMUP_READ       0xF080
#define ADSIGRP_SUMUP_WRITE      0xF081
#define ADSIGRP_DEVICE_DATA      0xF100

// ADS State enum
enum ADSSTATE : uint16_t {
    ADSSTATE_INVALID   = 0,
    ADSSTATE_IDLE      = 1,
    ADSSTATE_RUN       = 5,
    ADSSTATE_STOP      = 6,
    ADSSTATE_ERROR     = 11,
    ADSSTATE_MAXSTATES
};
```

**UDP discovery frame format** - cookie-based validation:

```cpp
// AdsLib.cpp - SendRecv()
static const uint32_t UDP_COOKIE = 0x71146603;
f.prepend(htole(UDP_COOKIE));
// ...
s.write(f);
f.reset();
s.read(f, &timeout);
// Response validation checks cookie match
```

### Known CVEs / Security Bugs in This Library

No CVEs filed against the Beckhoff/ADS open-source library itself. The library is primarily a client implementation. Server-side vulnerabilities exist in TwinCAT runtime:

- **CVE-2019-5636**: Malformed UDP packet to port 48899 removes routing table and shuts down ADS Discovery Service (CVSS 7.5)
- **CVE-2019-5637**: Divide-by-zero crash from malformed UDP when PROFINET driver is active

### GitHub Issues of Note

- No public security issues filed against the open-source library
- The library uses `#pragma pack(push, 1)` throughout, ensuring no struct padding issues on different platforms

---

## Library 3: adshli (simonwaid/adshli)

- **URL**: https://github.com/simonwaid/adshli
- **Language**: Python (pure Python)
- **Stars**: 20
- **License**: MIT
- **Description**: Pure Python AMS/ADS client with its own protocol implementation. Independent implementation useful for cross-referencing parsing behavior against pyads.

### Key Details

This is a smaller, independent Python ADS implementation. It provides an alternative parsing implementation for comparing behavior differences that a fuzzer could exploit. The key value for fuzzer development is having two independent parsers for the same protocol -- bugs in one that the other handles correctly reveal edge cases.

---

## Wire Format Summary (for fuzzer development)

### AMS/TCP Frame Layout (Total: 6 + 32 + variable)

```
Offset  Size   Field
------  ----   -----
0       2      Reserved (should be 0x0000)
2       4      AMS Length (LE uint32) -- total bytes following this field
--- AMS Header (32 bytes) ---
6       6      Target AMS NetID
12      2      Target AMS Port (LE uint16)
14      6      Source AMS NetID
20      2      Source AMS Port (LE uint16)
22      2      Command ID (LE uint16) -- 0x01-0x09
24      2      State Flags (LE uint16) -- bit 0: request(0)/response(1), bit 2: ADS command
26      4      Data Length (LE uint32) -- bytes of command-specific payload
30      4      Error Code (LE uint32)
34      4      Invoke ID (LE uint32)
--- Command Data (variable) ---
38      var    Command-specific payload
```

### ReadWrite Command Payload (cmd 0x09)

```
Offset  Size   Field
------  ----   -----
0       4      Index Group (LE uint32)
4       4      Index Offset (LE uint32)
8       4      Read Length (LE uint32) -- response buffer allocation
12      4      Write Length (LE uint32) -- bytes of write data following
16      var    Write Data
```

### Primary Fuzzing Targets

1. **AMS Length vs Data Length mismatch**: AMS Length (offset 2) should equal Data Length (offset 26) + 32 (header size). Sending mismatched values.
2. **ReadWrite read/write length mismatch**: Read Length + Write Length vs actual payload size.
3. **Command ID out of range**: Values > 0x09 or 0x00.
4. **Index Group system services (0xF000+)**: Especially 0xF080/0xF081 (SumUp Read/Write) which contain sub-request arrays with their own length fields.
5. **AMS NetID 0.0.0.0.0.0 or 255.255.255.255.255.255**: Broadcast/null addressing.
