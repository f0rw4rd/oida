# EtherNet/IP (CIP over Ethernet) - Reference Library Source Code

## Library 1: cpppo (pjkundert/cpppo)

- **URL**: https://github.com/pjkundert/cpppo
- **Language**: Python
- **Stars**: 382
- **License**: GPL-3.0
- **Default Branch**: master
- **Description**: Communications Protocol Python Parser and Originator for EtherNet/IP CIP. Implements both a CIP client and a simulated controller (server). The parser uses a state-machine/DFA approach that makes the parsing logic explicit and inspectable -- highly useful for understanding the protocol structure for fuzzer development.

### Key Source Files

| File | Purpose |
|------|---------|
| `server/enip/parser.py` | Core protocol parser: `enip_header`, `enip_machine`, `CIP`, `CPF`, `send_data`, `EPATH` classes implementing DFA-based parsing |
| `server/enip/client.py` | EtherNet/IP client: encapsulation frame construction, session management |
| `server/enip/device.py` | Simulated CIP device: object model, attribute handling, message router |
| `server/enip/logix.py` | Allen-Bradley Logix controller simulation: tag read/write, Forward Open |
| `server/enip/ab.py` | Allen-Bradley specific CIP extensions |
| `server/enip/main.py` | Server entry point |
| `server/enip/defaults.py` | Protocol defaults and constants |
| `server/enip/get_attribute.py` | CIP Get Attribute operations |
| `server/enip/pccc.py` | PCCC (legacy Allen-Bradley protocol over CIP) |
| `server/enip/hart.py` | HART over CIP |

### Notable Parsing Patterns

**EtherNet/IP Encapsulation Header** - DFA-based state machine parsing the 24-byte fixed header:

```python
# parser.py - enip_header class
class enip_header( dfa ):
    """Scans a complete EtherNet/IP encapsulation header"""
    def __init__( self, name=None, **kwds ):
        name = name or kwds.setdefault( 'context', 'header' )
        init = state( "empty", terminal=True )
        init[True] = cmnd = UINT( "command", context="command" )         # 2 bytes
        cmnd[True] = leng = UINT( "length", context="length" )           # 2 bytes
        leng[True] = sess = UDINT( "sess_hdl", context="session_handle" ) # 4 bytes
        sess[True] = stat = UDINT( "status", context="status" )           # 4 bytes
        stat[True] = ctxt = octets( "sndr_ctx", context="sender_context",
                                     repeat=8 )                           # 8 bytes
        ctxt[True] = UDINT( "options", context="options", terminal=True ) # 4 bytes
```

**Full EtherNet/IP message parsing** - header followed by length-delimited payload:

```python
# parser.py - enip_machine class
class enip_machine( dfa ):
    """Parses a complete EtherNet/IP message"""
    def __init__( self, name=None, **kwds ):
        name = name or kwds.setdefault( 'context', 'enip' )
        hedr = enip_header( 'header' )
        hedr[None] = octets( 'payload', repeat=".length", terminal=True )
        super( enip_machine, self ).__init__( name=name, initial=hedr, **kwds )
```

**Fuzzer observation**: The `repeat=".length"` directive reads exactly `length` bytes of payload. If `length` exceeds the available data on the socket, the parser will block waiting. If `length` is 0 but the command expects data, the parser succeeds with empty payload and the command handler must deal with it.

**CIP Command Dispatch** - predicate-based routing by command code:

```python
# parser.py - CIP class
class CIP( dfa ):
    COMMAND_PARSERS = {
        (0x0001,):       legacy,          # Legacy command
        (0x0004,):       list_services,   # ListServices
        (0x0063,):       list_identity,   # ListIdentity
        (0x0065,):       register,        # RegisterSession
        (0x006f, 0x0070): send_data,      # SendRRData / SendUnitData
    }

    def __init__( self, name=None, **kwds ):
        slct = octets_noop( 'sel_CIP' )
        for cmd, cls in self.COMMAND_PARSERS.items():
            slct[None] = decide(
                cls.__name__,
                state=cls( limit='...length', terminal=True ),
                predicate=lambda path=None, data=None, cmd=cmd,
                    **kwds: data[path+'..command'] in cmd,
            )
        super( CIP, self ).__init__( name=name, initial=slct, **kwds )
```

**Fuzzer observation**: Command codes not in the dispatch table (e.g., 0x0002, 0x0066, 0xFFFF) fall through without explicit error handling. The `limit='...length'` constrains sub-parsers to the declared length, but a length of 0 or a length exceeding the TCP segment is not validated at this level.

**CPF (Common Packet Format) Parsing** - item count + type_id/length pairs:

```python
# parser.py - CPF class
class CPF( dfa ):
    ITEM_PARSERS = {
        0x0001: legacy_CPF_0x0001,         # Legacy item
        0x00a1: connection_ID,             # Connected address item
        0x00b1: connection_data,           # Connected data item
        0x00b2: unconnected_send,          # Unconnected data item
        0x0100: communications_service,    # ListServices response
        0x000c: identity_object,           # ListIdentity response
    }

    def __init__( self, name=None, **kwds ):
        ityp = UINT( context='type_id' )
        ityp[True] = ilen = UINT( context='length' )
        ilen[None] = decide( 'empty',
            predicate=lambda path=None, data=None,
                **kwds: not data[path].length,
            state=octets_noop( 'done', terminal=True ))
        # ... dispatch by type_id
```

**SendRRData/SendUnitData** - interface handle + timeout + CPF:

```python
# parser.py - send_data class
class send_data( dfa ):
    def __init__( self, name=None, **kwds ):
        name = name or kwds.setdefault( 'context', self.__class__.__name__ )
        ifce = UDINT( context='interface' )             # 4 bytes
        ifce[True] = timo = UINT( context='timeout' )   # 2 bytes
        timo[True] = CPF( terminal=True )               # CPF items
        super( send_data, self ).__init__( name=name, initial=ifce, **kwds )
```

**EPATH Segment Parsing** - variable-length path with segment type dispatch:

```python
# parser.py - EPATH class
class EPATH( dfa ):
    SEGMENTS = {
        'symbolic':    0x91,    # Symbolic segment (string)
        'class':       0x20,    # Logical class ID
        'instance':    0x24,    # Logical instance ID
        'connection':  0x2c,    # Logical connection point
        'attribute':   0x30,    # Logical attribute ID
        'element':     0x28,    # Logical element (array index)
        'port':        0x00,    # Port segment (routing)
    }
```

**Fuzzer observation**: EPATH parsing is the most complex part of CIP. Each segment type has 8-bit, 16-bit, or 32-bit value variants. Symbolic segments include null-terminated strings with odd-length padding. Deeply nested paths or paths with mixed segment types stress the parser.

**Data type primitives** - struct-based type parsing:

```python
# parser.py
# Supported types: BOOL (1B), SINT/USINT (1B), INT/UINT (2B),
#                  DINT/UDINT (4B), LINT/ULINT (8B), REAL/LREAL (4B/8B)
class TYPE( octets_struct ):
    @classmethod
    def produce( cls, value ):
        return struct.pack( cls.struct_format, value )
```

### Known CVEs / Security Bugs in This Library

No CVEs filed against cpppo in NVD. The library is primarily used for testing and simulation. As a Python implementation, it is not vulnerable to buffer overflows, but logic bugs in the DFA parser transitions could cause hangs or incorrect parsing that a fuzzer would expose.

---

## Library 2: OpENer (EIPStackGroup/OpENer)

- **URL**: https://github.com/EIPStackGroup/OpENer
- **Language**: C
- **Stars**: 802
- **License**: BSD
- **Default Branch**: master
- **Description**: Open-source EtherNet/IP adapter stack for I/O devices, compliant with ODVA specification. This is the reference C implementation used in many industrial devices. Multiple CVEs have been found by fuzzing this stack, making it the highest-value target for EtherNet/IP fuzzer development.

### Key Source Files

| File | Purpose |
|------|---------|
| `source/src/enet_encap/encap.c` | Encapsulation layer: `CreateEncapsulationStructure()` header parsing, command dispatch (RegisterSession, SendRRData, etc.) |
| `source/src/enet_encap/encap.h` | `EncapsulationData` struct, command code enums, `ENCAPSULATION_HEADER_LENGTH` (24) |
| `source/src/enet_encap/cpf.c` | CPF parsing: item count extraction, address/data item parsing with boundary checks |
| `source/src/cip/cipconnectionmanager.c` | Forward Open / Large Forward Open: connection parameter parsing, EPATH routing, electronic key validation |
| `source/src/cip/cipconnectionobject.c` | `ConnectionObjectInitializeFromMessage()`: extracts connection IDs, timing params, network connection params from wire |
| `source/src/cip/cipepath.c` | EPATH segment parsing: segment type detection (0xE0 mask), logical segments (class/instance/attribute/connection point), data segments, network segments, extended logical |
| `source/src/cip/cipcommon.c` | CIP message router: service dispatch, attribute get/set |
| `source/src/cip/cipmessagerouter.c` | Message router: incoming CIP request dispatch to registered objects |
| `source/src/cip/cipstring.c` | CIP string type handling |
| `source/src/cip/cipelectronickey.c` | Electronic key segment parsing and validation |
| `source/src/opener_api.h` | Public API definitions |

### Notable Parsing Patterns

**Encapsulation Header Parsing** - sequential field extraction from raw buffer:

```c
// encap.c - CreateEncapsulationStructure()
int_fast32_t CreateEncapsulationStructure(
    const EipUint8 *receive_buffer,
    size_t receive_buffer_length,
    EncapsulationData *const encapsulation_data)
{
  encapsulation_data->communication_buffer_start = (EipUint8*) receive_buffer;
  encapsulation_data->command_code = GetUintFromMessage(&receive_buffer);    // 2 bytes
  encapsulation_data->data_length = GetUintFromMessage(&receive_buffer);     // 2 bytes
  encapsulation_data->session_handle = GetUdintFromMessage(&receive_buffer); // 4 bytes
  encapsulation_data->status = GetUdintFromMessage(&receive_buffer);         // 4 bytes

  memcpy(encapsulation_data->sender_context, receive_buffer, kSenderContextSize); // 8 bytes
  receive_buffer += kSenderContextSize;
  encapsulation_data->options = GetUdintFromMessage(&receive_buffer);        // 4 bytes
  encapsulation_data->current_communication_buffer_position =
      (EipUint8*) receive_buffer;

  return ( (int32_t)receive_buffer_length - ENCAPSULATION_HEADER_LENGTH -
           encapsulation_data->data_length );
}
```

**Fuzzer observation**: The return value is `receive_buffer_length - 24 - data_length`. If `data_length` > `receive_buffer_length - 24`, this returns negative (cast to int32_t). The caller checks `*number_of_remaining_bytes >= 0` but this is a signed comparison. A very large `data_length` (e.g., 0xFFFF) with a small buffer creates a large negative value.

**EncapsulationData struct**:

```c
// encap.h
typedef struct encapsulation_data {
  CipUint command_code;           // 2 bytes
  CipUint data_length;            // 2 bytes
  CipSessionHandle session_handle; // 4 bytes
  CipUdint status;                // 4 bytes
  CipOctet sender_context[8];    // 8 bytes
  CipUdint options;              // 4 bytes
  const EipUint8 *communication_buffer_start;
  const EipUint8 *current_communication_buffer_position;
} EncapsulationData;

#define ENCAPSULATION_HEADER_LENGTH 24

typedef enum {
  kEncapsulationProtocolSuccess           = 0x0000,
  kEncapsulationProtocolInvalidCommand    = 0x0001,
  kEncapsulationProtocolInsufficientMemory = 0x0002,
  kEncapsulationProtocolIncorrectData     = 0x0003,
  kEncapsulationProtocolInvalidSessionHandle = 0x0064,
  kEncapsulationProtocolInvalidLength     = 0x0065,
  kEncapsulationProtocolUnsupportedProtocol = 0x0069
} EncapsulationProtocolErrorCode;
```

**Command dispatch** - switch on command code after options validation:

```c
// encap.c - HandleReceivedExplictTcpData()
if(kEncapsulationHeaderOptionsFlag == encapsulation_data.options) {
  if(*number_of_remaining_bytes >= 0) {
    switch(encapsulation_data.command_code){
      case (kEncapsulationCommandNoOperation):
        return_value = kEipStatusOk;
        break;
      case (kEncapsulationCommandListServices):
        HandleReceivedListServicesCommand(&encapsulation_data, outgoing_message);
        break;
      case (kEncapsulationCommandRegisterSession):
        HandleReceivedRegisterSessionCommand(socket, &encapsulation_data,
                                              outgoing_message);
        break;
      case (kEncapsulationCommandSendRequestReplyData):
        return_value = HandleReceivedSendRequestResponseDataCommand(...);
        break;
      case (kEncapsulationCommandSendUnitData):
        return_value = HandleReceivedSendUnitDataCommand(...);
        break;
    }
  }
}
```

**CPF Item Parsing** - item count followed by type_id + length pairs:

```c
// cpf.c
CipUint item_count = GetUintFromMessage(&data);
common_packet_format_data->item_count = item_count;

// Address item (item_count >= 1)
if(common_packet_format_data->item_count >= 1U) {
  common_packet_format_data->address_item.type_id = GetUintFromMessage(&data);
  common_packet_format_data->address_item.length = GetUintFromMessage(&data);
  if(common_packet_format_data->address_item.length >= 4) {
    common_packet_format_data->address_item.data.connection_identifier =
      GetUdintFromMessage(&data);
  }
  if(common_packet_format_data->address_item.length == 8) {
    common_packet_format_data->address_item.data.sequence_number =
      GetUdintFromMessage(&data);
  }
}

// Data item (item_count >= 2)
if(common_packet_format_data->item_count >= 2) {
  common_packet_format_data->data_item.type_id = GetUintFromMessage(&data);
  common_packet_format_data->data_item.length = GetUintFromMessage(&data);
  common_packet_format_data->data_item.data = (EipUint8 *) data;
  if(data_length >= length_count + 4 +
      common_packet_format_data->data_item.length) {
    data += common_packet_format_data->data_item.length;
    length_count += (4 + common_packet_format_data->data_item.length);
  } else {
    return kEipStatusError;
  }
}
```

**Fuzzer observation**: The item_count field controls how many items are parsed, but the code only handles items at indices 0 and 1 explicitly. Item counts > 2 are partially handled via a loop for socket address items. CVE-2020-13556 was caused by a large item count overflowing a stack buffer. In production builds (no assert), any item_count value is accepted.

**Forward Open Request Parsing** - connection parameter extraction:

```c
// cipconnectionobject.c - ConnectionObjectInitializeFromMessage()
void ConnectionObjectInitializeFromMessage(
    const CipOctet **message,
    CipConnectionObject *const connection_object)
{
  CipByte priority_timetick = GetByteFromMessage(message);
  CipUsint timeout_ticks = GetUsintFromMessage(message);

  // Connection IDs (4 bytes each)
  ConnectionObjectSetCipConsumedConnectionID(connection_object,
      GetUdintFromMessage(message));
  ConnectionObjectSetCipProducedConnectionID(connection_object,
      GetUdintFromMessage(message));

  // Serial/vendor/originator
  ConnectionObjectSetConnectionSerialNumber(connection_object,
      GetUintFromMessage(message));
  ConnectionObjectSetOriginatorVendorId(connection_object,
      GetUintFromMessage(message));
  ConnectionObjectSetOriginatorSerialNumber(connection_object,
      GetUdintFromMessage(message));

  ConnectionObjectSetConnectionTimeoutMultiplier(connection_object,
      GetUsintFromMessage(message));

  (*message) += 3; /* 3 bytes reserved */

  // O-to-T requested packet interval (4 bytes)
  ConnectionObjectSetOToTRequestedPacketInterval(connection_object,
      GetUdintFromMessage(message));

  // Network connection parameters: 2 bytes (normal) or 4 bytes (large)
  if(connection_object->is_large_forward_open == true) {
    ConnectionObjectSetOToTNetworkConnectionParameters(connection_object,
        GetDwordFromMessage(message));
  } else {
    ConnectionObjectSetOToTNetworkConnectionParameters(connection_object,
        GetWordFromMessage(message));
  }

  // T-to-O requested packet interval
  ConnectionObjectSetTToORequestedPacketInterval(connection_object,
      GetUdintFromMessage(message));

  // T-to-O network connection parameters
  if(connection_object->is_large_forward_open == true) {
    ConnectionObjectSetTToONetworkConnectionParameters(connection_object,
        GetDwordFromMessage(message));
  } else {
    ConnectionObjectSetTToONetworkConnectionParameters(connection_object,
        GetWordFromMessage(message));
  }

  connection_object->transport_class_trigger = GetByteFromMessage(message);
}
```

**Fuzzer observation**: This function reads 30+ bytes sequentially from the message pointer without checking remaining buffer length. The `is_large_forward_open` flag changes the read size (2 vs 4 bytes for network params), so sending a normal Forward Open header size with `is_large_forward_open=true` causes a short read. CVE-2021-27478 was in this path -- incorrect conversion between numeric types in the connection path parsing.

**EPATH Segment Type Detection** - bitmask-based type classification:

```c
// cipepath.c
SegmentType GetPathSegmentType(const CipOctet *const cip_path) {
  const unsigned int kSegmentTypeMask = 0xE0;
  const unsigned int segment_type = *cip_path & kSegmentTypeMask;
  // Returns: kSegmentTypePortSegment (0x00),
  //          kSegmentTypeLogicalSegment (0x20),
  //          kSegmentTypeNetworkSegment (0x40),
  //          kSegmentTypeSymbolicSegment (0x60),
  //          kSegmentTypeDataSegment (0x80)
}

// Logical segment sub-type extraction
LogicalSegmentLogicalType GetPathLogicalSegmentLogicalType(
    const unsigned char *const cip_path) {
  const unsigned int kLogicalTypeMask = 0x1C;
  const unsigned int logical_type = (*cip_path) & kLogicalTypeMask;
  // Extracts bits 2-4: ClassId, InstanceId, MemberId,
  //                     ConnectionPoint, AttributeId, etc.
}

// Value size determination
LogicalSegmentLogicalFormat GetPathLogicalSegmentLogicalFormat(
    const unsigned char *const cip_path) {
  const unsigned int kLogicalFormatMask = 0x03;
  const unsigned int logical_format = (*cip_path) & kLogicalFormatMask;
  // Returns: EightBit (0), SixteenBit (1), ThirtyTwoBit (2)
}
```

**Logical Segment Value Extraction** - format-dependent with padding:

```c
// cipepath.c
CipDword CipEpathGetLogicalValue(const EipUint8 **message) {
  LogicalSegmentLogicalFormat logical_format =
    GetPathLogicalSegmentLogicalFormat(*message);
  (*message) += 1;  // Move past segment byte
  switch(logical_format) {
    case kLogicalSegmentLogicalFormatEightBit:
      data = GetByteFromMessage(message);   // 1 byte, no padding
      break;
    case kLogicalSegmentLogicalFormatSixteenBit:
      (*message) += 1;                      // Skip padding byte
      data = GetWordFromMessage(message);   // 2 bytes
      break;
    case kLogicalSegmentLogicalFormatThirtyTwoBit:
      (*message) += 1;                      // Skip padding byte
      data = GetDwordFromMessage(message);  // 4 bytes
      break;
  }
  return data;
}
```

**Fuzzer observation**: The padding byte skip for 16-bit and 32-bit formats means the total consumed bytes differ by segment format. A path that declares 8-bit format but is followed by data intended for 16-bit alignment will misparse subsequent segments. The format field (2 bits) value of 3 is undefined -- its handling depends on the default case (or lack thereof).

**Connection Path Parsing** - validates message boundaries:

```c
// cipconnectionmanager.c - ParseConnectionPath()
const EipUint8 *message = message_router_request->data;
const size_t connection_path_size = GetUsintFromMessage(&message);

// Boundary validation
if( ( header_length + remaining_path * sizeof(CipWord) ) <
    message_router_request->request_data_size ) {
  return kCipErrorTooMuchData;
}
if( ( header_length + remaining_path * sizeof(CipWord) ) >
    message_router_request->request_data_size ) {
  return kCipErrorNotEnoughData;
}
```

**Fuzzer observation**: `connection_path_size` is in 16-bit words, so actual byte count is `connection_path_size * 2`. The boundary check compares `header_length + path_words * sizeof(CipWord)` against `request_data_size`. An attacker can set `connection_path_size` to 0 (empty path) or to a value that makes the multiplication overflow.

### Known CVEs / Security Bugs

OpENer has multiple CVEs found by fuzzing (Claroty Team82, Talos):

**CVE-2020-13556** (CVSS 9.8): Out-of-bounds write in ENIP server. Large CPF item count causes stack buffer overflow. The code extracts `item_count` from the packet but only has fixed-size arrays for items. In release builds (no assert), the count is trusted, causing a stack-based buffer overflow.

**CVE-2021-27478** (CVSS 8.2): Incorrect conversion between numeric types in Forward Open CIP connection path parsing. The `remaining_path` variable and connection path size calculation have an integer type mismatch leading to incorrect boundary validation.

**CVE-2021-27482** (CVSS 7.5): Out-of-bounds read. No checks on bytes read from packet before processing. A crafted packet allows reading arbitrary memory.

**CVE-2021-27500** (CVSS 7.5): Reachable assertion. A crafted packet triggers an assert that crashes the process in debug builds and causes undefined behavior in release builds.

**CVE-2021-27498** (CVSS 7.5): Reachable assertion. Similar to CVE-2021-27500, a different code path triggers an assert from a crafted packet.

**CISA Advisory**: https://www.cisa.gov/news-events/ics-advisories/icsa-21-105-02

**GitHub Issues of Note**:
- Issue #531: "Potential NULL Pointer Dereference in cipcommon.c"
- Issue #532: "Undefined behavior: left shift of 168 by 24 places in endianconv.c"
- Issue #530: "Can't build OpENer with AFL" (fuzzing infrastructure issue)
- Issue #535: "EncapsulateIpAddress writes wrong sin_family on big endian machine"

---

## Wire Format Summary (for fuzzer development)

### EtherNet/IP Encapsulation Header (24 bytes)

```
Offset  Size   Field
------  ----   -----
0       2      Command Code (LE uint16)
               0x0001 = NOP, 0x0004 = ListServices, 0x0063 = ListIdentity,
               0x0065 = RegisterSession, 0x0066 = UnregisterSession,
               0x006F = SendRRData, 0x0070 = SendUnitData
2       2      Length (LE uint16) -- size of command-specific data
4       4      Session Handle (LE uint32) -- from RegisterSession response
8       4      Status (LE uint32) -- 0 = success
12      8      Sender Context (8 bytes, echoed back)
20      4      Options (LE uint32) -- must be 0
```

### CPF (Common Packet Format)

```
Offset  Size   Field
------  ----   -----
0       2      Item Count (LE uint16) -- typically 2
--- Per Item ---
0       2      Type ID (LE uint16)
               0x0000 = Null Address, 0x00A1 = Connected Address,
               0x00B1 = Connected Data, 0x00B2 = Unconnected Data
2       2      Length (LE uint16) -- data bytes following
4       var    Item Data
```

### CIP Forward Open (Service 0x54)

```
Offset  Size   Field
------  ----   -----
0       1      Priority/Time_Tick
1       1      Timeout Ticks
2       4      O-to-T Connection ID (LE uint32)
6       4      T-to-O Connection ID (LE uint32)
10      2      Connection Serial Number (LE uint16)
12      2      Originator Vendor ID (LE uint16)
14      4      Originator Serial Number (LE uint32)
18      1      Connection Timeout Multiplier
19      3      Reserved
22      4      O-to-T RPI (LE uint32, microseconds)
26      2/4    O-to-T Network Connection Params (2=normal, 4=large)
28/30   4      T-to-O RPI (LE uint32)
32/34   2/4    T-to-O Network Connection Params
34/38   1      Transport Class/Trigger
35/39   1      Connection Path Size (in 16-bit words)
36/40   var    Connection Path (EPATH segments)
```

### EPATH Segment Encoding

```
Segment byte: [Type(3 bits)][SubType(3 bits)][Format(2 bits)]

Logical Segments (Type = 001):
  0x20 = Class ID (8-bit)      0x21 = Class ID (16-bit, +pad)
  0x24 = Instance ID (8-bit)   0x25 = Instance ID (16-bit, +pad)
  0x30 = Attribute ID (8-bit)  0x31 = Attribute ID (16-bit, +pad)
  0x2C = Connection Point (8-bit)

Data Segments (Type = 100):
  0x80 = Simple Data (length in words follows)

Network Segments (Type = 010):
  0x43 = Production Inhibit Time

Port Segments (Type = 000):
  Port number + link address
```

### Primary Fuzzing Targets

1. **CPF item count**: Values 0, 1, 3+, 0xFFFF. CVE-2020-13556 was caused by large item count.
2. **Encapsulation length vs actual data**: Length field = 0 with data, or length > TCP segment.
3. **Forward Open connection path**: Path size in words vs actual path bytes. Empty path (size=0). Path with unknown segment types. Mixed 8-bit/16-bit/32-bit logical formats.
4. **Session handle after UnregisterSession**: Use-after-free potential.
5. **Large Forward Open vs normal Forward Open**: Network connection params change from 2 to 4 bytes -- sending normal-sized packet with large flag set.
6. **EPATH format field = 3 (undefined)**: Logical segment with format bits = 0x03.
7. **Multiple Service Packet (service 0x0A)**: Contains an offset table pointing to embedded CIP services. Offsets pointing outside the buffer boundary.
8. **Data segment length**: Simple data segment with word-length field causing read past buffer end.
