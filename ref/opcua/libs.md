# OPC UA -- Reference Library Source Code

Open-source libraries implementing OPC UA binary protocol encoding/decoding,
useful as reference for fuzzer development and vulnerability research.

---

## 1. open62541 (C)

- **Repository**: https://github.com/open62541/open62541
- **Language**: C (C99/C11)
- **License**: MPLv2.0
- **Maintainer**: o6 Automation team + community
- **Notes**: The primary open-source OPC UA implementation in C. Single-file
  distribution option (amalgamated build). Used in industrial devices, gateways,
  engineering tools, and cloud OPC UA bridges. Includes built-in fuzzing
  harnesses for AFL/libFuzzer. Well-maintained with active security response.

### Key Source Files

**Binary Encoding/Decoding**:

| File | Purpose |
|------|---------|
| `src/ua_types_encoding_binary.c` | **Core binary codec**: type dispatch jump table, all decode/encode functions |
| `src/ua_types_encoding_binary.h` | Decode context struct, function declarations |
| `src/ua_types.c` | UA type definitions, memory management, array operations |
| `src/ua_types_encoding_json.c` | JSON encoding/decoding (CVE-2020-36429 lives here) |
| `src/ua_types_encoding_xml.c` | XML encoding/decoding |

**Transport / Secure Channel**:

| File | Purpose |
|------|---------|
| `src/ua_securechannel.c` | **Chunk extraction, assembly, security header parsing** |
| `src/ua_securechannel.h` | Secure channel structures |
| `src/ua_securechannel_crypto.c` | Crypto operations for secure channel |

**Server Message Processing**:

| File | Purpose |
|------|---------|
| `src/server/ua_server_binary.c` | Server-side binary message processing |
| `src/server/ua_services_attribute.c` | Read/Write/Browse service handlers |

**Type System**:

| File | Purpose |
|------|---------|
| `include/open62541/types.h` | UA_Variant, UA_NodeId, UA_DataType definitions |
| `include/open62541/types_generated.h` | Auto-generated type definitions |
| `src/util/ua_types_lex.c` | Type lexer utilities |

### Notable Parsing Patterns

**Type dispatch via jump table (ua_types_encoding_binary.c)**:
```c
const decodeBinarySignature decodeBinaryJumpTable[UA_DATATYPEKINDS] = {
    (decodeBinarySignature)Boolean_decodeBinary,
    (decodeBinarySignature)Byte_decodeBinary,       /* SByte */
    (decodeBinarySignature)Byte_decodeBinary,       /* Byte */
    (decodeBinarySignature)UInt16_decodeBinary,     /* Int16 */
    (decodeBinarySignature)UInt16_decodeBinary,     /* UInt16 */
    (decodeBinarySignature)UInt32_decodeBinary,     /* Int32 */
    (decodeBinarySignature)UInt32_decodeBinary,     /* UInt32 */
    (decodeBinarySignature)UInt64_decodeBinary,     /* Int64 */
    (decodeBinarySignature)UInt64_decodeBinary,     /* UInt64 */
    (decodeBinarySignature)Float_decodeBinary,
    (decodeBinarySignature)Double_decodeBinary,
    (decodeBinarySignature)String_decodeBinary,
    (decodeBinarySignature)UInt64_decodeBinary,     /* DateTime */
    (decodeBinarySignature)Guid_decodeBinary,
    (decodeBinarySignature)String_decodeBinary,     /* ByteString */
    (decodeBinarySignature)String_decodeBinary,     /* XmlElement */
    (decodeBinarySignature)NodeId_decodeBinary,
    (decodeBinarySignature)ExpandedNodeId_decodeBinary,
    (decodeBinarySignature)UInt32_decodeBinary,     /* StatusCode */
    (decodeBinarySignature)QualifiedName_decodeBinary,
    (decodeBinarySignature)LocalizedText_decodeBinary,
    (decodeBinarySignature)ExtensionObject_decodeBinary,
    (decodeBinarySignature)DataValue_decodeBinary,
    (decodeBinarySignature)Variant_decodeBinary,
    (decodeBinarySignature)DiagnosticInfo_decodeBinary,
    (decodeBinarySignature)decodeBinaryStructure,
    (decodeBinarySignature)decodeBinaryStructureWithOptFields,
    (decodeBinarySignature)decodeBinaryUnion,
    (decodeBinarySignature)decodeBinaryNotImplemented  /* BitfieldCluster */
};
```
The jump table indexes by `type->typeKind`. An out-of-range typeKind would
index into garbage memory -- the check `typeKind <= UA_DATATYPEKIND_DIAGNOSTICINFO`
in Variant decoding prevents this for Variants but other callers may not check.

**NodeId decoding (ua_types_encoding_binary.c)**:
```c
FUNC_DECODE_BINARY(NodeId) {
    u8 encodingByte;
    status ret = DECODE_DIRECT(&encodingByte, Byte);

    /* Mask off ExpandedNodeId flags */
    encodingByte &= (u8)~(u8)(UA_EXPANDEDNODEID_SERVERINDEX_FLAG |
                              UA_EXPANDEDNODEID_NAMESPACEURI_FLAG);

    switch(encodingByte) {
    case UA_NODEIDTYPE_NUMERIC_TWOBYTE:
        /* 1 byte namespace (always 0), 1 byte identifier */
        ret = DECODE_DIRECT(&dstByte, Byte);
        dst->identifier.numeric = dstByte;
        break;
    case UA_NODEIDTYPE_NUMERIC_FOURBYTE:
        /* 1 byte namespace, 2 byte identifier */
        ret |= DECODE_DIRECT(&dstByte, Byte);
        dst->namespaceIndex = dstByte;
        ret |= DECODE_DIRECT(&dstUInt16, UInt16);
        dst->identifier.numeric = dstUInt16;
        break;
    case UA_NODEIDTYPE_NUMERIC_COMPLETE:
        /* 2 byte namespace, 4 byte identifier */
        break;
    case UA_NODEIDTYPE_STRING:
        /* 2 byte namespace + length-prefixed string */
        break;
    case UA_NODEIDTYPE_GUID:
        /* 2 byte namespace + 16 byte GUID */
        break;
    case UA_NODEIDTYPE_BYTESTRING:
        /* 2 byte namespace + length-prefixed byte string */
        break;
    default:
        ret |= UA_STATUSCODE_BADINTERNALERROR;
        break;
    }
    return ret;
}
```
The encoding byte determines the NodeId format. Fuzzing with invalid encoding
byte values (e.g., 0x07-0xFF) tests the default case. The String and ByteString
cases delegate to String_decodeBinary which reads a 4-byte length prefix.

**Variant decoding with recursion limit (ua_types_encoding_binary.c)**:
```c
#define UA_ENCODING_MAX_RECURSION 100

FUNC_DECODE_BINARY(Variant) {
    u8 encodingByte;
    status ret = DECODE_DIRECT(&encodingByte, Byte);
    if(encodingByte == 0) return UA_STATUSCODE_GOOD;  /* NULL variant */

    const UA_Boolean isArray = (encodingByte & UA_VARIANT_ENCODINGMASKTYPE_ARRAY) > 0;
    size_t typeKind = (size_t)((encodingByte & UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK) - 1);

    /* Bounds check on type kind */
    UA_CHECK(typeKind <= UA_DATATYPEKIND_DIAGNOSTICINFO,
             return UA_STATUSCODE_BADDECODINGERROR);

    /* Prevent Variant-in-Variant without array wrapper */
    UA_CHECK(typeKind != UA_DATATYPEKIND_VARIANT || isArray,
             return UA_STATUSCODE_BADDECODINGERROR);

    /* Recursion depth limit */
    UA_CHECK(ctx->depth <= UA_ENCODING_MAX_RECURSION,
             return UA_STATUSCODE_BADENCODINGERROR);
    ctx->depth++;

    /* ... decode scalar or array ... */

    /* Array dimensions validation */
    if(isArray && (encodingByte & UA_VARIANT_ENCODINGMASKTYPE_DIMENSIONS) > 0) {
        /* Decode Int32 array of dimensions */
        /* Validate: product of dimensions == arrayLength */
        size_t totalSize = 1;
        for(size_t i = 0; i < dst->arrayDimensionsSize; ++i) {
            if(dst->arrayDimensions[i] == 0)
                ret = UA_STATUSCODE_BADDECODINGERROR;
            totalSize *= dst->arrayDimensions[i];
        }
        UA_CHECK(totalSize == dst->arrayLength,
                 ret = UA_STATUSCODE_BADDECODINGERROR);
    }

    ctx->depth--;
    return ret;
}
```
The recursion limit (100) was added after CVE-2021-27432. The dimension product
validation prevents mismatched array sizes. Integer overflow in `totalSize *= dims[i]`
is still theoretically possible with large dimension values on 32-bit platforms.

**Array decoding with pre-allocation check (ua_types_encoding_binary.c)**:
```c
static status
Array_decodeBinary(Ctx *ctx, void **dst, size_t *out_length,
                   const UA_DataType *type) {
    i32 signed_length;
    status ret = DECODE_DIRECT(&signed_length, UInt32);

    if(signed_length <= 0) {
        *out_length = 0;
        if(signed_length < 0) *dst = NULL;       /* -1 = null array */
        else *dst = UA_EMPTY_ARRAY_SENTINEL;      /* 0 = empty array */
        return UA_STATUSCODE_GOOD;
    }

    size_t length = (size_t)signed_length;

    /* Sanity check: rough estimate if enough data remains */
    UA_CHECK(ctx->pos + ((type->memSize * length) / 128) <= ctx->end,
             return UA_STATUSCODE_BADDECODINGERROR);

    *dst = ctxCalloc(ctx, length, type->memSize);

    /* For overlayable types, direct memcpy with exact bounds check */
    if(type->overlayable) {
        if(ctx->pos + (type->memSize * length) > ctx->end) {
            ctxFree(ctx, *dst);
            *dst = NULL;
            return UA_STATUSCODE_BADDECODINGERROR;
        }
        memcpy(*dst, ctx->pos, type->memSize * length);
        ctx->pos += type->memSize * length;
    } else {
        /* Element-by-element decoding */
        for(size_t i = 0; i < length; ++i) {
            ret = decodeBinaryJumpTable[type->typeKind](ctx, ...);
        }
    }
    *out_length = length;
    return UA_STATUSCODE_GOOD;
}
```
The rough sanity check `(memSize * length) / 128` is a heuristic -- it prevents
extreme allocations but is intentionally loose. The exact check happens later for
overlayable types via `ctx->pos + exact_size > ctx->end`. Note: `type->memSize * length`
can overflow on 32-bit if both values are large.

**Chunk extraction (ua_securechannel.c)**:
```c
static UA_StatusCode
extractCompleteChunk(UA_SecureChannel *channel, UA_Chunk *chunk,
                     UA_DateTime nowMonotonic) {
    size_t remaining = channel->unprocessed.length - channel->unprocessedOffset;
    if(remaining < UA_SECURECHANNEL_MESSAGEHEADER_LENGTH)  /* 8 bytes minimum */
        return UA_STATUSCODE_GOOD;

    /* Decode TcpMessageHeader: 3-byte type + 1-byte chunk type + 4-byte size */
    UA_TcpMessageHeader hdr;
    UA_decodeBinaryInternal(&channel->unprocessed, &offset, &hdr, ...);

    /* Validate message size */
    /* Route by message type: HEL, ACK, ERR, OPN, MSG, CLO */
}
```
The 4-byte message size field in the header is the primary attack vector. Values
of 0, less than 8, or larger than MaxMessageSize should be tested.

**Asymmetric security header unpacking (ua_securechannel.c)**:
```c
static UA_StatusCode
unpackPayloadOPN(UA_SecureChannel *channel, UA_Chunk *chunk) {
    /* Decode AsymmetricAlgorithmSecurityHeader:
     *   - SecurityPolicyUri (length-prefixed string)
     *   - SenderCertificate (length-prefixed ByteString)
     *   - ReceiverCertificateThumbprint (length-prefixed ByteString) */
    UA_AsymmetricAlgorithmSecurityHeader asymHeader;
    res = UA_decodeBinaryInternal(..., &asymHeader, ...);
    /* Certificate validation follows */
}
```
The security header contains three length-prefixed fields. Oversized certificate
ByteStrings (e.g., length = 0x7FFFFFFF) are a crash vector.

### Known CVEs in This Library

| CVE | CVSS | Type | Description |
|-----|------|------|-------------|
| CVE-2020-36429 | 5.5 | OOB Write | JSON encoding of deeply nested Variants writes past buffer |
| CVE-2022-25761 | 7.5 | Resource exhaustion | No limit on received chunks per session |
| CVE-2026-1301 | 5.7 | Heap overflow | JSON PubSub decoder writes past heap buffer (pre-auth) |

The library has good bounds checking in the binary codec path (post-2021 fixes),
but the JSON encoding path and PubSub subsystem have been less thoroughly audited.

### Fuzzing Priorities

1. **Message size field (4 bytes)**: 0, 7 (< header), MAX_UINT32
2. **String/ByteString length prefix (4 bytes)**: -1, 0, 0x7FFFFFFF, size > remaining
3. **NodeId encoding byte**: values 0x06-0xFF (invalid types)
4. **Variant encoding byte**: invalid typeKind (0, 26+), array bit patterns
5. **Array dimensions**: product overflow, dimensions not matching arrayLength
6. **Chunk type byte**: invalid values (not F/C/A), sequence number gaps
7. **ExtensionObject TypeId**: unknown TypeIds with non-null body
8. **Nested Variant depth**: 100+ levels of Variant-in-array-of-Variant
9. **Security header sizes**: oversized SecurityPolicyUri, SenderCertificate
10. **Hello/Acknowledge**: extreme buffer sizes, max message/chunk counts

---

## 2. opcua-asyncio / asyncua (Python)

- **Repository**: https://github.com/FreeOpcUa/opcua-asyncio
- **Language**: Python (3.8+)
- **License**: LGPL
- **PyPI**: `pip install asyncua`
- **Notes**: The most actively maintained Python OPC UA library. Asyncio-based
  client/server with synchronous wrappers. Most type structures are
  auto-generated from the OPC UA XML specification. Pure Python implementation
  means no native buffer overflows, but resource exhaustion and logic bugs are
  possible (CVE-2022-25304).

### Key Source Files

| File | Purpose |
|------|---------|
| `asyncua/ua/ua_binary.py` | **Core binary codec**: all encode/decode functions |
| `asyncua/ua/uatypes.py` | Type system utilities, Optional/Union handling |
| `asyncua/ua/uaprotocol_auto.py` | Auto-generated OPC UA type definitions |
| `asyncua/ua/uaprotocol_hand.py` | Hand-written protocol structures (Header, etc.) |
| `asyncua/server/uaprocessor.py` | Server-side message processing and dispatch |
| `asyncua/server/binary_server_asyncio.py` | Server binary transport layer |
| `asyncua/common/structures.py` | Custom structure definitions |
| `asyncua/common/structures104.py` | OPC UA 1.04 structure definitions |

### Notable Parsing Patterns

**Header parsing (ua_binary.py)**:
```python
def header_from_binary(data):
    hdr = ua.Header()
    hdr.MessageType, hdr.ChunkType, hdr.packet_size = struct.unpack("<3scI", data.read(8))
    hdr.body_size = hdr.packet_size - 8
    if hdr.MessageType in (ua.MessageType.SecureOpen,
                           ua.MessageType.SecureClose,
                           ua.MessageType.SecureMessage):
        hdr.body_size -= 4
        hdr.ChannelId = Primitives.UInt32.unpack(data)
        hdr.header_size = 12
    return hdr
```
The `packet_size` from the wire directly determines `body_size`. No upper bound
check. If `packet_size < 8`, `body_size` underflows (becomes negative in Python,
which is handled by struct.unpack reading 0 bytes, but downstream code may not
expect negative sizes).

**NodeId decoding (ua_binary.py)**:
```python
def nodeid_from_binary(data):
    encoding = ord(data.read(1))
    nidtype = ua.NodeIdType(encoding & 0b00111111)

    if nidtype == ua.NodeIdType.TwoByte:
        identifier = ord(data.read(1))
        nidx = 0
    elif nidtype == ua.NodeIdType.FourByte:
        nidx, identifier = struct.unpack("<BH", data.read(3))
    elif nidtype == ua.NodeIdType.Numeric:
        nidx, identifier = struct.unpack("<HI", data.read(6))
    elif nidtype == ua.NodeIdType.String:
        nidx = Primitives.UInt16.unpack(data)
        identifier = Primitives.String.unpack(data)
    elif nidtype == ua.NodeIdType.ByteString:
        nidx = Primitives.UInt16.unpack(data)
        identifier = Primitives.Bytes.unpack(data)
    elif nidtype == ua.NodeIdType.Guid:
        nidx = Primitives.UInt16.unpack(data)
        identifier = Primitives.Guid.unpack(data)
    else:
        raise UaError(f"Unknown NodeId encoding: {nidtype}")

    # ExpandedNodeId flags
    if test_bit(encoding, 7):
        uri = Primitives.String.unpack(data)
    if test_bit(encoding, 6):
        server_idx = Primitives.UInt32.unpack(data)

    return ua.NodeId(identifier, nidx, nidtype)
```
The `ua.NodeIdType(encoding & 0b00111111)` will raise ValueError for undefined
enum values. String/ByteString NodeIds delegate to `Primitives.String.unpack`
which reads a 4-byte length then `data.read(length)` -- no upper bound on length.

**Variant decoding (ua_binary.py)**:
```python
def variant_from_binary(data):
    encoding = ord(data.read(1))
    int_type = encoding & 0b00111111
    vtype = ua.datatype_to_varianttype(int_type)

    if test_bit(encoding, 7):           # Array flag
        value = unpack_uatype_array(vtype, data)
        array = True
    else:
        value = unpack_uatype(vtype, data)

    if test_bit(encoding, 6):           # Dimensions flag
        dimensions = unpack_uatype_array(ua.VariantType.Int32, data)
        if value is not None:
            value = _reshape(value, dimensions)

    return ua.Variant(value, vtype, dimensions, is_array=array)
```
No recursion depth limit in the Python implementation (unlike open62541's
`UA_ENCODING_MAX_RECURSION = 100`). A Variant containing an array of Variants
containing arrays of Variants will recurse until Python hits its recursion limit
(default 1000), causing RecursionError.

**String/ByteString with length prefix (ua_binary.py)**:
```python
class _Bytes:
    @staticmethod
    def unpack(data):
        length = Primitives.Int32.unpack(data)
        if length == -1:
            return None          # Null value
        return data.read(length) # No upper bound on length!

class _String:
    @staticmethod
    def unpack(data):
        b = _Bytes.unpack(data)
        if b is None:
            return b
        return b.decode("utf-8", errors="replace")
```
The length field is a signed 32-bit integer. -1 means null. Any positive value
is used directly as the read length. For a malicious message with length = 2GB,
`data.read(2147483647)` will attempt to allocate that much memory. This is the
root cause of CVE-2022-25304.

**ExtensionObject decoding (ua_binary.py)**:
```python
def extensionobject_from_binary(data):
    typeid = nodeid_from_binary(data)
    encoding = ord(data.read(1))
    body = None
    if encoding & (1 << 0):           # Binary body
        length = Primitives.Int32.unpack(data)
        if length == -1:
            body = data
        elif length < 1:
            body = Buffer(b"")
        else:
            body = data.copy(length)
            data.skip(length)

    if typeid.Identifier == 0:
        return ua.ExtensionObject()

    if typeid in ua.extension_objects_by_typeid:
        cls = ua.extension_objects_by_typeid[typeid]
        return from_binary(cls, body)   # Recursive decode

    # Unknown type: store raw bytes
    return ua.ExtensionObject(TypeId=typeid, Body=body_data)
```
Unknown TypeIds with body encoding = binary will have their body stored as raw
bytes. Known TypeIds trigger recursive decoding via `from_binary()`. A crafted
TypeId that maps to a complex nested type can trigger deep recursion.

**Dataclass deserialization with cached deserializers (ua_binary.py)**:
```python
@functools.cache
def _create_dataclass_deserializer(objtype):
    """Build a cached deserializer function for a dataclass"""
    # Resolves field types, creates per-field deserializers
    # Handles optional fields via Encoding bitmask
    # Handles UaUnion types via Encoding + value dispatch

    def decode(data):
        kwargs = {}
        enc = 0
        for field, optional_enc_bit, deserialize_field in field_deserializers:
            if field.name == "Encoding":
                enc = deserialize_field(data)
            elif optional_enc_bit == 0 or enc & optional_enc_bit:
                kwargs[field.name] = deserialize_field(data)
        return objtype(**kwargs)
    return decode
```
The cached deserializer pattern means each OPC UA type gets a one-time compiled
deserializer. The Encoding bitmask controls which optional fields are present.
A malformed Encoding value can cause fields to be skipped or read out of order.

### Known CVEs in This Library

| CVE | CVSS | Type | Description |
|-----|------|------|-------------|
| CVE-2022-25304 | 7.5 | Resource exhaustion | No limit on chunk count/size per session (DoS) |
| CVE-2023-26150 | -- | Auth bypass | Address Space accessible without encryption/auth |

CVE-2022-25304 is a fuzzer-relevant parsing bug: sending unlimited 2GB chunks
without a Final chunk exhausts server memory. Fixed in asyncua >= 0.9.96.

CVE-2023-26150 is a logic flaw (no auth check), not a parsing bug -- excluded
from fuzzer scope.

### Fuzzing Priorities

1. **String/ByteString length**: values near INT32_MAX, negative (not -1), 0
2. **Variant recursion**: deeply nested Variant arrays without depth limit
3. **Chunk accumulation**: many Continue chunks without Final (CVE-2022-25304 pattern)
4. **ExtensionObject with unknown TypeId**: triggers body-skip path
5. **Encoding bitmask in optional fields**: invalid bit patterns
6. **NodeId encoding byte**: undefined values (0x06+) in lower 6 bits
7. **Header packet_size**: values < 8 causing negative body_size
8. **Array length + element decoding**: length says 1M elements, data has 10 bytes
