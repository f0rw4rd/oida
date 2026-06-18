# MMS / IEC 61850 -- Reference Library Source Code

Open-source libraries implementing MMS protocol parsing (ASN.1/BER encoding,
COTP/TPKT transport, MMS PDU handling), useful as reference for fuzzer
development and vulnerability research.

---

## 1. libiec61850 (C)

- **Repository**: https://github.com/mz-automation/libiec61850
- **Language**: C (C99)
- **License**: GPLv3 / commercial dual-license
- **Maintainer**: MZ Automation GmbH (Michael Zillgith)
- **Version**: 1.6 (latest stable branch)
- **Notes**: The most widely deployed open-source IEC 61850 implementation.
  Implements MMS client/server, GOOSE, and Sampled Values. Contains embedded
  asn1c-generated ASN.1 codec plus hand-written BER decode/encode utilities.
  Has the most CVEs of any IEC 61850 library (4 in 2022, 3 in 2024, plus
  additional bugs in 2024-2025).

### Key Source Files

**ASN.1 / BER Layer**:

| File | Purpose |
|------|---------|
| `src/mms/asn1/ber_decode.c` | BER decoding: length, integer, float, string, boolean, OID |
| `src/mms/asn1/ber_encoder.c` | BER encoding: length, tag, integer, float, string |
| `src/mms/asn1/ber_integer.c` | BER integer encoding/decoding utilities |
| `src/mms/asn1/asn1_ber_primitive_value.c` | Primitive BER value wrapper |
| `src/mms/inc_private/ber_decode.h` | BER decoder function declarations |
| `src/mms/inc_private/ber_encoder.h` | BER encoder function declarations |

**TPKT / COTP / ISO Stack**:

| File | Purpose |
|------|---------|
| `src/mms/iso_cotp/cotp.c` | COTP (ISO 8073) over TCP: TPKT header, PDU type dispatch, segmentation |
| `src/mms/iso_session/iso_session.c` | ISO session layer (ISO 8327) |
| `src/mms/iso_presentation/iso_presentation.c` | ISO presentation layer (ISO 8823) |
| `src/mms/iso_acse/acse.c` | ACSE association control |
| `src/mms/iso_server/iso_connection.c` | ISO connection management |

**MMS Protocol Layer**:

| File | Purpose |
|------|---------|
| `src/mms/iso_mms/server/mms_server_connection.c` | **Main PDU dispatcher**: routes by tag to service handlers |
| `src/mms/iso_mms/server/mms_read_service.c` | MMS Read service handler |
| `src/mms/iso_mms/server/mms_write_service.c` | MMS Write service handler |
| `src/mms/iso_mms/server/mms_association_service.c` | MMS Initiate/Conclude service |
| `src/mms/iso_mms/server/mms_file_service.c` | MMS file transfer (ObtainFile, FileRead, etc.) |
| `src/mms/iso_mms/server/mms_identify_service.c` | MMS Identify service |
| `src/mms/iso_mms/server/mms_get_namelist_service.c` | MMS GetNameList service |
| `src/mms/iso_mms/common/mms_common_msg.c` | MMS Data element encoding/decoding (type dispatch) |
| `src/mms/iso_mms/common/mms_value.c` | MMS value creation, manipulation, conversion |

**ASN.1 Generated Code (asn1c)**:

| File | Purpose |
|------|---------|
| `src/mms/iso_mms/asn1c/MmsPdu.c` | Top-level MMS PDU ASN.1 structure |
| `src/mms/iso_mms/asn1c/ConfirmedRequestPdu.c` | Confirmed request PDU |
| `src/mms/iso_mms/asn1c/ConfirmedServiceRequest.c` | Service request dispatch |
| `src/mms/iso_mms/asn1c/Data.c` | MMS Data type (recursive, contains all value types) |
| `src/mms/iso_mms/asn1c/ReadRequest.c` / `ReadResponse.c` | Read service structures |
| `src/mms/iso_mms/asn1c/WriteRequest.c` / `WriteResponse.c` | Write service structures |
| `src/mms/iso_mms/asn1c/ber_decoder.c` | asn1c BER decoder (separate from hand-written ber_decode.c) |
| `src/mms/iso_mms/asn1c/ber_tlv_length.c` | BER TLV length parsing |
| `src/mms/iso_mms/asn1c/ber_tlv_tag.c` | BER TLV tag parsing |

### Notable Parsing Patterns

**BER length decoding (ber_decode.c)**:
```c
/* BerDecoder_decodeLength - handles definite and indefinite forms */
/* Short form: length < 128, single byte */
/* Long form: first byte & 0x80, remaining bytes give length of length */
/* Indefinite form: 0x80, scan for 0x00 0x00 end-of-content */
```
The length decoder handles all three BER length encodings. The critical
vulnerability pattern: decoded length is returned as an int and used directly
in memcpy/buffer operations without clamping to the remaining buffer size.
This is the root cause of CVE-2022-2970 and CVE-2022-2972.

**BER value decoding (ber_decode.c)**:
```c
/* BerDecoder_decodeUint32(buffer, bufPos, length) */
/* BerDecoder_decodeInt32(buffer, bufPos, length) */
/* BerDecoder_decodeFloat(buffer, bufPos) - reads 5 bytes (1 exponent + 4 mantissa) */
/* BerDecoder_decodeDouble(buffer, bufPos) - reads 9 bytes (1 exponent + 8 mantissa) */
/* BerDecoder_decodeString(buffer, bufPos, maxLength, dest, destSize) */
/* BerDecoder_decodeBoolean(buffer, bufPos) */
```
The string decoder `BerDecoder_decodeString` takes a `destSize` parameter but
earlier versions did not validate `maxLength` against `destSize` before copying.

**COTP TPKT header parsing (cotp.c)**:
```c
/* TPKT header: 4 bytes */
/* byte 0: version (0x03) */
/* byte 1: reserved (0x00) */
/* bytes 2-3: big-endian total length (including TPKT header) */

/* COTP PDU type dispatch via parseCotpMessage(): */
/* 0xe0 -> Connection Request (CR) */
/* 0xd0 -> Connection Confirm (CC) */
/* 0xf0 -> Data Transfer (DT) */
```
The TPKT 2-byte length field determines how much data to read. Mismatch between
TPKT length and TCP payload is a crash vector -- the parser may read beyond the
buffer or underflow.

**MMS PDU type dispatch (mms_server_connection.c)**:
```c
/* MmsServerConnection_parseMessage() routes by ASN.1 tag: */
/* 0xa8 -> Initiate request PDU */
/* 0xa0 -> Confirmed request PDU */
/* 0xa1 -> Confirmed response PDU (file service only) */
/* 0xa2 -> Confirmed error PDU (file service only) */
/* 0x8b -> Conclude request PDU */

/* handleConfirmedRequestPdu() dispatches by service tag: */
/* Status, Identify, Read, Write, GetNameList, etc. */
```
Each service handler receives the BER-decoded ASN.1 structure and processes
fields. The service handlers are where most CVEs occur because they trust
field lengths from ASN.1 decoding.

**MMS Data type parsing (mms_common_msg.c)**:
```c
/* mmsMsg_parseDataElement(Data_t* dataElement) */
/* Dispatches on dataElement->present: */
/*   Data_PR_array     -> recursive array parsing */
/*   Data_PR_structure  -> recursive structure parsing */
/*   Data_PR_integer    -> BerInteger_createFromBuffer() */
/*   Data_PR_floatingpoint -> endian-aware float/double copy */
/*   Data_PR_bitstring  -> bit string with unused bits */
/*   ... and more types */
```
Arrays and structures are parsed recursively. No depth limit is enforced in older
versions, making stack exhaustion via deeply nested Data elements a viable attack.

### Known CVEs in This Library

| CVE | CVSS | Type | Component | Description |
|-----|------|------|-----------|-------------|
| CVE-2022-2970 | 9.8 | Stack overflow | MMS server | Missing bounds check before memcpy of BER-decoded length |
| CVE-2022-2972 | 9.8 | Stack overflow | MMS server | Second unchecked memcpy in different service handler |
| CVE-2022-2971 | 8.6 | Type confusion | MMS server | Wrong ASN.1 tag class not validated before cast |
| CVE-2022-2973 | 7.5 | NULL deref | MMS server | Missing NULL check on decoded field |
| CVE-2024-25366 | 6.2 | Buffer overflow | mms_getnamelist_service | Overflow in GetNameList request handler |
| CVE-2024-45969 | 7.5 | NULL deref | MMS client | Crafted InitiateResponse crashes client |
| CVE-2024-45970 | 9.8 | Stack overflow | MMS client | Unchecked length in FileDirResponse handler |
| CVE-2024-45971 | 9.8 | Stack overflow | MMS client | Unchecked string length in IdentifyResponse |

Additionally, GitHub issue #505 reports a heap-buffer-overflow in
`BerEncoder_encodeLength` in v1.5.

The systemic pattern: BER-decoded lengths are used directly in memcpy/buffer
operations without validating against remaining buffer or destination size.
Every service handler is potentially vulnerable until individually audited.

### Fuzzing Priorities

1. **ASN.1 BER lengths**: indefinite lengths (0x80), multi-byte long-form
   lengths (0x81 0xFF, 0x82 0xFF 0xFF), lengths exceeding remaining data
2. **ASN.1 tag bytes**: wrong class (UNIVERSAL vs CONTEXT-SPECIFIC), wrong
   constructed/primitive bit, undefined tag numbers
3. **TPKT length mismatch**: TPKT says 1000 bytes, TCP payload has 50
4. **MMS Data nesting**: deeply nested structures/arrays (100+ levels)
5. **String fields**: ObjectNames, domain names, file paths with lengths
   near or exceeding 256/1024/4096 boundaries
6. **File service paths**: directory traversal in ObtainFile/FileOpen
7. **Initiate parameters**: negotiated PDU size then violated
8. **COTP parameter options**: malformed TPDU size negotiation values

---

## 2. iec61850bean (Java) -- formerly OpenIEC61850

- **Repository**: https://github.com/beanit/iec61850bean
- **Language**: Java
- **License**: Apache 2.0
- **Stars**: 175
- **Notes**: Java implementation of IEC 61850 MMS client/server. Formerly known
  as OpenIEC61850, now maintained under the beanit organization. Uses the
  jASN1 library for ASN.1 BER encoding/decoding. Less relevant for C/native
  fuzzing but useful for understanding the protocol specification mapping.
  The ASN.1 structure definitions match the MMS ISO 9506 spec closely.

### Key Source Files

| File | Purpose |
|------|---------|
| `src/main/java/com/beanit/iec61850bean/ClientAssociation.java` | MMS client association handling |
| `src/main/java/com/beanit/iec61850bean/ServerAssociation.java` | MMS server association handling |
| `src/main/java/com/beanit/iec61850bean/ServerSap.java` | Server access point |
| `src/main/java/com/beanit/iec61850bean/ServerModel.java` | Server-side data model |
| `src/main/java-gen/com/beanit/iec61850bean/internal/mms/asn1/` | jASN1-generated MMS PDU types |
| `src/main/java/com/beanit/josistack/AcseAssociation.java` | ACSE/COTP/TPKT ISO stack |

### Notable Parsing Patterns

Java's managed memory prevents buffer overflows, but the ASN.1 structure
definitions are faithful to the ISO 9506 MMS specification. The jASN1 library
handles BER tag/length/value parsing with checked array bounds.

The library is useful for:
- Understanding the complete MMS service set and PDU structures
- Cross-referencing ASN.1 tag assignments with libiec61850's C code
- Generating valid MMS messages to use as fuzzer seed corpus

### Known CVEs in This Library

No CVEs assigned to iec61850bean or its predecessor OpenIEC61850.

---

## 3. pyiec61850 / libiec61850 Python Bindings

- **Repository**: https://github.com/mz-automation/libiec61850 (bindings in `pyiec61850/` directory)
- **Alternative wrapper**: https://github.com/keyvdir/pyiec61850
- **Language**: Python (SWIG bindings around libiec61850 C library)
- **License**: GPLv3
- **Notes**: SWIG-generated Python bindings for libiec61850. The actual parsing
  happens in the C library; Python provides the API surface. Build requires
  CMake with `-DBUILD_PYTHON_BINDINGS=ON` and SWIG installed.

### Key Source Files

| File | Purpose |
|------|---------|
| `pyiec61850/iec61850.py` | SWIG-generated Python wrapper |
| `pyiec61850/iec61850.i` | SWIG interface definition |
| All C files listed in Library 1 above | Actual parsing implementation |

### Notable Parsing Patterns

The Python bindings expose libiec61850's C API directly. All parsing happens in
the C layer (see Library 1 above). The Python layer adds no additional
validation or bounds checking.

Key Python API functions that trigger C parsing:
```python
# Connection and association
con = IedConnection_create()
IedConnection_connect(con, host, port)

# Reading values triggers MMS Read service parsing
value = IedConnection_readObject(con, objectRef, FC)

# The MMS server-side parsing is triggered when handling incoming connections
server = IedServer_create(model)
IedServer_start(server, port)
```

### Known CVEs in This Library

Same CVEs as libiec61850 (Library 1) since the Python bindings are a thin
wrapper. Any exploitation of the C library's parsing bugs can be triggered
through the Python API.

### Fuzzing Relevance

The pyiec61850 bindings can be used to:
1. Build fuzzer harnesses that feed crafted bytes through the C parser via Python
2. Generate valid MMS messages as seed corpus (then mutate at the wire level)
3. Test the server by connecting to it with a malicious client sending crafted PDUs

The SWIG bindings add no safety layer -- buffer overflows in the C library
will crash the Python process.
