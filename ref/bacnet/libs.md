# BACnet Reference Library Source Code

Reference implementations for BACnet/IP protocol parsing, relevant for fuzzer development.

---

## 1. bacpypes (Python)

- **Repository**: https://github.com/JoelBender/bacpypes (322 stars)
- **Language**: Python 2.7 / Python 3 (bacpypes3 fork exists)
- **License**: MIT

### Key Source Files

| File | Purpose |
|------|---------|
| `py27/bacpypes/bvll.py` | BVLC (BACnet Virtual Link Control) encode/decode |
| `py27/bacpypes/npdu.py` | NPDU (Network Protocol Data Unit) encode/decode |
| `py27/bacpypes/apdu.py` | APDU (Application PDU) types: ConfirmedRequest, SimpleAck, etc. |
| `py27/bacpypes/pdu.py` | Base PDU class with `get()`, `get_short()`, `get_data()` primitives |
| `py27/bacpypes/primitivedata.py` | ASN.1 primitive types: Boolean, Integer, Real, OctetString, etc. |
| `py27/bacpypes/constructeddata.py` | ASN.1 constructed types: Sequence, Array, Any |
| `py27/bacpypes/basetypes.py` | BACnet-specific types: ObjectIdentifier, PropertyReference, etc. |
| `py27/bacpypes/bvllservice.py` | BVLC service layer (BBMD, foreign device registration) |
| `py27/bacpypes/netservice.py` | Network layer service (routing, Who-Is-Router) |

### Notable Parsing Patterns

**BVLC Header Decode** (`py27/bacpypes/bvll.py`):

The BVLC header is 4 bytes: type (1), function (1), length (2). The length includes itself.

```python
class BVLCI(PCI, DebugContents):
    _debug_contents = ('bvlciType', 'bvlciFunction', 'bvlciLength')

    result                              = 0x00
    writeBroadcastDistributionTable     = 0x01
    readBroadcastDistributionTable      = 0x02
    readBroadcastDistributionTableAck   = 0x03
    forwardedNPDU                       = 0x04
    registerForeignDevice               = 0x05
    readForeignDeviceTable              = 0x06
    readForeignDeviceTableAck           = 0x07
    deleteForeignDeviceTableEntry       = 0x08
    distributeBroadcastToNetwork        = 0x09
    originalUnicastNPDU                 = 0x0A
    originalBroadcastNPDU               = 0x0B

    def decode(self, pdu):
        """decode the contents of the PDU into the BVLCI."""
        PCI.update(self, pdu)

        self.bvlciType = pdu.get()
        if self.bvlciType != 0x81:
            raise DecodingError("invalid BVLCI type")

        self.bvlciFunction = pdu.get()
        self.bvlciLength = pdu.get_short()

        if (self.bvlciLength != len(pdu.pduData) + 4):
            raise DecodingError("invalid BVLCI length")
```

Key observations for fuzzing:
- Type byte MUST be 0x81 -- fuzz to other values to test error paths
- Length field is validated against `len(pdu.pduData) + 4` -- mismatch raises DecodingError
- BUT: `pdu.pduData` is the remaining data AFTER the 4-byte header, so the check is `bvlciLength == remaining + 4`
- Function byte has no range check -- values 0x0C-0xFF are undefined and will cause KeyError in dispatch

**Forwarded-NPDU Decode** (`py27/bacpypes/bvll.py`):

This is the BBMD forwarding path -- historically vulnerable:

```python
class ForwardedNPDU(BVLPDU):
    messageType = BVLCI.forwardedNPDU

    def decode(self, bvlpdu):
        BVLCI.update(self, bvlpdu)
        self.bvlciAddress = Address(unpack_ip_addr(bvlpdu.get_data(6)))
        self.pduData = bvlpdu.get_data(len(bvlpdu.pduData))
```

Key observations for fuzzing:
- `get_data(6)` reads exactly 6 bytes for the IP address -- if less than 6 bytes remain, this raises
- `self.pduData` gets everything remaining -- no size limit on the forwarded NPDU content
- The original source IP (6 bytes) is attacker-controlled in a forwarded packet

**WriteBroadcastDistributionTable Decode**:

```python
class WriteBroadcastDistributionTable(BVLPDU):
    def decode(self, bvlpdu):
        BVLCI.update(self, bvlpdu)
        self.bvlciBDT = []
        while bvlpdu.pduData:
            bdte = Address(unpack_ip_addr(bvlpdu.get_data(6)))
            bdte.addrMask = bvlpdu.get_long()
            self.bvlciBDT.append(bdte)
```

Key observations for fuzzing:
- Reads entries in a loop until `pduData` is empty -- each entry is 10 bytes (6 addr + 4 mask)
- If remaining data is not a multiple of 10, the last `get_data(6)` or `get_long()` will fail mid-entry
- No limit on number of BDT entries -- 65536-byte BVLC length = ~6553 entries

**NPDU Decode** (`py27/bacpypes/npdu.py`):

The NPDU carries routing information with variable-length addresses:

```python
class NPCI(PCI, DebugContents):
    def decode(self, pdu):
        # check the length
        if len(pdu.pduData) < 2:
            raise DecodingError("invalid length")

        self.npduVersion = pdu.get()
        if (self.npduVersion != 0x01):
            raise DecodingError("only version 1 messages supported")

        self.npduControl = control = pdu.get()
        netLayerMessage = control & 0x80
        dnetPresent = control & 0x20
        snetPresent = control & 0x08
        self.pduExpectingReply = (control & 0x04) != 0
        self.pduNetworkPriority = control & 0x03

        # extract the destination address
        if dnetPresent:
            dnet = pdu.get_short()
            dlen = pdu.get()
            dadr = pdu.get_data(dlen)

            if dnet == 0xFFFF:
                self.npduDADR = GlobalBroadcast()
            elif dlen == 0:
                self.npduDADR = RemoteBroadcast(dnet)
            else:
                self.npduDADR = RemoteStation(dnet, dadr)

        # extract the source address
        if snetPresent:
            snet = pdu.get_short()
            slen = pdu.get()
            sadr = pdu.get_data(slen)

            if snet == 0xFFFF:
                raise DecodingError("SADR can't be a global broadcast")
            elif slen == 0:
                raise DecodingError("SADR can't be a remote broadcast")

            self.npduSADR = RemoteStation(snet, sadr)

        # extract the hop count
        if dnetPresent:
            self.npduHopCount = pdu.get()

        # extract the network layer message type
        if netLayerMessage:
            self.npduNetMessage = pdu.get()
            if (self.npduNetMessage >= 0x80) and (self.npduNetMessage <= 0xFF):
                self.npduVendorID = pdu.get_short()
```

Key observations for fuzzing:
- `dlen` and `slen` are single bytes (0-255) read from the wire, used as `get_data(dlen)` argument
- No check that `dlen` or `slen` is within a reasonable range (MAC addresses are typically 1-7 bytes)
- A `dlen` of 255 would try to read 255 bytes from the remaining packet data
- Control byte bit 5 (dnetPresent) and bit 3 (snetPresent) drive which fields are parsed
- Hop count is only present when dnetPresent -- fuzz with dnetPresent=1 but no hop count byte
- Vendor ID (2 bytes) only present for network message types >= 0x80

### Known CVEs in bacpypes

No CVEs assigned specifically to bacpypes. As a pure Python library, buffer overflows are not applicable. However, the parsing patterns above can cause unhandled exceptions from malformed packets.

---

## 2. bacnet-stack (C)

- **Repository**: https://github.com/bacnet-stack/bacnet-stack (531 stars)
- **Language**: C
- **License**: GPL-2.0-or-later with GCC-exception-2.0

### Key Source Files

| File | Purpose |
|------|---------|
| `src/bacnet/datalink/bvlc.c` | BVLC encode/decode: header, result, BDT, FDT, forwarded NPDU |
| `src/bacnet/datalink/bvlc.h` | BVLC constants, message types, data structures |
| `src/bacnet/npdu.c` | NPDU encode/decode: routing headers, hop count, network messages |
| `src/bacnet/npdu.h` | NPDU data structures: `BACNET_NPDU_DATA`, `BACNET_ADDRESS` |
| `src/bacnet/bacdcode.c` | ASN.1 BER tag/length/value encoding -- the core serialization layer |
| `src/bacnet/bacdcode.h` | Tag encoding/decoding function prototypes |
| `src/bacnet/bacapp.c` | Application-layer data encode/decode (object property values) |
| `src/bacnet/apdu.h` | APDU type definitions, service choice constants |
| `src/bacnet/basic/bbmd/h_bbmd.c` | BBMD handler -- processes BVLC messages on the server side |
| `src/bacnet/arf.c` | AtomicReadFile service decode |
| `src/bacnet/awf.c` | AtomicWriteFile service decode |

### Notable Parsing Patterns

**BVLC Header Decode** (`src/bacnet/datalink/bvlc.c`):

```c
int bvlc_decode_header(
    const uint8_t *pdu,
    uint16_t pdu_len,
    uint8_t *message_type,
    uint16_t *message_length)
{
    int bytes_consumed = 0;

    if (pdu && (pdu_len >= 4)) {
        if (pdu[0] == BVLL_TYPE_BACNET_IP) {
            if (message_type) {
                *message_type = pdu[1];
            }
            if (message_length) {
                decode_unsigned16(&pdu[2], message_length);
            }
            bytes_consumed = 4;
        }
    }
    return bytes_consumed;
}
```

Key observations for fuzzing:
- `message_length` is read from the wire (2 bytes at offset 2-3), but no validation against `pdu_len`
- The caller is responsible for checking if `message_length <= pdu_len`
- `pdu[0]` must be `BVLL_TYPE_BACNET_IP` (0x81) -- non-0x81 silently returns 0 (no error)
- `message_type` (pdu[1]) has no range validation here -- undefined types propagate to higher layers

**BVLC Result Decode** (`src/bacnet/datalink/bvlc.c`):

```c
int bvlc_encode_header(
    uint8_t *pdu, uint16_t pdu_size, uint8_t message_type, uint16_t length)
{
    int bytes_encoded = 0;
    if (pdu && (pdu_size >= 2)) {
        pdu[0] = BVLL_TYPE_BACNET_IP;
        pdu[1] = message_type;
        encode_unsigned16(&pdu[2], length);
        bytes_encoded = 4;
    }
    return bytes_encoded;
}

int bvlc_decode_result(
    const uint8_t *pdu, uint16_t pdu_len, uint16_t *result_code)
{
    int bytes_consumed = 0;
    const uint16_t length = 2;

    if (pdu && (pdu_len >= length)) {
        if (result_code) {
            decode_unsigned16(&pdu[0], result_code);
        }
        bytes_consumed = (int)length;
    }
    return bytes_consumed;
}
```

**NPDU Decode** (`src/bacnet/npdu.c`):

The C implementation of NPDU parsing with explicit bounds checking:

```c
int bacnet_npdu_decode(
    const uint8_t *npdu,
    uint16_t pdu_len,
    BACNET_ADDRESS *dest,
    BACNET_ADDRESS *src,
    BACNET_NPDU_DATA *npdu_data)
{
    int len = 0;
    uint8_t i = 0;
    uint16_t src_net = 0, dest_net = 0;
    uint8_t slen = 0, dlen = 0, mac_octet = 0;

    if (npdu && npdu_data && (pdu_len >= 2)) {
        npdu_data->protocol_version = npdu[0];
        npdu_data->network_layer_message = (npdu[1] & BIT(7)) ? true : false;
        npdu_data->data_expecting_reply = (npdu[1] & BIT(2)) ? true : false;
        npdu_data->priority = (BACNET_MESSAGE_PRIORITY)(npdu[1] & 0x03);
        len = 2;

        /* Destination specifier */
        if (npdu[1] & BIT(5)) {
            if (pdu_len >= (len + 3)) {
                len += decode_unsigned16(&npdu[len], &dest_net);
                dlen = npdu[len++];
                if (dest) {
                    dest->net = dest_net;
                    dest->len = dlen;
                }
                if (dlen) {
                    if ((dlen > MAX_MAC_LEN) || (pdu_len < (len + dlen))) {
                        /* address is too large -- malformed message */
                        return -1;
                    }
                    for (i = 0; i < dlen; i++) {
                        mac_octet = npdu[len++];
                        if (dest) dest->adr[i] = mac_octet;
                    }
                }
            }
        }

        /* Source specifier */
        if (npdu[1] & BIT(3)) {
            if (pdu_len >= (len + 3)) {
                len += decode_unsigned16(&npdu[len], &src_net);
                slen = npdu[len++];
                if (src) {
                    src->net = src_net;
                    src->len = slen;
                }
                if (slen) {
                    if ((slen > MAX_MAC_LEN) || (pdu_len < (len + slen))) {
                        return -1;
                    }
                    for (i = 0; i < slen; i++) {
                        mac_octet = npdu[len++];
                        if (src) src->adr[i] = mac_octet;
                    }
                }
            }
        }

        /* Hop count (only if destination present) */
        if (dest_net) {
            if (pdu_len > len) {
                npdu_data->hop_count = npdu[len++];
            } else {
                npdu_data->hop_count = 0;
            }
        }

        /* Network layer message type */
        if (npdu_data->network_layer_message) {
            if (pdu_len > len) {
                npdu_data->network_message_type = npdu[len++];
            }
            if (npdu_data->network_message_type >= 0x80) {
                if (pdu_len >= (len + 2)) {
                    len += decode_unsigned16(&npdu[len], &npdu_data->vendor_id);
                }
            }
        }
    }
    return len;
}
```

Key observations for fuzzing:
- `dlen` and `slen` are checked against `MAX_MAC_LEN` (7 bytes typically) -- values > MAX_MAC_LEN return -1
- `pdu_len` bounds are checked before each field read
- `dest_net = 0` skips hop count parsing -- but the original bacnet-stack 0.8.x did NOT have these checks
- The `npdu[1] & BIT(5)` and `npdu[1] & BIT(3)` control which address fields are present -- fuzz these independently
- Fuzz: `dlen = MAX_MAC_LEN + 1`, `slen = 0` with snetPresent, hop count missing when dnet present

**ASN.1 Tag/Length/Value Encoding** (`src/bacnet/bacdcode.c`):

This is the core serialization layer. BACnet uses context-tagged ASN.1 encoding extensively.

```c
int encode_tag(
    uint8_t *apdu,
    uint8_t tag_number,
    bool context_specific,
    uint32_t len_value_type)
{
    int len = 1;

    if (apdu) apdu[0] = 0;
    if (context_specific) {
        if (apdu) apdu[0] = BIT(3);
    }

    /* Extended tag byte for tag_number > 14 */
    if (tag_number <= 14) {
        if (apdu) apdu[0] |= (tag_number << 4);
    } else {
        if (apdu) {
            apdu[0] |= 0xF0;
            apdu[1] = tag_number;
        }
        len++;
    }

    /* Length encoding */
    if (len_value_type <= 4) {
        if (apdu) apdu[0] |= len_value_type;
    } else {
        if (apdu) apdu[0] |= 5;
        if (len_value_type <= 253) {
            if (apdu) apdu[len] = (uint8_t)len_value_type;
            len++;
        } else if (len_value_type <= 65535) {
            if (apdu) apdu[len] = 254;
            len++;
            len += encode_unsigned16(apdu ? &apdu[len] : NULL,
                                     (uint16_t)len_value_type);
        } else {
            if (apdu) apdu[len] = 255;
            len++;
            len += encode_unsigned32(apdu ? &apdu[len] : NULL,
                                     len_value_type);
        }
    }
    return len;
}
```

Key observations for fuzzing:
- Tag number > 14 uses extended encoding (2+ bytes for tag)
- Length encoding is variable: 0-4 inline, 5-253 = 1 extra byte, 254 prefix = 2-byte length, 255 prefix = 4-byte length
- Opening tag: `len_value_type` bits = B'110', closing tag = B'111'
- Fuzz: tag_number=255 with context_specific, len_value_type=0xFFFFFFFF, opening tag without matching closing tag
- Nested constructed types (opening/closing pairs) can cause stack exhaustion if recursive

### Known CVEs in bacnet-stack

**CVE-2019-12480** (CVSS 7.5): Segmentation fault in BACnet APDU layer. Malformed DCC in AtomicWriteFile, AtomicReadFile, and DeviceCommunicationControl services causes invalid read in `bacdcode.c` during parsing of alarm tag numbers. Unauthenticated remote attacker crashes bacserv daemon. Fixed in 0.8.7. PoC: https://www.exploit-db.com/exploits/47148

**CVE-2018-10238**: Buffer overflow in `bvlc_bdt_forward_npdu()` in bacnet-stack bacserv 0.9.1 and 0.8.5. The BVLC forwarding code copies content from the request into a local buffer without bounds checking, overflowing the stack buffer (canary clobbered). Triggered by sending an oversized Forwarded-NPDU BVLC message.

---

## Fuzzer-Relevant Parsing Comparison

| Aspect | bacpypes (Python) | bacnet-stack (C) |
|--------|-------------------|------------------|
| Buffer overflow risk | None (Python) | Yes (C stack/heap buffers) |
| BVLC length validation | Checks `length == remaining + 4` | Returns length but caller must validate |
| NPDU DLEN/SLEN bounds | No max check (reads `dlen` bytes) | Checks `dlen > MAX_MAC_LEN` |
| ASN.1 tag parsing | Python object-based, exception-safe | C with manual bounds tracking |
| BBMD BDT entry limit | Reads until empty (no limit) | Linked list, no inherent limit |
| Forwarded-NPDU | Reads 6-byte IP + remaining data | Historically overflowed (CVE-2018-10238) |
| Error handling | Raises DecodingError exceptions | Returns -1 or 0 bytes consumed |

## Fuzz Mutation Strategy Recommendations

1. **BVLC header**: Type byte != 0x81, function byte 0x0C-0xFF (undefined), length=0, length=0xFFFF, length mismatch with UDP payload
2. **BVLC Forwarded-NPDU**: Oversized NPDU content (>1500 bytes) to test buffer limits
3. **BVLC WriteBDT**: Non-multiple-of-10 payload, 6553+ entries to exhaust BDT table
4. **NPDU control byte**: All 8 bits fuzzed independently, especially bits 5 (dnet), 3 (snet), 7 (net msg)
5. **NPDU DLEN/SLEN**: 0, 1, 7 (MAX_MAC_LEN), 8, 255 -- test bounds checking
6. **NPDU hop count**: 0 (should be dropped), 255, missing when dnet present
7. **ASN.1 tags**: Extended tag number (>14), nested opening/closing pairs (depth 100+), length prefix 255 with 4-byte length > remaining data
8. **APDU services**: AtomicReadFile/AtomicWriteFile with oversized offset/count, DeviceCommunicationControl with malformed tag encoding
9. **Register-Foreign-Device**: TTL=0, TTL=0xFFFF, repeated rapid registration
