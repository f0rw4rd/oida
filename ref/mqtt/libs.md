# MQTT Reference Library Source Code

Reference implementations for MQTT broker/client parsing, relevant for fuzzer development.

---

## 1. Eclipse Mosquitto (C)

- **Repository**: https://github.com/eclipse-mosquitto/mosquitto (10.7k stars)
- **Language**: C
- **License**: EPL-2.0 / BSD-3-Clause

### Key Source Files

| File | Purpose |
|------|---------|
| `lib/packet_mosq.c` | Packet allocation, cleanup, queuing, writing |
| `lib/packet_datatypes.c` | Wire primitives: read/write byte, uint16, uint32, varint, string, binary |
| `lib/read_handle.c` | Packet type dispatch (`handle__packet()` -- switch on command nibble) |
| `lib/handle_publish.c` | Client-side PUBLISH handling |
| `src/handle_connect.c` | **Server-side** CONNECT packet parsing (auth, will, client ID) |
| `src/handle_publish.c` | **Server-side** PUBLISH processing (topic validation, QoS state) |
| `src/handle_subscribe.c` | **Server-side** SUBSCRIBE parsing (topic filter + QoS pairs) |
| `src/handle_disconnect.c` | Server-side DISCONNECT (MQTTv5 reason codes + properties) |
| `lib/handle_connack.c` | Client-side CONNACK handling |
| `src/property_broker.c` | MQTTv5 property validation on broker side |

### Notable Parsing Patterns

**Packet Type Dispatch** (`lib/read_handle.c`):

The top 4 bits of the first byte determine the packet type. The broker dispatches to type-specific handlers:

```c
int handle__packet(struct mosquitto *mosq)
{
    int rc = MOSQ_ERR_INVAL;

    switch((mosq->in_packet.command)&0xF0){
        case CMD_PINGREQ:
            rc = handle__pingreq(mosq);
            break;
        case CMD_PINGRESP:
            rc = handle__pingresp(mosq);
            break;
        case CMD_PUBACK:
            rc = handle__pubackcomp(mosq, "PUBACK");
            break;
        case CMD_PUBLISH:
            rc = handle__publish(mosq);
            break;
        case CMD_CONNACK:
            rc = handle__connack(mosq);
            break;
        /* ... other types ... */
        default:
            log__printf(mosq, MOSQ_LOG_ERR,
                "Error: Unrecognised command %d\n",
                (mosq->in_packet.command)&0xF0);
            rc = MOSQ_ERR_PROTOCOL;
            break;
    }

    if(mosq->protocol == mosq_p_mqtt5){
        if(rc == MOSQ_ERR_PROTOCOL || rc == MOSQ_ERR_DUPLICATE_PROPERTY){
            send__disconnect(mosq, MQTT_RC_PROTOCOL_ERROR, NULL);
        }else if(rc == MOSQ_ERR_MALFORMED_PACKET || rc == MOSQ_ERR_MALFORMED_UTF8){
            send__disconnect(mosq, MQTT_RC_MALFORMED_PACKET, NULL);
        }
        /* ... more error mapping ... */
    }
    return rc;
}
```

Key observations for fuzzing:
- Bottom 4 bits of command byte are flags (DUP, QoS, RETAIN) -- fuzz reserved flag bits
- Invalid packet type (0x00, 0xF0) goes to default handler
- MQTTv5 sends DISCONNECT on parse errors -- this is itself parseable, creating recursive attack surface

**Wire Primitive Readers** (`lib/packet_datatypes.c`):

These are the building blocks. Every field read goes through these bounds-checked functions:

```c
int packet__read_byte(struct mosquitto__packet_in *packet, uint8_t *byte)
{
    if(packet->pos+1 > packet->remaining_length){
        return MOSQ_ERR_MALFORMED_PACKET;
    }
    *byte = packet->payload[packet->pos];
    packet->pos++;
    return MOSQ_ERR_SUCCESS;
}

int packet__read_uint16(struct mosquitto__packet_in *packet, uint16_t *word)
{
    if(packet->pos+2 > packet->remaining_length){
        return MOSQ_ERR_MALFORMED_PACKET;
    }
    memcpy(&val, &packet->payload[packet->pos], sizeof(uint16_t));
    packet->pos += sizeof(uint16_t);
    *word = ntohs(val);
    return MOSQ_ERR_SUCCESS;
}

int packet__read_string(struct mosquitto__packet_in *packet, char **str, uint16_t *length)
{
    rc = packet__read_binary(packet, (uint8_t **)str, length);
    if(rc) return rc;
    if(*length == 0) return MOSQ_ERR_SUCCESS;

    if(mosquitto_validate_utf8(*str, *length)){
        mosquitto_FREE(*str);
        *length = 0;
        return MOSQ_ERR_MALFORMED_UTF8;
    }
    return MOSQ_ERR_SUCCESS;
}

int packet__read_binary(struct mosquitto__packet_in *packet, uint8_t **data, uint16_t *length)
{
    uint16_t slen;
    rc = packet__read_uint16(packet, &slen);
    if(rc) return rc;

    if(slen == 0){
        *data = NULL;
        *length = 0;
        return MOSQ_ERR_SUCCESS;
    }
    if(packet->pos+slen > packet->remaining_length){
        return MOSQ_ERR_MALFORMED_PACKET;
    }
    *data = mosquitto_malloc(slen+1U);
    if(*data){
        memcpy(*data, &(packet->payload[packet->pos]), slen);
        ((uint8_t *)(*data))[slen] = '\0';
        packet->pos += slen;
    }else{
        return MOSQ_ERR_NOMEM;
    }
    *length = slen;
    return MOSQ_ERR_SUCCESS;
}
```

Key observations for fuzzing:
- All reads are bounds-checked against `remaining_length` -- the remaining_length itself must be correct
- `packet__read_binary` allocates `slen+1` bytes -- when `slen=0xFFFF`, allocation is 65536 bytes
- `packet__read_string` validates UTF-8 -- malformed UTF-8 sequences trigger a free+error path
- Zero-length binary data returns `*data = NULL` -- callers must handle NULL

**Variable-Length Integer (Remaining Length) Decoding** (`lib/packet_datatypes.c`):

```c
int packet__read_varint(struct mosquitto__packet_in *packet, uint32_t *word, uint8_t *bytes)
{
    int i;
    uint8_t byte;
    unsigned int remaining_mult = 1;
    uint32_t lword = 0;
    uint8_t lbytes = 0;

    for(i=0; i<4; i++){
        if(packet->pos < packet->remaining_length){
            lbytes++;
            byte = packet->payload[packet->pos];
            lword += (byte & 127) * remaining_mult;
            remaining_mult *= 128;
            packet->pos++;
            if((byte & 128) == 0){
                if(lbytes > 1 && byte == 0){
                    /* Catch overlong encodings */
                    return MOSQ_ERR_MALFORMED_PACKET;
                }else{
                    *word = lword;
                    if(bytes) (*bytes) = lbytes;
                    return MOSQ_ERR_SUCCESS;
                }
            }
        }else{
            return MOSQ_ERR_MALFORMED_PACKET;
        }
    }
    return MOSQ_ERR_MALFORMED_PACKET;
}
```

Key observations for fuzzing:
- Max 4 iterations (4 bytes, 7 bits each = 28 bits = max 268,435,455)
- Catches overlong encodings (continuation byte followed by 0x00)
- `remaining_mult *= 128` -- after 4 iterations, `remaining_mult = 128^3 = 2,097,152`
- Fuzz: continuation bit set on 4th byte (would need 5th byte), overlong encodings, value=0 with multi-byte encoding

**Packet Allocation Based on Remaining Length** (`lib/packet_mosq.c`):

```c
int packet__alloc(struct mosquitto__packet **packet, uint8_t command,
                  uint32_t remaining_length)
{
    uint8_t remaining_bytes[5] = {0}, byte;
    int8_t remaining_count;
    uint32_t packet_length;

    remaining_count = 0;
    do{
        byte = remaining_length % 128;
        remaining_length = remaining_length / 128;
        if(remaining_length > 0){
            byte = byte | 0x80;
        }
        remaining_bytes[remaining_count] = byte;
        remaining_count++;
    }while(remaining_length > 0 && remaining_count < 5);
    if(remaining_count == 5){
        return MOSQ_ERR_PAYLOAD_SIZE;
    }

    packet_length = remaining_length_stored + 1 + (uint8_t)remaining_count;
    (*packet) = mosquitto_malloc(
        sizeof(struct mosquitto__packet) + packet_length + WS_PACKET_OFFSET);
    /* ... */
}
```

Key observations for fuzzing:
- Allocation size depends on remaining_length -- fuzz with large values to test OOM handling
- `remaining_count == 5` catches overflow (>4 VBI bytes), but is this reachable from wire input?

### Known CVEs in Mosquitto (Parsing-Relevant)

**CVE-2021-34432** (CVSS 7.5): NULL deref / crash when broker receives PUBLISH with zero-length topic (`topic_len=0`). The topic pointer becomes NULL and is dereferenced in the subscription matching code.

**CVE-2023-0809** (CVSS 7.5): Excessive memory allocation when a client's first packet is not CONNECT. The broker allocated memory based on the remaining_length of non-CONNECT packets before validating the connection state.

**CVE-2023-3592** (CVSS 7.5): Memory leak when clients send MQTTv5 CONNECT with will messages containing invalid property types. The property parsing allocated memory that was never freed on the error path.

**CVE-2023-28366** (CVSS 7.5): Memory leak from QoS 2 messages with duplicate message IDs that are never acknowledged. Not strictly a parsing bug but triggered by specific wire sequences.

**CVE-2024-3935**: Clients could send CONNECT with will delay properties that could crash the broker during will message delivery.

**CVE-2024-10525**: The broker could be crashed by clients with specific keepalive and session expiry combinations.

---

## 2. Eclipse Paho MQTT Python (Python)

- **Repository**: https://github.com/eclipse-paho/paho.mqtt.python (2.4k stars)
- **Language**: Python 3.7+
- **License**: EPL-2.0 / BSD-3-Clause

### Key Source Files

| File | Purpose |
|------|---------|
| `src/paho/mqtt/client.py` | Complete client: `_packet_read()`, `_packet_handle()`, `_pack_remaining_length()` |
| `src/paho/mqtt/properties.py` | MQTTv5 property encoding/decoding |
| `src/paho/mqtt/packettypes.py` | Packet type constants |
| `src/paho/mqtt/reasoncodes.py` | MQTTv5 reason code mapping |
| `src/paho/mqtt/subscribe.py` | Simple subscribe API |

### Notable Parsing Patterns

**Packet Reading and Remaining Length Decoding** (`src/paho/mqtt/client.py`):

This is the client-side packet reader. It reads from the socket incrementally:

```python
def _packet_read(self) -> MQTTErrorCode:
    # Step 1: Read command byte (1 byte)
    if self._in_packet['command'] == 0:
        try:
            command = self._sock_recv(1)
        except BlockingIOError:
            return MQTTErrorCode.MQTT_ERR_AGAIN
        except OSError as err:
            return MQTTErrorCode.MQTT_ERR_CONN_LOST
        else:
            if len(command) == 0:
                return MQTTErrorCode.MQTT_ERR_CONN_LOST
            self._in_packet['command'] = command[0]

    # Step 2: Read remaining length (variable-length integer)
    if self._in_packet['have_remaining'] == 0:
        while True:
            try:
                byte = self._sock_recv(1)
            except BlockingIOError:
                return MQTTErrorCode.MQTT_ERR_AGAIN
            except OSError as err:
                return MQTTErrorCode.MQTT_ERR_CONN_LOST
            else:
                if len(byte) == 0:
                    return MQTTErrorCode.MQTT_ERR_CONN_LOST
                byte_value = byte[0]
                self._in_packet['remaining_count'].append(byte_value)
                # Max 4 bytes length for remaining length
                if len(self._in_packet['remaining_count']) > 4:
                    return MQTTErrorCode.MQTT_ERR_PROTOCOL

                self._in_packet['remaining_length'] += (
                    byte_value & 127) * self._in_packet['remaining_mult']
                self._in_packet['remaining_mult'] *= 128

            if (byte_value & 128) == 0:
                break

        self._in_packet['have_remaining'] = 1
        self._in_packet['to_process'] = self._in_packet['remaining_length']

    # Step 3: Read payload in chunks
    count = 100  # Don't get stuck in this loop for huge messages
    while self._in_packet['to_process'] > 0:
        try:
            data = self._sock_recv(self._in_packet['to_process'])
        except BlockingIOError:
            return MQTTErrorCode.MQTT_ERR_AGAIN
        except OSError as err:
            return MQTTErrorCode.MQTT_ERR_CONN_LOST
        else:
            if len(data) == 0:
                return MQTTErrorCode.MQTT_ERR_CONN_LOST
            self._in_packet['to_process'] -= len(data)
            self._in_packet['packet'] += data
        count -= 1
        if count == 0:
            return MQTTErrorCode.MQTT_ERR_AGAIN

    # All data read -- dispatch to handler
    self._in_packet['pos'] = 0
    rc = self._packet_handle()
    # Reset state for next packet
    self._in_packet = {
        "command": 0, "have_remaining": 0, "remaining_count": [],
        "remaining_mult": 1, "remaining_length": 0,
        "packet": bytearray(b""), "to_process": 0, "pos": 0,
    }
    return rc
```

Key observations for fuzzing:
- `remaining_count > 4` check correctly limits VBI to 4 bytes
- `remaining_mult` grows as 1, 128, 16384, 2097152 -- no overflow in Python (arbitrary precision)
- `count = 100` limits read iterations per call -- a large remaining_length causes MQTT_ERR_AGAIN
- The `packet` bytearray grows unboundedly -- remaining_length of 268M would allocate 256MB
- No overlong encoding check (unlike Mosquitto which catches `lbytes > 1 && byte == 0`)

**Remaining Length Encoding** (`src/paho/mqtt/client.py`):

```python
def _pack_remaining_length(self, packet: bytearray, remaining_length: int):
    while True:
        byte = remaining_length % 128
        remaining_length = remaining_length // 128
        if remaining_length > 0:
            byte = byte | 0x80
        packet.append(byte)
        if remaining_length == 0:
            break
```

Key observations for fuzzing:
- This is the client's encoder -- no upper bound check
- A buggy caller could pass remaining_length > 268,435,455 causing 5+ VBI bytes

### Known CVEs in Paho MQTT Python

No CVEs assigned specifically to the Python paho-mqtt client at time of writing. As a client library (not a broker), its parsing attack surface is limited to server responses. The library is pure Python, so no memory corruption is possible, but crafted server responses could cause:
- Excessive memory allocation via large remaining_length
- Unhandled exceptions from malformed UTF-8 topics
- Infinite loops from pathological VBI encoding

---

## Fuzzer-Relevant Parsing Comparison

| Aspect | Mosquitto (C broker) | Paho MQTT Python (client) |
|--------|---------------------|---------------------------|
| Buffer overflow risk | Yes (C heap/stack) | No (Python memory safety) |
| Remaining length VBI | Max 4 bytes, catches overlong | Max 4 bytes, no overlong check |
| String reading | Bounds-checked + UTF-8 validated | UTF-8 decode can raise exceptions |
| Memory allocation | Controlled by max_packet_size | Unbounded (allocates up to remaining_length) |
| Zero-length fields | Historically caused crashes (CVE-2021-34432) | Returns empty bytes/None |
| Property parsing (v5) | Complex, led to CVE-2023-3592 | Simpler, raises on unknown |
| Connection state | Must be CONNECT first (CVE-2023-0809 fixed) | Client assumes valid server |

## Fuzz Mutation Strategy Recommendations

1. **Remaining length VBI**: 0x00, 0xFF 0xFF 0xFF 0x7F (max), 0x80 0x80 0x80 0x80 (continuation on 4th), 0x80 0x00 (overlong zero)
2. **CONNECT packet**: Zero-length client ID, conflicting flags (will_flag=0 but will_qos=2), username_flag=1 with no username payload
3. **PUBLISH packet**: topic_len=0, topic with embedded NULLs, topic with only wildcards (# or +)
4. **SUBSCRIBE packet**: Extremely long topic filter strings, deeply nested / separators, mixed wildcards
5. **MQTTv5 properties**: Unknown property IDs, duplicate properties where only one allowed, property_length that exceeds remaining data
6. **First packet**: Send PUBLISH/SUBSCRIBE before CONNECT to test connection state validation
7. **QoS 2 state machine**: Duplicate message IDs, out-of-order PUBREC/PUBREL/PUBCOMP
