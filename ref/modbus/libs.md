# Modbus Reference Library Source Code

Reference implementations for Modbus TCP/RTU parsing, relevant for fuzzer development.

---

## 1. pymodbus (Python)

- **Repository**: https://github.com/pymodbus-dev/pymodbus (2.6k stars)
- **Language**: Python 3.10+
- **License**: BSD-3-Clause

### Key Source Files

| File | Purpose |
|------|---------|
| `pymodbus/framer/socket.py` | MBAP header encode/decode for Modbus TCP |
| `pymodbus/framer/rtu.py` | RTU framing with CRC-16 |
| `pymodbus/framer/base.py` | Base framer with PDU dispatch (handleFrame) |
| `pymodbus/pdu/register_message.py` | Register read/write request decode (FC 3,4,6,16,23) |
| `pymodbus/pdu/bit_message.py` | Coil/discrete read/write decode (FC 1,2,5,15) |
| `pymodbus/pdu/decoders.py` | Function code -> PDU class lookup table |
| `pymodbus/pdu/mei_message.py` | MEI (FC 0x2B) Device Identification decode |
| `pymodbus/pdu/diag_message.py` | Diagnostics (FC 0x08) sub-function decode |

### Notable Parsing Patterns

**MBAP Header Parsing** (`pymodbus/framer/socket.py`):

The socket framer reads a 7-byte MBAP header: `[tid:2][pid:2][length:2][uid:1]`. The `length` field drives how much data to read. No upper-bound validation on the length field -- it trusts whatever the wire says.

```python
class FramerSocket(FramerBase):
    """Modbus Socket frame type.

    Layout::
        [         MBAP Header         ] [ Function Code] [ Data ]
        [ tid ][ pid ][ length ][ uid ]
          2b     2b     2b        1b           1b           Nb

    length = uid + function code + data
    """
    MIN_SIZE = 8

    def decode(self, data: bytes) -> tuple[int, int, int, bytes]:
        """Decode ADU."""
        if (data_len := len(data)) < self.MIN_SIZE:
            Log.debug("Very short frame (NO MBAP): {} wait for more data", data, ":hex")
            return 0, 0, 0, self.EMPTY
        tid = int.from_bytes(data[0:2], 'big')
        if (pid := int.from_bytes(data[2:4], 'big')):
            Log.error("Invalid Modbus protocol id: {}", pid)
            return 0, 0, 0, self.EMPTY
        msg_len = int.from_bytes(data[4:6], 'big') + 6
        dev_id = int(data[6])
        if data_len < msg_len:
            Log.debug("Short frame: {} wait for more data", data, ":hex")
            return 0, 0, 0, self.EMPTY
        if msg_len == 8 and data_len == 9:
            msg_len = 9
        return msg_len, dev_id, tid, data[7:msg_len]
```

Key observations for fuzzing:
- `msg_len` is derived directly from wire bytes (`data[4:6]`), added to 6
- No maximum length check -- a length of 0xFFFF would compute `msg_len = 65541`
- Protocol ID must be 0x0000, so fuzz it to non-zero to test error handling paths
- The `msg_len == 8 and data_len == 9` special case is a quirk that extends the frame

**RTU CRC-16 Validation** (`pymodbus/framer/rtu.py`):

RTU framing has no length prefix, so the framer must infer frame boundaries from the function code. CRC-16 is the only integrity check.

```python
class FramerRTU(FramerBase):
    MIN_SIZE = 4  # <device id><function code><crc 2 bytes>

    def decode(self, data: bytes) -> tuple[int, int, int, bytes]:
        """Decode ADU."""
        data_len = len(data)
        for used_len in range(data_len):
            if data_len - used_len < self.MIN_SIZE:
                return 0, 0, 0, self.EMPTY
            dev_id = int(data[used_len])
            if self.device_ids and dev_id not in self.device_ids:
                return data_len, 0, 0, self.EMPTY
            if not (pdu_class := self.decoder.lookupPduClass(data[used_len:])):
                continue
            if not (size := pdu_class.calculateRtuFrameSize(data[used_len:])):
                return 0, dev_id, 0, self.EMPTY
            if data_len < used_len + size:
                return 0, dev_id, 0, self.EMPTY
            for test_len in range(data_len, used_len + size - 1, -1):
                start_crc = test_len - 2
                crc = data[start_crc : start_crc + 2]
                crc_val = (int(crc[0]) << 8) + int(crc[1])
                if not FramerRTU.check_CRC(data[used_len : start_crc], crc_val):
                    continue
                return data_len, dev_id, 0, data[used_len + 1 : start_crc]
        return 0, 0, 0, self.EMPTY
```

Key observations for fuzzing:
- `calculateRtuFrameSize` uses function-code-specific size logic -- fuzz with unknown FCs
- CRC validation iterates backwards from the end, so garbled trailing data triggers retries
- The `lookupPduClass` dispatch is based on the function code byte -- invalid FCs return None

**WriteMultipleRegisters (FC 16) Decode** (`pymodbus/pdu/register_message.py`):

The classic byte_count vs. count mismatch target:

```python
class WriteMultipleRegistersRequest(ModbusPDU):
    function_code = 16
    rtu_byte_count_pos = 6

    def decode(self, data: bytes) -> None:
        """Decode a write single register packet packet request."""
        self.address, self.count, _byte_count = struct.unpack(">HHB", data[:5])
        self.registers = []
        for idx in range(5, (self.count * 2) + 5, 2):
            self.registers.append(struct.unpack(">H", data[idx : idx + 2])[0])
```

Key observations for fuzzing:
- `_byte_count` is read but NEVER used -- the loop uses `self.count * 2` instead
- If `count * 2` exceeds remaining `data` length, `struct.unpack` raises on short buffer
- A `count` of 0xFFFF with a small payload tests the loop upper bound (65535 * 2 = 131070)
- `address + count` wrapping around 0xFFFF is not checked here (checked later in datastore_update)

**ReadWriteMultipleRegisters (FC 23) Decode**:

```python
class ReadWriteMultipleRegistersRequest(ModbusPDU):
    function_code = 23
    rtu_byte_count_pos = 10

    def decode(self, data: bytes) -> None:
        (self.read_address, self.read_count, self.write_address,
         self.write_count, self.write_byte_count,
        ) = struct.unpack(">HHHHB", data[:9])
        self.write_registers = []
        for i in range(9, self.write_byte_count + 9, 2):
            register = struct.unpack(">H", data[i : i + 2])[0]
            self.write_registers.append(register)
```

Key observations for fuzzing:
- This one DOES use `write_byte_count` for the loop, but does not validate `write_byte_count == write_count * 2`
- Mismatched `write_byte_count` and `write_count` is the classic trigger
- Odd `write_byte_count` causes `struct.unpack(">H")` to read one extra byte

### Known CVEs in pymodbus

No CVEs assigned specifically to pymodbus at time of writing. The library is pure Python, so buffer overflows are not applicable. However, the parsing patterns above (trusted length fields, unchecked count/byte_count mismatches) can cause unhandled exceptions that crash a pymodbus server.

---

## 2. libmodbus (C)

- **Repository**: https://github.com/stephane/libmodbus (4.1k stars)
- **Language**: C
- **License**: LGPL-2.1

### Key Source Files

| File | Purpose |
|------|---------|
| `src/modbus.c` | Core: `modbus_reply()`, `_modbus_receive_msg()`, response length computation |
| `src/modbus-tcp.c` | TCP transport: MBAP header build/parse, `_modbus_tcp_check_integrity()` |
| `src/modbus-rtu.c` | RTU transport: CRC computation, serial framing |
| `src/modbus-private.h` | Internal structures: `modbus_backend_t`, `_modbus` context struct |
| `src/modbus.h` | Public API: constants like `MODBUS_MAX_READ_REGISTERS`, `MAX_MESSAGE_LENGTH` |
| `src/modbus-data.c` | Data conversion helpers (float, 16/32-bit register packing) |

### Notable Parsing Patterns

**Three-Step Receive State Machine** (`src/modbus.c`):

libmodbus parses incoming messages in three steps: FUNCTION, META, DATA. This is where most CVEs live.

```c
#define MAX_MESSAGE_LENGTH 260

typedef enum {
    _STEP_FUNCTION,
    _STEP_META,
    _STEP_DATA
} _step_t;

int _modbus_receive_msg(modbus_t *ctx, uint8_t *msg, msg_type_t msg_type)
{
    /* ... setup ... */
    step = _STEP_FUNCTION;
    length_to_read = ctx->backend->header_length + 1;

    while (length_to_read != 0) {
        rc = ctx->backend->recv(ctx, msg + msg_length, length_to_read);
        /* ... error handling ... */
        msg_length += rc;
        length_to_read -= rc;

        if (length_to_read == 0) {
            switch (step) {
            case _STEP_FUNCTION:
                length_to_read = compute_meta_length_after_function(
                    msg[ctx->backend->header_length], msg_type);
                if (length_to_read != 0) {
                    step = _STEP_META;
                    break;
                } /* else switches straight to the next step */
            case _STEP_META:
                length_to_read = compute_data_length_after_meta(ctx, msg, msg_type);
                if ((msg_length + length_to_read) > ctx->backend->max_adu_length) {
                    errno = EMBBADDATA;
                    _error_print(ctx, "too many data");
                    return -1;
                }
                step = _STEP_DATA;
                break;
            default:
                break;
            }
        }
    }
    return ctx->backend->check_integrity(ctx, msg, msg_length);
}
```

Key observations for fuzzing:
- `msg` is a stack buffer of `MAX_MESSAGE_LENGTH` (260 bytes)
- The overflow check `msg_length + length_to_read > max_adu_length` exists but uses `max_adu_length` from the backend
- `compute_data_length_after_meta` reads a byte count from the wire (see below)

**Data Length from Wire Byte Count** (`src/modbus.c`):

```c
static int compute_data_length_after_meta(modbus_t *ctx, uint8_t *msg, msg_type_t msg_type)
{
    int function = msg[ctx->backend->header_length];
    int length;

    if (msg_type == MSG_INDICATION) {
        switch (function) {
        case MODBUS_FC_WRITE_MULTIPLE_COILS:
        case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
            length = msg[ctx->backend->header_length + 5];
            break;
        case MODBUS_FC_WRITE_AND_READ_REGISTERS:
            length = msg[ctx->backend->header_length + 9];
            break;
        default:
            length = 0;
        }
    } else {
        /* MSG_CONFIRMATION */
        if (function <= MODBUS_FC_READ_INPUT_REGISTERS ||
            function == MODBUS_FC_REPORT_SLAVE_ID ||
            function == MODBUS_FC_WRITE_AND_READ_REGISTERS) {
            length = msg[ctx->backend->header_length + 1];
        } else {
            length = 0;
        }
    }
    length += ctx->backend->checksum_length;
    return length;
}
```

Key observations for fuzzing:
- For FC 15/16 INDICATION: data length is a single byte from `msg[offset + 5]` -- max 255
- For FC 23 INDICATION: data length from `msg[offset + 9]` -- max 255
- Combined with header, this CAN exceed `MAX_MESSAGE_LENGTH` (260) if not checked properly
- The `max_adu_length` check in `_modbus_receive_msg` catches most cases, but edge cases with exactly-sized buffers have led to CVEs

**modbus_reply() -- The CVE Hotspot** (`src/modbus.c`):

This 200+ line function dispatches by function code and builds responses. The FC 16 handler:

```c
int modbus_reply(modbus_t *ctx, const uint8_t *req, int req_length,
                 modbus_mapping_t *mb_mapping)
{
    uint8_t rsp[MAX_MESSAGE_LENGTH];
    /* ... */
    offset = ctx->backend->header_length;
    function = req[offset];
    address = (req[offset + 1] << 8) + req[offset + 2];

    switch (function) {
    /* ... */
    case MODBUS_FC_WRITE_MULTIPLE_REGISTERS: {
        int nb = (req[offset + 3] << 8) + req[offset + 4];
        int mapping_address = address - mb_mapping->start_registers;

        if (nb < 1 || MODBUS_MAX_WRITE_REGISTERS < nb) {
            /* exception response */
        } else if (mapping_address < 0 || (mapping_address + nb) > nb_registers) {
            /* exception response */
        } else {
            int i, j;
            rsp_length = ctx->backend->build_response_basis(&sft, rsp);
            rsp[rsp_length++] = address >> 8;
            rsp[rsp_length++] = address & 0x00FF;
            rsp[rsp_length++] = nb >> 8;
            rsp[rsp_length++] = nb & 0x00FF;

            for (i = mapping_address, j = 6; i < mapping_address + nb; i++, j += 2) {
                mb_mapping->tab_registers[i] =
                    (req[offset + j] << 8) + req[offset + j + 1];
            }
        }
    } break;
```

Key observations for fuzzing:
- `nb` comes from the wire (2 bytes at offset+3,4), checked against `MODBUS_MAX_WRITE_REGISTERS`
- The loop reads from `req[offset + j]` where j starts at 6 -- if req is short, this reads past the buffer
- CVE-2024-10918 was a stack overflow because `req_length` was not validated against `nb` before the copy loop

**MBAP Header Building** (`src/modbus-tcp.c`):

```c
static int _modbus_tcp_build_request_basis(
    modbus_t *ctx, int function, int addr, int nb, uint8_t *req)
{
    modbus_tcp_t *ctx_tcp = ctx->backend_data;

    if (ctx_tcp->t_id < UINT16_MAX)
        ctx_tcp->t_id++;
    else
        ctx_tcp->t_id = 0;
    req[0] = ctx_tcp->t_id >> 8;
    req[1] = ctx_tcp->t_id & 0x00ff;
    req[2] = 0;  /* Protocol Modbus */
    req[3] = 0;
    /* Length will be defined later at offsets 4 and 5 */
    req[6] = ctx->slave;
    req[7] = function;
    req[8] = addr >> 8;
    req[9] = addr & 0x00ff;
    req[10] = nb >> 8;
    req[11] = nb & 0x00ff;

    return _MODBUS_TCP_PRESET_REQ_LENGTH;
}

static int _modbus_tcp_check_integrity(modbus_t *ctx, uint8_t *msg, const int msg_length)
{
    return msg_length;  /* TCP has no checksum -- always passes */
}
```

Key observations for fuzzing:
- TCP integrity check is a no-op (`return msg_length`) -- no CRC, no checksum
- Length field at bytes [4:5] is set AFTER building the request in `_modbus_tcp_send_msg_pre()`
- For fuzzing: craft packets where MBAP length field disagrees with actual payload size

### Known CVEs in libmodbus

**CVE-2024-10918** (CVSS 4.8): Stack-based buffer overflow in `modbus_reply()`. A Modbus request with unexpected length causes stack buffer overflow when the function copies request data into the `rsp[MAX_MESSAGE_LENGTH]` stack buffer without validating `req_length` against the expected size. Fixed in 3.1.11.

**CVE-2022-0367** (CVSS 7.8): Heap-based buffer overflow in `modbus_reply()` in libmodbus <= 3.1.6. Writing to registers triggers a heap overflow due to insufficient bounds checking of the number of registers.

**CVE-2023-26793**: Heap-based buffer overflow in `read_io_status()` in libmodbus 3.1.10.

---

## Fuzzer-Relevant Parsing Comparison

| Aspect | pymodbus (Python) | libmodbus (C) |
|--------|-------------------|---------------|
| MBAP length handling | No max check, relies on buffering | Checked against `max_adu_length` (260) |
| FC 16 byte_count validation | Reads `_byte_count` but ignores it, uses `count` | Uses byte from wire for data length |
| Buffer overflow risk | None (Python memory safety) | Stack buffer `rsp[260]`, historically exploited |
| CRC validation (RTU) | Tries multiple offsets, bruteforces from end | Standard CRC-16 check |
| Exception response (0x80) | PDU class lookup handles high-bit FCs | Checked in `check_confirmation()` with `function >= 0x80` |
| Integer overflow in address calc | Python ints are arbitrary precision | `address + nb` can wrap on 16-bit |

## Fuzz Mutation Strategy Recommendations

1. **MBAP length field**: Set to 0, 1, 0xFFFF, and values that are +/- 1 from actual payload size
2. **Function code**: 0x00, 0x7F, 0x80, 0xFF, and all valid FCs with wrong payload sizes
3. **FC 16 payload**: Set `count` and `byte_count` to mismatched values (count=100, byte_count=3)
4. **FC 23 payload**: Mutate `write_byte_count` independently of `write_count`
5. **RTU CRC**: Valid CRC with corrupted payload, invalid CRC with valid payload
6. **Protocol ID**: Non-zero values in bytes [2:3] of MBAP header
7. **Unit ID**: 0 (broadcast), 248-254 (reserved), 255 (TCP default)
