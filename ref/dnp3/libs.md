# DNP3 (Distributed Network Protocol 3) - Reference Library Source Code

## Library 1: opendnp3 (dnp3/opendnp3)

- **URL**: https://github.com/dnp3/opendnp3
- **Language**: C++ (C++11)
- **Stars**: 327
- **License**: Apache 2.0
- **Default Branch**: release
- **Status**: End-of-life (September 2022). Succeeded by stepfunc/dnp3 (Rust).
- **Description**: The reference DNP3 (IEEE-1815) protocol stack by Automatak. Modern C++ with bindings for .NET and Java. This is the most widely deployed open-source DNP3 implementation and the one used by Project Robus to test 20+ vendor implementations.

### Key Source Files

| File | Purpose |
|------|---------|
| `cpp/lib/src/link/LinkHeader.h` / `.cpp` | Link layer header: 0x0564 sync bytes, length, control byte (DIR/PRM/FCB/FCV + function code), src/dest addresses, CRC |
| `cpp/lib/src/link/LinkLayerParser.cpp` | State machine parser: FindSync -> ReadHeader -> ReadBody with CRC validation per 16-byte block |
| `cpp/lib/src/link/LinkFrame.cpp` | Link frame construction with block CRC, `FormatHeader()`, `WriteUserData()`, `ValidateBodyCRC()` |
| `cpp/lib/src/transport/TransportRx.cpp` | Transport layer reassembly: FIR/FIN bits, sequence number validation (0-63), buffer overflow protection |
| `cpp/lib/src/app/parsing/ObjectHeaderParser.cpp` | Application layer: group/variation/qualifier extraction from object headers |
| `cpp/lib/src/app/parsing/APDUParser.cpp` | APDU parser: function code dispatch, qualifier code routing (ALL_OBJECTS, UINT8_CNT, UINT16_START_STOP, etc.) |
| `cpp/lib/src/app/APDUHeader.h` / `.cpp` | APDU header struct: control field, function code |
| `cpp/lib/src/app/APDURequest.h` / `.cpp` | Request APDU handling |
| `cpp/lib/src/app/APDUResponse.h` / `.cpp` | Response APDU with IIN (Internal Indications) |
| `cpp/lib/include/opendnp3/app/GroupVariationID.h` | Group/Variation type identifier |
| `cpp/lib/include/opendnp3/link/LinkHeaderFields.h` | Link header field structs |

### Notable Parsing Patterns

**Link Layer State Machine** - three-state parser with CRC validation:

```cpp
// LinkLayerParser.cpp
void LinkLayerParser::OnRead(size_t numBytes, IFrameSink& sink)
{
    buffer.AdvanceWrite(numBytes);
    while (ParseUntilComplete() == State::Complete)
    {
        ++statistics.numLinkFrameRx;
        this->PushFrame(sink);
        state = State::FindSync;
    }
    buffer.Shift();
}

// Sync byte search (0x05, 0x64)
LinkLayerParser::State LinkLayerParser::ParseSync()
{
    if (this->buffer.NumBytesRead() >= 10)
    {
        size_t skipCount = 0;
        const auto synced = buffer.Sync(skipCount);
        if (skipCount > 0)
        {
            FORMAT_LOG_BLOCK(logger, flags::WARN,
                "Skipped %zu bytes seaching for start bytes", skipCount);
        }
        return synced ? State::ReadHeader : State::FindSync;
    }
    return State::FindSync;
}

// Header CRC validation
bool LinkLayerParser::ReadHeader()
{
    header.Read(buffer.ReadBuffer());
    if (CRC::IsCorrectCRC(buffer.ReadBuffer(), LI_CRC))
    {
        return ValidateHeaderParameters();
    }
    else
    {
        ++statistics.numHeaderCrcError;
        return false;
    }
}
```

**Fuzzer observation**: The parser requires 10 bytes minimum before attempting sync. The `Sync()` method scans for 0x0564 and skips garbage bytes. A fuzzer should send frames with valid sync bytes but corrupt headers/CRCs to test the error recovery path.

**Link Header read/write** - fixed byte offsets with endian conversion:

```cpp
// LinkHeader.cpp - Writing link frame header
void LinkHeader::Write(uint8_t* apBuff) const
{
    apBuff[LI_START_05] = 0x05;
    apBuff[LI_START_64] = 0x64;
    apBuff[LI_LENGTH] = length;
    ser4cpp::wseq_t buffer(apBuff + LI_DESTINATION, 4);
    ser4cpp::UInt16::write_to(buffer, dest);
    ser4cpp::UInt16::write_to(buffer, src);
    apBuff[LI_CONTROL] = ctrl;
    CRC::AddCrc(apBuff, LI_CRC);
}

// Reading link frame header
void LinkHeader::Read(const uint8_t* apBuff)
{
    length = apBuff[LI_LENGTH];
    ser4cpp::rseq_t buffer(apBuff + LI_DESTINATION, 4);
    ser4cpp::UInt16::read_from(buffer, dest);
    ser4cpp::UInt16::read_from(buffer, src);
    ctrl = apBuff[LI_CONTROL];
}

bool ValidLength() { return length > 4; }
```

**Fuzzer observation**: Length field must be > 4 (minimum 5 for header-only). Values 0-4 are rejected. The maximum is 255 (uint8). A fuzzer should test boundary values: 0, 4, 5, 254, 255.

**Transport Layer Reassembly** - FIR/FIN handling with sequence validation:

```cpp
// TransportRx.cpp
TransportRx::TransportRx(const Logger& logger, uint32_t maxRxFragSize)
    : logger(logger), rxBuffer(maxRxFragSize), numBytesRead(0) { }

// FIR bit handling - resets in-progress assembly
if (header.fir && this->numBytesRead > 0)
{
    ++statistics.numTransportDiscard;
    this->numBytesRead = 0;
}

// FIN bit - marks completion
if (header.fin) {
    const auto ret = rxBuffer.as_rslice().take(numBytesRead);
    this->numBytesRead = 0;
    return Message(segment.addresses, ret);
}

// Sequence number validation (non-FIR segments)
if (header.seq != this->expectedSeq) {
    ++statistics.numTransportIgnore;
    return Message(); // drop
}
this->expectedSeq.Increment();

// Buffer overflow protection
if (payload.length() > available.length()) {
    ++statistics.numTransportBufferOverflow;
    this->numBytesRead = 0;
    return Message();
}
```

**Fuzzer observation**: Key attack vectors: (1) Send FIR without FIN to start assembly, then never complete it (memory exhaustion). (2) Send segments with sequence numbers that wrap around 0-63 boundary. (3) Send payload that exactly fills `maxRxFragSize` then one more byte. (4) Send FIR segment mid-assembly to force discard.

**Application Layer Object Header Parsing** - group/variation/qualifier extraction:

```cpp
// ObjectHeaderParser.cpp
ParseResult ObjectHeaderParser::ParseObjectHeader(ObjectHeader& header,
                                                   ser4cpp::rseq_t& buffer,
                                                   Logger* pLogger)
{
    if (buffer.length() < 3)
    {
        SIMPLE_LOGGER_BLOCK(pLogger, flags::WARN,
                           "Not enough data for header");
        return ParseResult::NOT_ENOUGH_DATA_FOR_HEADER;
    }

    ser4cpp::UInt8::read_from(buffer, header.group);
    ser4cpp::UInt8::read_from(buffer, header.variation);
    ser4cpp::UInt8::read_from(buffer, header.qualifier);
    return ParseResult::OK;
}

// APDU qualifier dispatch
switch (record.GetQualifierCode())
{
case (QualifierCode::ALL_OBJECTS):
    return HandleAllObjectsHeader(pLogger, record, settings, pHandler);
case (QualifierCode::UINT8_CNT):
    return CountParser::ParseHeader(buffer, NumParser::OneByte(), ...);
case (QualifierCode::UINT16_START_STOP):
    return RangeParser::ParseHeader(buffer, NumParser::TwoByte(), ...);
case (QualifierCode::UINT8_CNT_UINT8_INDEX):
    return CountIndexParser::ParseHeader(buffer, NumParser::OneByte(), ...);
}
```

**Fuzzer observation**: The qualifier code determines how the range/count following the object header is parsed. Sending an unknown qualifier code, or a qualifier code with a count that exceeds the remaining buffer, tests the bounds checking in CountParser and RangeParser.

### Known CVEs / Security Bugs

No CVEs directly against opendnp3 in NVD. However, opendnp3 was the *tool used to find* DNP3 bugs in other implementations (Project Robus). GitHub issues of note:

- **Issue #255**: "Buffer Overflow Bug" - reported buffer overflow in event handling
- **Issue #393**: "Infinite loop when outstation has event buffer overflow" - configuration edge case
- **Issue #122**: "Crash on outstation event buffer update" - null pointer from full event buffer
- **Issue #430**: "Not enough data for specified octet objects" - OctetString parsing edge case

---

## Library 2: stepfunc/dnp3 (Step Function I/O)

- **URL**: https://github.com/stepfunc/dnp3
- **Language**: Rust (with C, C++, .NET, Java bindings)
- **Stars**: 142
- **License**: Non-commercial (source available, requires commercial license for production)
- **Default Branch**: main
- **Description**: The successor to opendnp3 by the same team (Automatak, rebranded as Step Function I/O). Written in safe Rust with zero-copy/zero-allocation parsing. Provides the most modern and memory-safe DNP3 implementation.

### Key Source Files

| File | Purpose |
|------|---------|
| `dnp3/src/link/parser.rs` | Link layer state machine: FindSync1 -> FindSync2 -> ReadHeader -> ReadBody with block CRC validation |
| `dnp3/src/link/crc.rs` | CRC-16 calculation with 0x0564 prefix handling |
| `dnp3/src/transport/real/header.rs` | Transport header: FIR/FIN/SEQ extraction from single byte via bitmasks |
| `dnp3/src/transport/real/assembler.rs` | Fragment reassembly: state machine (Empty/Running/Complete), sequence validation, buffer overflow detection |
| `dnp3/src/transport/real/reader.rs` | Transport reader: bridges link frames to assembled application fragments |
| `dnp3/src/transport/real/sequence.rs` | Sequence number wrapping (0-63) |
| `dnp3/src/app/parse/parser.rs` | Application layer parser: control field, function code, IIN, object header dispatch |
| `dnp3/src/app/parse/count.rs` | Count-based qualifier parsing |
| `dnp3/src/app/parse/range.rs` | Range-based qualifier parsing (start/stop) |
| `dnp3/src/app/parse/prefix.rs` | Prefix-based qualifier parsing (count + index) |
| `dnp3/src/app/parse/free_format.rs` | Free-format qualifier parsing |
| `dnp3/src/app/variations.rs` | Group/Variation lookup table |
| `dnp3/src/app/header.rs` | Application header types |
| `dnp3/src/decode.rs` | Diagnostic decoder |

### Notable Parsing Patterns

**Link Layer Parser** - Rust state machine with two error modes:

```rust
// link/parser.rs
enum ParseState {
    FindSync1,                   // Looking for 0x05
    FindSync2,                   // Looking for 0x64
    ReadHeader,                  // Parse 8-byte header + CRC
    ReadBody(Header, usize),     // Read payload blocks with CRC
}

// Main parse function with error recovery
pub(crate) fn parse(
    &mut self,
    cursor: &mut ReadCursor,
    payload: &mut FramePayload,
) -> Result<Option<Header>, ParseError> {
    loop {
        if self.mode == LinkErrorMode::Close {
            return self.parse_impl(cursor, payload);
        }
        // In Discard mode, skip bytes on error and retry
        let res = cursor.transaction(|cur| self.parse_impl(cur, payload));
        match res {
            Ok(x) => return Ok(x),
            Err(_) => {
                let _ = cursor.read_u8();  // skip one byte
                self.reset();
            }
        }
    }
}
```

**Fuzzer observation**: Two error modes -- `Close` (strict, errors are fatal) and `Discard` (skip garbage, retry). The `Discard` mode's byte-skip-and-retry loop is the more interesting fuzzing target since it exercises error recovery paths.

**Sync byte validation** - strict two-byte check:

```rust
fn parse_sync1(&mut self, cursor: &mut ReadCursor) -> Result<(), ParseError> {
    let x = cursor.read_u8()?;
    if x != 0x05 {
        return Err(FrameError::UnexpectedStart1(x).into());
    }
    self.state = ParseState::FindSync2;
    Ok(())
}

fn parse_sync2(&mut self, cursor: &mut ReadCursor) -> Result<(), ParseError> {
    let x = cursor.read_u8()?;
    if x != 0x64 {
        return Err(FrameError::UnexpectedStart2(x).into());
    }
    self.state = ParseState::ReadHeader;
    Ok(())
}
```

**Header parsing with CRC** - validates 6-byte header + 2-byte CRC:

```rust
fn parse_header(&mut self, cursor: &mut ReadCursor) -> Result<(), ParseError> {
    if cursor.remaining() < 8 {
        return Ok(());  // need more data
    }

    let crc_bytes = cursor.read_bytes(6)?;
    let crc_value = cursor.read_u16_le()?;

    let mut cur = ReadCursor::new(crc_bytes);
    let len = cur.read_u8()?;
    let header = Header::new(
        ControlField::from(cur.read_u8()?),
        AnyAddress::from(cur.read_u16_le()?),
        AnyAddress::from(cur.read_u16_le()?),
    );

    if len < 5 {
        return Err(FrameError::BadLength(len).into());
    }

    let expected_crc = super::crc::calc_crc_with_0564(crc_bytes);
    if crc_value != expected_crc {
        return Err(FrameError::BadHeaderCrc.into());
    }

    let trailer_length = Self::calc_trailer_length(len - 5);
    self.state = ParseState::ReadBody(header, trailer_length);
    Ok(())
}
```

**Fuzzer observation**: The header CRC includes the 0x0564 prefix in calculation. Length < 5 is explicitly rejected. The `calc_trailer_length` computes how many body bytes to expect -- a length field of 5 means zero body bytes, 255 means 250 body bytes split into CRC-checked blocks.

**Body parsing with per-block CRC** - 16 data bytes + 2 CRC per block:

```rust
fn parse_body(
    &mut self,
    trailer_length: usize,
    cursor: &mut ReadCursor,
    payload: &mut FramePayload,
) -> Result<Option<()>, ParseError> {
    if cursor.remaining() < trailer_length {
        return Ok(None);  // need more data
    }

    payload.clear();
    let body = cursor.read_bytes(trailer_length)?;

    for block in body.chunks(18) {  // 16 data + 2 CRC per block
        if block.len() < 3 {
            return Err(LogicError::BadSize.into());
        }

        let data_len = block.len() - 2;
        let (data, crc) = block.np_split_at(data_len)?;
        let crc_value = ReadCursor::new(crc).read_u16_le()?;
        let calc_crc = super::crc::calc_crc(data);

        if crc_value != calc_crc {
            return Err(FrameError::BadBodyCrc.into());
        }

        payload.push(data)?;
    }

    self.state = ParseState::FindSync1;
    Ok(Some(()))
}
```

**Fuzzer observation**: Body is split into chunks of 18 bytes (16 data + 2 CRC). The last block can be shorter. A block < 3 bytes is a logic error. Corrupted CRC in any block rejects the entire frame.

**Transport Header Parsing** - single byte with bitmask extraction:

```rust
// transport/real/header.rs
#[derive(Copy, Clone)]
pub(crate) struct Header {
    pub(crate) fin: bool,
    pub(crate) fir: bool,
    pub(crate) seq: Sequence,
}

pub(crate) fn from_u8(value: u8) -> Self {
    Self {
        fin: value & FIN_MASK != 0,   // bit 7
        fir: value & FIR_MASK != 0,   // bit 6
        seq: Sequence::new(value),     // bits 0-5 (0-63)
    }
}
```

**Transport Assembler** - state machine with FIR/FIN/sequence validation:

```rust
// transport/real/assembler.rs
// FIR bit unconditionally resets assembly state
if header.fir {
    self.state = InternalState::Empty;
}

// Sequence validation for non-FIR segments
if header.seq.value() != previous_header.seq.next() {
    // sequence mismatch -- reset and reject
}

// Source address consistency check
if info != previous_info {
    self.state = InternalState::Empty;
}

// Buffer overflow detection
match cursor.write_bytes(data) {
    // overflow logged, state cleared
}

// FIN triggers completion
if header.fin {
    let frame_id = self.frame_id;
    self.frame_id = self.frame_id.wrapping_add(1);
    self.state = InternalState::Complete(info, new_length);
}
```

**Application Layer Parser** - function code and object header dispatch:

```rust
// app/parse/parser.rs
let control = ControlField::parse(&mut cursor)?;
let raw_func = cursor.read_u8()?;
let function = match FunctionCode::from(raw_func) {
    None => return Err(HeaderParseError::UnknownFunction(control.seq, raw_func)),
    Some(x) => x,
};

// Object header parsing
let gv = Variation::parse(&mut self.cursor)?;  // group (u8) + variation (u8)
let qualifier = QualifierCode::parse(&mut self.cursor)?;

// Qualifier dispatch to specialized parsers
match qualifier {
    QualifierCode::AllObjects       => self.parse_all_objects(gv),
    QualifierCode::Range8           => self.parse_start_stop_u8(gv),
    QualifierCode::Range16          => self.parse_start_stop_u16(gv),
    QualifierCode::Count8           => self.parse_count_u8(gv),
    QualifierCode::Count16          => self.parse_count_u16(gv),
    QualifierCode::CountAndPrefix8  => self.parse_count_and_prefix_u8(gv),
    QualifierCode::CountAndPrefix16 => self.parse_count_and_prefix_u16(gv),
    QualifierCode::FreeFormat16     => self.parse_free_format_u16(gv),
}
```

**Fuzzer observation**: Unknown function codes are immediately rejected. Unknown group/variation combinations also error. The qualifier dispatch is exhaustive -- no default/wildcard case. The safety comes from Rust's type system, but the *logic* of range parsing (start > stop, count exceeding buffer, etc.) is where bugs would hide.

### Known CVEs / Security Bugs

No CVEs against stepfunc/dnp3 in NVD. The Rust memory safety model eliminates buffer overflows and use-after-free. Logic bugs in sequence handling or reassembly timeouts would be the remaining attack surface.

---

## Wire Format Summary (for fuzzer development)

### DNP3 Link Layer Frame (10-byte header + variable body)

```
Offset  Size   Field
------  ----   -----
0       1      Start byte 1 (0x05)
1       1      Start byte 2 (0x64)
2       1      Length (5-255, user data + 5)
3       1      Control (DIR|PRM|FCB|FCV/DFC|FUNC[4bits])
4       2      Destination address (LE uint16)
6       2      Source address (LE uint16)
8       2      CRC-16 of bytes 0-7
--- User Data (in 16-byte blocks, each followed by 2-byte CRC) ---
10      16+2   Block 1 (16 data bytes + CRC-16)
28      16+2   Block 2 (if needed)
...
last    1-16+2 Final block (1-16 data bytes + CRC-16)
```

### DNP3 Transport Header (1 byte, first byte of user data)

```
Bit 7: FIN (final segment)
Bit 6: FIR (first segment)
Bits 5-0: Sequence number (0-63)
```

### DNP3 Application Header (2-4 bytes)

```
Offset  Size   Field
------  ----   -----
0       1      Application Control (FIR|FIN|CON|UNS|SEQ[4bits])
1       1      Function Code (0x00-0x83)
--- Response only ---
2       2      Internal Indications (IIN1 + IIN2)
```

### DNP3 Object Header (3+ bytes, repeats)

```
Offset  Size   Field
------  ----   -----
0       1      Group (e.g., 1=Binary Input, 12=CROB, 30=Analog Input)
1       1      Variation (data encoding within group)
2       1      Qualifier Code (determines range format)
3       var    Range specifier (depends on qualifier: 1-byte start/stop, 2-byte, count, etc.)
var     var    Object data
```

### Primary Fuzzing Targets

1. **Link layer length field**: Values 0-4 (rejected), 5 (empty), 255 (max). Body block count calculation depends on this.
2. **CRC block boundaries**: Non-standard frame sizes where the last block is < 16 bytes.
3. **Transport FIR/FIN combinations**: FIR=0 FIN=1 (single segment arriving as "last" with no prior "first"). FIR=1 FIN=0 followed by nothing (incomplete assembly).
4. **Sequence number wrapping**: Sequence 63 -> 0 transition, out-of-order sequences.
5. **Application object qualifier/count mismatch**: Qualifier says "8-bit count" but count exceeds remaining bytes. Start > Stop in range qualifiers.
6. **Unknown group/variation**: Groups > 120, vendor-specific variations.
7. **File transfer function codes (0x19-0x1E)**: Complex sub-protocol with filename strings and file handles.
8. **Secure Authentication v5**: HMAC and challenge-response parsing adds significant attack surface.
