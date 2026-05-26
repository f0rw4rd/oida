# MMS (IEC 61850) — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/mms.py` |
| Boofuzz class | `MMSFuzzer` (BaseFuzzer) |
| Requests | 14 |
| Mutation depth | 17 fuzzable : 1 default : 63 Static (**lowest fuzzable count for P0**) |
| State machine | None |
| Test coverage | `tests/unit/fuzz/test_mms_fuzzer.py`, `test_mms_fuzzer_integration.py`. Benchmark `(20, 1500, 25)`. |

## CVE patterns covered

See `ref/mms/cves/README.md`. MMS sits on TPKT (port 102) over OSI ISO
8073/8473; CVEs cluster around the ASN.1 BER decoder, the TPKT/COTP
framing, and per-service parser bugs:

| CVE pattern | MMS fuzzer request | Covered? |
|---|---|---|
| TPKT length / version field abuse | `MMS_TPKT_Mutation` | ✓ |
| COTP TPDU type / TSAP parameter parsing | `MMS_COTP_Mutation` | ✓ |
| ASN.1 BER length encoding (indefinite, > 4 bytes) | `MMS_ASN1_Length` | ✓ |
| ASN.1 BER tag-class confusion | covered via `Group()` over tag bytes | ✓ |
| Initiate-RequestPDU — proposed parameter values | `MMS_Initiate` | ✓ |
| Read service — variable list parsing | `MMS_Read` | ✓ |
| Write service — value-list type/length mismatch | `MMS_Write` | ✓ |
| GetNameList — object class enumeration | `MMS_GetNameList` | ✓ |
| FileDirectory / FileOpen / FileRead | `MMS_File_*` | ✓ |
| GOOSE Control Block enumeration (via MMS, not GOOSE proper) | `MMS_GoCB` | ✓ |

## Audit observation: low fuzzable count for P0

17 fuzzable fields against 63 Static is the lowest mutation-depth
profile among P0 protocols. The audit recommendation (S2) was to
introduce `ASN1Primitive`-based requests that mutate at the ASN.1
encoding layer rather than at the application semantic layer.

The current fuzzer treats most ASN.1 tag/length bytes as `Static` —
which means malformed BER (a real bug class — see `libiec61850`
CVE history) is *not* exercised. The ASN.1 length-encoding request
`MMS_ASN1_Length` is the only one varying these.

## Optimization recommendations

1. **`MMS_BER_Tag_Confusion` request.** Take a valid MMS PDU template,
   replace the outer SEQUENCE tag with `Group(values=[0x30, 0x31, 0x80,
   0xA0, 0xA1, 0xC0])`. Targets ASN.1 BER parsers that don't validate
   constructed vs. primitive bits.
2. **Indefinite-length BER request.** Some ASN.1 decoders mishandle
   `0x80` (indefinite length) followed by `00 00` (end-of-contents) at
   wrong nesting depths. Single request, high yield.
3. **GoCB (GOOSE Control Block) parameter sweep.** The
   `MMS_GoCB` request enumerates GoCB references but doesn't fuzz the
   parameters (MinTime, MaxTime, DatSet, GoID). Adding `Group()`s on
   those four catches the IEC 61850 GoCB-attribute parser bugs that
   show up in vendor MMS stacks.
