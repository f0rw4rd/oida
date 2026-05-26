# CVE Pattern Schema for Fuzzer Consumption

Each `ref/<proto>/cve_patterns.json` enumerates *fuzzer-findable* bug
classes for that protocol — input-validation, length-confusion, encoding-
abuse, state-confusion bugs that a black-box fuzzer can hit. Auth-bypass
via stolen credentials, key-recovery via side-channel, etc., are **out
of scope** for these files.

## File format

```json
{
  "protocol": "<short name>",
  "spec_refs": ["RFC 9999", "..."],
  "patterns": [
    {
      "id": "<protocol>-<pattern-name>",
      "cve_refs": ["CVE-YYYY-NNNN"],
      "summary": "one-line description of the bug class",
      "bug_class": "length_confusion | encoding_overflow | state_confusion | parser_oob | crc_bypass | reflection | resource_exhaustion",
      "target_request": "<RequestInfo name in fuzzer.PROTOCOL_FUZZERS[proto]>",
      "target_field": "<field path inside the Request, e.g. MBAP.Length>",
      "mutation_strategy": "boofuzz_default | group_values | static_invalid | length_lie",
      "mutation_values": ["array of explicit values to try, when applicable"],
      "covered_by_oida_today": true,
      "fuzzer_notes": "specific guidance for the fuzzer author"
    }
  ]
}
```

## Bug classes

| Bug class | What the fuzzer should do |
|---|---|
| `length_confusion` | Length field declares one size, actual payload is a different size. Mutate the length field via `Group([0, 1, expected-1, expected+1, 65535])` while keeping payload fixed. |
| `encoding_overflow` | Variable-length encoding (BER, varint, ASN.1 indefinite) consumes more bytes than allocated. Mutate encoding bytes / prefix bytes. |
| `state_confusion` | Service request sent before required precondition (e.g. session not established). Requires `StatefulFuzzer` or manual state setup before request. |
| `parser_oob` | Field value larger than parser's internal buffer (string length, array count, recursion depth). Use boofuzz `String`/`Bytes` overflow defaults plus explicit large values. |
| `crc_bypass` | Frame CRC is auto-recomputed by mutators, never tested for *deliberately wrong* CRC. Use a `Static` invalid CRC. |
| `reflection` | UDP-based amplification: short request → large response. Document the ratio in the pattern; not a "crash" but a security finding. |
| `resource_exhaustion` | Subscription / connection / file-descriptor exhaustion. Multi-request pattern, requires session orchestration. |

## How to consume

A future enhancement to `BaseFuzzer` could load `cve_patterns.json` and:

1. For each pattern with `covered_by_oida_today == false`, *skip* it
   (gap to fix in the fuzzer code).
2. For each `covered_by_oida_today == true` pattern, optionally bias
   the mutation engine toward the listed `mutation_values` to hit the
   pattern faster than random search would.

Today this is documentation. The integration hook will land alongside
the next fuzzer architecture refactor (see `docs/ARCHITECTURE.md`).
