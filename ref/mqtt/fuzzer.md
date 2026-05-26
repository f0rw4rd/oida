# MQTT — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/mqtt.py` |
| Boofuzz class | `MQTTFuzzer` (StatefulFuzzer) |
| Requests | 12 |
| Mutation depth | 2 fuzzable : 0 default : 39 Static |
| State machine | StatefulFuzzer — CONNECT → CONNACK → published/subscribe |
| Test coverage | Benchmark `(20, 9000, 70)`. tshark validation passes. |

## CVE patterns covered

See `ref/mqtt/cves/README.md`. MQTT parser CVEs cluster around the
variable-length remaining-length encoding and per-control-packet
payload parsers:

| CVE pattern | MQTT fuzzer request | Covered? |
|---|---|---|
| Remaining-length encoding overflow (CVE-2018-17614, CVE-2018-12551) | `MQTT_Remaining_Length` | ✓ |
| CONNECT packet — Will Message / username / password / client ID lengths | `MQTT_CONNECT` | ✓ |
| PUBLISH topic name encoding (UTF-8 abuse, null bytes) | `MQTT_PUBLISH` | ✓ |
| SUBSCRIBE topic filter wildcards (`#`, `+` at wrong positions) | `MQTT_SUBSCRIBE` | ✓ |
| PUBREL / PUBREC / PUBCOMP — wrong PacketId for state | `MQTT_QoS_Confusion` | ✓ |
| MQTT 5.0 properties length encoding | `MQTT5_Properties` | ✓ |

## Coverage notes

MQTT mutation count is low (2 explicit fuzzable) because most fields are
already covered by boofuzz defaults on `String`/`Bytes`/`Word`. The
length-encoding boundary cases (variable byte integer 1-byte vs 4-byte
encodings) are well-covered.

## Optimization recommendations

1. **Sparkplug B payload fuzzing** — MQTT often carries Sparkplug B
   binary payloads (Google protobuf). Add a `MQTT_Sparkplug_Payload`
   request that mutates the inner protobuf framing.
2. **MQTT 5.0 reason codes** — a 1-byte field with sparse valid values.
   `Group()` of all 256 values catches lazy validation.
