# Fuzzer Payloads — Research Notes (2026-07-28)

How OIDA's fuzzer generates payloads, what corpora exist, and where the gaps are.
Verified by reading the code + introspecting pinned libs.

## Architecture — five payload layers

1. **Universal string library** — `fuzz/primitives/reduced_string.py` (`ReducedString`,
   a trimmed boofuzz `String`). Supplies format strings (`%p`, `%n`, `AAAA%08x%08x%08x%n`,
   `%99999$n`), length-boundary seeds mutated at 8/16/32/64/128/256/512/1024/4096/65535,
   NULL/control chars, CRLF, malformed UTF-8, binary sequences. Has a "reduced" mode that
   trims the library + lengths for speed.

2. **Context-aware corpus** — `fuzz/primitives/smart_string.py` (`SmartStringPrimitive`,
   `StringContext` Flag enum). 8 base contexts (PATH, FILENAME, CREDENTIAL, IP_ADDRESS,
   PORT, NUMERIC, HOSTNAME, COMMAND) + composites (HOST, NETWORK_TARGET, FILE_PATH).
   `_CONTEXT_PAYLOADS` is curated per context and covers real vuln classes:
   - PATH: traversal (`../`, `..%c0%af`, `%2e%2e%2f`, overlong-UTF-8, double-encoded),
     absolute paths (`/etc/shadow`, `/proc/self/environ`), Windows reserved (`CON`,`NUL`),
     NULL-in-path.
   - FILENAME: NULL truncation, NTFS ADS (`test.txt::$DATA`), path-separator injection.
   - CREDENTIAL: NULL truncation (`admin\x00wrongpassword`), Unicode homoglyphs (Cyrillic
     `а`, Latin `ɑ`), fullwidth/circled normalization bypass.
   - IP_ADDRESS: malformed octets, NULL-termination, SSRF-style (`@127.0.0.1`, `#fragment`).
   - PORT/NUMERIC: signed/unsigned INT8/16/32 boundaries ±1, overflow, float edges
     (NaN/Infinity/subnormal), alt representations (hex/octal/scientific).
   - HOSTNAME: IDN homographs, punycode, 63/253-char label limits.
   - COMMAND: CRLF injection, ANSI escapes, command separators, quoting.
   - GENERIC is intentionally **empty** (documented) to avoid redundancy with layer 1.

3. **Native deterministic Radamsa** — `fuzz/core/mutation/radamsa_native.py`
   (`NativeRadamsaMutator`). Seed-based → **replayable** (no external radamsa binary).
   Weighted mutators: byte drop/flip/insert/repeat/permute/inc/dec/random/seq, line
   delete/repeat/insert, and specials `interesting_bytes` + `ascii_num_insert`. Magic-value
   corpora `INTERESTING_8/16/32` (0,1,…,127,128,255,…,32767,32768,65535,…). Per-context
   creative-mutation budget via `_get_radamsa_count()`.

4. **Structured codecs** — `fuzz/core/codecs/{asn1,mms,opcua}.py`. `ASN1Builder` builds
   BER TLVs (multi-byte length, integer, octet/bit string, OID, sequence, context-specific)
   AND fuzz-specific mutators: `fuzz_length_variants`, `fuzz_tag_variants`,
   `build_with_overflow` (oversized content), `build_truncated` (length says full, content
   short → length/content mismatch), `build_nested_depth`.

5. **CVE-replication payloads** — embedded directly in the per-protocol fuzzers
   (`fuzz/protocols/*.py`). **152 distinct CVEs** referenced across **40 of 51** fuzzer
   files, as named targeted fuzz cases (e.g. s7comm: "ReadVar item-count inflated past items
   present (CVE-2017-1000230)", "WriteVar data-length larger than bytes present
   (CVE-2026-51218 heap overflow)", "COTP DT EOT=0 fragment then incomplete WriteVar
   (CVE-2020-22552)"). `test_cve_replication.py` lists real/fake mock pairs (fake = false-
   positive control).

## Strengths

- Genuinely sophisticated and **not** just random mutation: layered universal + context +
  creative + structured + CVE-targeted.
- The context taxonomy is **actually wired in** — 157 context-tagged string fields across
  protocols (CREDENTIAL 55, PATH 42, NUMERIC 29, FILENAME 14, HOSTNAME 6, COMMAND 4).
- Deterministic mutation → reproducible crashes / replayable sessions.
- Broad, real-world CVE-pattern coverage (152 CVEs), with false-positive controls.

## Gaps & issues (verified)

1. **Structured/BER fuzzing is essentially dead code.** `ASN1Builder.fuzz_length_variants`,
   `fuzz_tag_variants`, `build_with_overflow`, `build_truncated`, `build_nested_depth` have
   **0 call sites**; the codecs (`ASN1Builder`/`MMSCodec`/`OPCUACodec`) are imported by
   **only one** protocol (`tase2.py`). So ASN.1/BER-heavy protocols (MMS, OPC UA, SNMP)
   receive **no** structured length/tag/overflow/truncation fuzzing — the highest-yield
   surface for parser bugs in exactly those protocols. This is the biggest payload gap.
2. **MMS codec BER-length correctness bug** (`fuzz/core/codecs/mms.py:135,326,357,420`) —
   strips the BER length with a fixed `[2:]`, assuming a 1-byte length; wrong for content
   ≥128 bytes (multi-byte length), silently emitting corrupt PDUs. A length-aware
   `_ber_content()` already exists in `tase2.py`. (See BUG_HUNT_2026-07-28.md.)
3. **CVE replication is unverified.** `tests/coverage/fuzz/test_cve_replication.py` is a
   scaffold (its docstring says so) with the crash assertion **commented out** — there is no
   automated proof that the 152 embedded CVE payloads actually trigger their CVEs against the
   mocks. The "fuzzer CVE replication" coverage axis is aspirational until those assertions
   are filled in.
4. **`ref/` payload provenance is missing from the repo.** CLAUDE.md cites
   `ref/<proto>/cve_patterns.json` and `ref/<proto>/fuzzer.md` as the "single source of truth
   for protocol-level decisions", but **0** `ref/` files are tracked in git and the dir is
   empty locally — the payload/CVE research backlog isn't in the repo.
5. **Network-target contexts underused / dead enum members.** `IP_ADDRESS` is used at only
   2 call sites and `PORT` at **0**; the composites `HOST`, `NETWORK_TARGET`, `FILE_PATH` are
   defined but **never used**. Host/port string fields fall back to GENERIC rather than the
   SSRF/malformed-octet/boundary corpora built for them.

6. **No message/PCAP corpus — single-template synthesis.** There is no corpus-loading path
   anywhere; `--seed` (`base_fuzzer.py:154`) seeds only the RNG, not a message library. Every
   fuzzer hand-builds **one** valid baseline frame in code. Most do this well, but no protocol
   seeds from a library of real captured frames / multiple message types, so structural
   coverage is bounded by whatever single template the author wrote.

7. **Big string-rich protocols leave everything GENERIC** — the exact contexts they need
   exist and are simply never passed (see table). Worst offenders by untagged string-field
   count: **dns (133), hl7 (59), dhcp (47), snmpv3 (20), snmpv1 (16), snmpv2 (15)**. The SNMP
   family repeats one copy-pasted gap three times (BER length-mutation wired via
   `asn1_blocks.BERSize`, but community / OID / USM-user strings all GENERIC).

Note on layer-4: the MMS and OPC UA *fuzzers* do use structured BER, but via the simpler
`primitives/asn1` / `asn1_blocks.BERSize` helpers — **not** the richer `core/codecs`
`MMSCodec`/`OPCUACodec` (only `tase2.py` imports those). So gap #1 is specifically about the
`core/codecs` tag/overflow/truncation/nested-depth surface being unrealized, while basic BER
*length* mutation does reach SNMP/GOOSE.

## Per-protocol payload wiring (36 protocols surveyed)

Every `SmartString(...)` resolves to `SmartStringPrimitive`; omitting `context=` silently
defaults to `GENERIC` (universal payloads only). So "untagged" below = context available but
not passed.

**Well-tagged (context genuinely used):** `http_protocol` (32 tags, best-in-class), the
reference exemplars `ftp`/`smtp`/`vnc`, and CREDENTIAL-heavy ICS: `ads`, `iec104`, `dnp3`,
`bacnet`, `mms`, `ethernetip`, `mqtt`, `tftp` (FILENAME), `dicom` (PATH), `opcua` (2 cred).

**String-rich but ALL GENERIC (real misses — context defined, never passed):**
`dns` (133 label/name fields; needs HOSTNAME), `hl7` (59 segment fields; CREDENTIAL/PATH),
`dhcp` (47, incl. a literal `hostname` field; HOSTNAME), `snmpv1/2/3` (16/15/20; CREDENTIAL
for community/USM), `coap` (6; URI-Path→PATH, Proxy-Uri→HOST), `http2` (7; :path→PATH,
:authority→HOSTNAME). For pure L2/L3/L4 (`ethernet`/`ipv4`/`ipv6`/`icmpv6`/`tcp`) GENERIC is
defensible (payload bytes).

**Hardcoded-frame heavy — string identifiers emitted as immutable bytes (no string fuzzing
at all):** `goose` (gocbRef/goID/datSet), `s7comm` (45 Static/11 Group), `tase2`
(domain/object names via codec), `netbios` (NetBIOS names), `profinet` (DCP station-name/IP),
plus `sixlowpan`, `ethercat`, `hart_ip`, `igmp`, `pppoe`, `knx`. `netbios`/`profinet` are the
clearest "string field encoded as immutable bytes" cases (HOSTNAME/IP_ADDRESS fit unused).

**Strong examples to copy:** `modbus` (Size fields + `fuzz_values=ICS_ADDRESS_BOUNDARIES` +
length-mismatch tests), `snmp*` BER length-underflow tests, `s7comm`/`goose` valid baselines.

## Highest-leverage improvements (ranked)

1. Wire the existing `core/codecs` tag/overflow/truncation/nested-depth fuzzers into the
   ASN.1/BER protocols (MMS, OPC UA, SNMP) — the biggest unrealized parser-bug surface. Fix
   the MMS codec BER-length bug first (it currently emits corrupt cases silently).
2. Pass the contexts that already exist to the big GENERIC protocols: `dns→HOSTNAME`,
   `dhcp→HOSTNAME`, `hl7→CREDENTIAL/PATH`, `snmp*→CREDENTIAL`, `coap→PATH/HOST`,
   `http2→PATH/HOSTNAME`. Near-zero risk, large coverage gain.
3. Promote hardcoded string identifiers (goose/s7comm/tase2/netbios/profinet) from
   `Static`/`SmartBytes` to context-tagged `SmartString`.
4. Fill in `test_cve_replication.py`'s commented-out assertions so the 152 CVE payloads are
   actually verified to trigger.
5. Add a message-corpus seeding path (load real frames) so fuzzing isn't bounded by one
   hand-written template per protocol.
