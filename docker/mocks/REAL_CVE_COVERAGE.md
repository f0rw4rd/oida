# Real CVE Container Coverage

This document tracks **real, verified-crashing CVE containers** in the OIDA mock
fleet. "Real" here is a strict bar — every container below:

1. Builds the **genuine vulnerable OSS** from source, pinned to a confirmed
   pre-fix version/tag/commit (not a simulation or hand-written canary).
2. Is instrumented with **AddressSanitizer + UndefinedBehaviorSanitizer**
   (`-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer`).
3. Was **R6-verified**: `docker build` → `docker run` → fire a real network PoC →
   confirm an **observable failure** (ASan/UBSan abort, SIGSEGV/SIGABRT, reachable
   `assert()`/`REQUIRE()` abort, or a watchdog-proven DoS) whose symbolized trace
   lands on the **CVE-named function** of the upstream fix.

## Crash-class taxonomy

A parser bug only crashes on a normal Linux/MMU host when it crosses a real memory
boundary. We classify each:

- **(a) crosses-allocation** — negative index / overrun past a whole allocation →
  native ASan abort. No tricks.
- **(b) allocator violation** — UAF / double-free / NULL-deref / reachable
  assertion → native abort, geometry-independent.
- **(c) contained over-read** — bounded inside a live allocation, so a stock ASan
  build stays silent. Made observable with the **`__asan_poison_memory_region`
  moving-fence** at the received-frame boundary (the modbus-CVE-2019-14462
  technique): poison the bytes beyond the real message so the over-read hits
  poisoned shadow. The vulnerable code is untouched — only a fence is added.
- **(DoS)** — resource exhaustion / server-exit, NOT memory corruption. ASan will
  not (and should not) abort; proven by a CPU/RSS **watchdog** or observed
  process exit, and labeled honestly.

## Honesty policy (crash vs DoS vs contrived)

Every container below produces a **genuine memory fault in the real vulnerable
code** — an ASan/UBSan abort on a real OOB/UAF/double-free, a SIGSEGV/NULL-deref,
a poison-fenced real over-read, or the **library's own** reachable
`assert/REQUIRE/INSIST` firing on network input. Containers that were only
*observable failures* but not real memory crashes were **removed**, not kept for
a count:

- **Removed — contrived:** `opcua CVE-2024-53429` (our harness re-encoded and
  `abort()`-ed on a status check; the decoder never faulted — it's a fuzz-harness
  assertion, not a server crash).
- **Removed — pure DoS:** `opcua CVE-2022-25761`, `nghttp2 CVE-2020-11080` &
  `CVE-2019-9513`, `isc-dhcp CVE-2010-2156` (watchdog/CPU/server-exit, no memory
  corruption).
- **Removed — fake:** the hand-written `wuftpd` S/Key `check_canary()` simulation.

Consequence: three hardened protocols genuinely have **fewer than 3** server-reachable
memory-corruption CVEs, and we report that honestly rather than padding:
**opcua = 2, http2 = 1, dhcp = 2.**

## Coverage matrix (19 protocols, 53 verified containers)

| Protocol | OSS (pinned) | Verified CVEs | Notable crash classes |
|---|---|---|---|
| modbus | libmodbus 3.1.4 | CVE-2022-0367 (a), CVE-2019-14462 (c), CVE-2019-14463 (c) | native + poison-fence |
| coap | libcoap | CVE-2023-35862 (a), CVE-2024-0962 (c), CVE-2026-29013 (a) | global-overflow / redzone / NDEBUG underflow |
| bacnet | bacnet-stack 0.8.6/1.4.2 | CVE-2019-12480 (a SEGV), CVE-2026-41502 (c), CVE-2026-41503 (c) | native SEGV + poison-fence |
| snmp | net-snmp 5.7.3/5.8/5.9.1 | CVE-2018-18066 (b), CVE-2019-20892 (b), CVE-2022-24807 (a) | NULL-deref / double-free / stack-overflow |
| iec104 | lib60870-C 2.0/2.2/2.3.5 | GHSA-75pr (b), GHSA-7v97-class (a), handleASDU-null (b) | NULL-deref + heap OOB read |
| mms | libIEC61850 1.4.0 | CVE-2020-7054 (a), CVE-2019-19931 (a), CVE-2020-15158 (a) | heap overflows + COTP underflow |
| ethernetip | OpENer 58ee13c | CVE-2022-43604 (a), CVE-2022-43605 (a), CVE-2022-43606 (b) | stack-overflow + NULL call |
| dnp3 | opendnp3 1.1.0 | CVE-2019-18996, CVE-2017-7938 (both c) | aegis APDU over-read family, poison-fence |
| opcua | open62541 1.0.1/1.5.0-rc2 | CVE-2020-36429 (a), CVE-2026-1301 (a) | JSON-encode + JSON-PubSub-decode heap OOB writes — **2 genuine**, open62541 hardened (no 3rd) |
| mqtt | mosquitto 1.6.5/2.0.7/2.0.18 | CVE-2021-34432 (b), CVE-2019-11779 (a), CVE-2024-8376 (b) | NULL-deref / stack-overflow / UAF |
| dicom | DCMTK 3.6.3/3.6.8 | CVE-2024-34508 (b), CVE-2019-1010228 (a), CVE-2024-47796 (a) | DIMSE NULL + RLE/render OOB |
| http | nginx 1.4.0/1.13.2/1.20.0 | CVE-2013-2028 (a), CVE-2021-23017 (a), CVE-2017-7529 (UBSan) | stack/heap overflow + int-overflow |
| http2 | nghttp2 1.5.0 | CVE-2015-8659 (b) | idle-stream UAF — **1 genuine**, nghttp2's bug surface is DoS-only (no 2nd/3rd memory CVE) |
| smtp | exim 4.92.1/4.94 | CVE-2019-16928 (a), CVE-2020-28023 (a), CVE-2020-28024 (a) | heap/global/underwrite, all native |
| vnc | LibVNCServer 0.9.11 | CVE-2018-15127 (a), CVE-2018-20748 (a), CVE-2018-7225 (c) | server-side OOB write + poison-fence |
| dhcp | dnsmasq 2.77 / busybox 1.29.3 | CVE-2017-14493 (a), CVE-2018-20679 (c) | DHCPv6 stack-overflow + udhcp over-read — **2 genuine** |
| mdns | avahi 0.8 | CVE-2023-38469/38471/38473 (all b) | reachable-assertion family |
| ntp | ntpd 4.2.8p3/p8 | CVE-2015-7855 (b), CVE-2016-7434 (b), CVE-2016-9311 (b) | mode-6 assert / NULL-deref / INSIST |
| dns | dnsmasq 2.77 / BIND 9.11.4 | CVE-2017-14491 (c), CVE-2017-14493 (a), CVE-2018-5740 (b) | poison-fence + stack-overflow + REQUIRE |

Reachability notes are documented per-CVE in each `Dockerfile.*-real` header and PoC.
Where a CVE is reachable only via a non-network transport (e.g. avahi 38471 is
D-Bus/local; some are reached through a thin TCP harness that feeds the genuine
vulnerable function), that is stated honestly in the service description.

## Protocols with NO suitable OSS (no real container feasible)

Investigated via OT Brain (search-cves / lookup-cve) + GitHub; documented honestly
rather than faked. The goal is "real containers **where possible**" — these are the
"not possible" cases:

| Protocol | Why no real CVE container |
|---|---|
| s7 / snap7 | Server side is proprietary Siemens firmware; snap7 lib has no server-side parsing CVE with a PoC. |
| ads | Beckhoff TwinCAT proprietary; no OSS ADS server with a memory CVE. |
| profinet | Stack CVEs are Siemens Scalance firmware (not buildable); p-net has no reachable server memory CVE. |
| ethercat | SOEM/IgH are master-side; no OSS slave/server with a memory CVE. |
| tase2 | libtase2 is commercial (MZ Automation); no OSS. |
| hart | HART-IP servers are proprietary; no OSS with a memory CVE. |
| knx | knxd/calimero have no reachable server-side memory CVE (calimero is Java). |
| can | SocketCAN/can-utils are kernel/app utilities, not a discrete network service with a parser CVE. |
| ocpp | OSS servers are Java (SteVe) / Python; WebSocket/JSON, no native memory CVE. |
| hl7 | All OSS HL7v2/MLLP stacks are Java (HAPI/Mirth) or Python (hl7apy); the one C parser (hl7parser) has an OOB but it is **not reachable via a malicious MLLP frame** (API-misuse only). Documented negative. |
| fhir | HAPI FHIR is Java; no native memory CVE. |
| astm | Niche; no OSS C/C++ server with a memory CVE. |

## Out-of-scope fuzzer primitives (no discrete-service CVE target)

The fuzzer also supports transport/layer primitives that are not "a network service
with an OSS parser to crash" in the CVE-container sense: **tcp, ipv4, ipv6, icmp,
icmpv6, ethernet, echo, daytime, mutation**, and **modbus_rtu** (serial transport
variant of modbus, covered by the modbus containers). These are exercised by the
fuzzer against arbitrary targets / the kernel, not a buildable vulnerable daemon.

## GOOSE (IEC 61850 layer-2) — special case

GOOSE rides raw Ethernet multicast (no IP), so it is not reachable over a Docker
bridge network the way MMS (TCP/102) is. The libIEC61850 GOOSE subscriber parser
shares the codebase covered by the MMS containers. A GOOSE-specific container would
require host-network + raw L2 injection; deferred as not bridge-reachable.

## Running

```bash
cd docker/mocks
# Build + run one protocol's CVE set:
docker compose -f compose.yml -f compose.cve.yml --profile vuln-<proto> up -d
# Fire the PoC (per service), then check the ASan trace:
python3 services/<proto>/cve/poc_*.py <host> <port>
docker logs <container>   # -> AddressSanitizer / SIGABRT trace on the CVE-named function
```

Each CVE service is `restart: "no"` — it is a crash-on-trigger target and stays
`exited` after the PoC fires; re-`up` to re-arm. Forking daemons (exim, storescp)
keep PID 1 alive and surface the crash as the ASan trace in `docker logs`.
