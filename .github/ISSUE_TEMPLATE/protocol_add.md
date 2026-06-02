---
name: New protocol
about: Request a new protocol scanner or fuzzer
title: "[proto] <protocol name>"
labels: new-protocol
assignees: ''
---

## Protocol

- Name + acronym:
- Standard / spec reference (RFC, IEC, ASHRAE, IEEE):
- Default port(s):
- Transport (TCP/UDP/L2/serial):
- Encrypted variant (if any):

## Real-world deployment

<!-- Where is this protocol actually deployed? Which industries / device
     families? Without this, we'll deprioritise — we don't add scanners
     for unused protocols just because they exist on paper. -->

## Reference material

- Open-source library (Python preferred):
- Public pcaps / test fixtures (link, or attach a small one):
- A vulnerable / mock implementation we can ship to docker/mocks/:
- Known CVEs (NVD links):

## Operator value

- Discovery: what does a scan tell the operator that they didn't know?
- Security findings: what insecure-default / misconfiguration patterns
  should the scanner flag?
- Write operations (if any): require `--confirm` gating; what's the
  blast radius?

## Are you offering to implement?

(yes / partial / no — looking for someone to take it)

See [docs/new-protocol.md](../../docs/new-protocol.md) for the layout
of a protocol module.
