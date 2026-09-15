---
name: Bug report
about: Report a bug in OIDA (not in a target device — that goes to the vendor)
title: "[bug] <one-line summary>"
labels: bug
assignees: ''
---

## Summary

<!-- One sentence: what happens vs. what should happen. -->

## Reproduce

```bash
# Exact command + flags you ran
oida <protocol> <target> --flag …
```

If the bug needs a specific input (pcap, wordlist, target response),
attach it or describe the minimum reproducer.

## Expected behaviour

<!-- What you thought would happen. -->

## Actual behaviour

<!-- Stack trace / log line / wrong output. Redact target IPs and
     credentials before pasting. -->

```
<paste here>
```

## Environment

- OIDA version: `oida --version`
- Python version: `python --version`
- OS: <Linux/macOS/Windows + version>
- Installed extras: <e.g. `pip install oida-ics[modbus,opcua]`>
- Docker / mock used (if any):

## Anything else

<!-- Did this work before? Did you bisect to a commit? Any workaround? -->
