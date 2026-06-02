# Hardware-Validation Smoke Checklist — Siemens S7-300 / S7-400

Tailored to a **dedicated lab device** with **read + safe-write** scope.
Don't run any of this against production gear, even on the same network.

> **Verify before reporting** (per `CLAUDE.md`): every command below should
> be run, the output read, and the actual result recorded — not "looks
> like it worked from the log line." Where a step's expected output is
> ambiguous, note what you actually saw.

## 0. Pre-flight (do NOT skip)

```bash
# Confirm target host
TARGET=10.0.0.10        # replace with your lab PLC IP
RACK=0                  # default for S7-300/400 standalone
SLOT=2                  # CPU slot — S7-300 default is 2, S7-400 may be 3

# Confirm reachability + ISO-TSAP port open before doing anything
nc -vz $TARGET 102

# Snapshot device state so we can detect side-effects later
oida snap7 $TARGET --rack $RACK --slot $SLOT -i --format json -o snap7-pre.json
```

Record:
- [ ] Does TCP 102 respond? Y / N
- [ ] CPU model / order code from `-i` output:
- [ ] CPU run/stop state from `-i` output:
- [ ] Firmware version:

## 1. Discovery + identification (read-only)

```bash
# 1.1 Bare discovery
oida snap7 $TARGET --rack $RACK --slot $SLOT

# 1.2 Full device info (CPU type, MLFB/order code, serial, status)
oida snap7 $TARGET --rack $RACK --slot $SLOT -i

# 1.3 SZL (System Status List) enumeration — vendor-specific
oida snap7 $TARGET --rack $RACK --slot $SLOT -L

# 1.4 Slot scan (no --slot flag → auto-discover)
oida snap7 $TARGET --rack $RACK -s
```

Record:
- [ ] 1.1 — connects without error: Y / N
- [ ] 1.2 — fields populated: order_code __ / module_type __ / serial __ / status __
- [ ] 1.3 — SZL IDs returned (count): __ — any decode errors? __
- [ ] 1.4 — slot scan finds CPU at slot __ (matches manual config?): Y / N

## 2. Data block reads (read-only)

```bash
# 2.1 Block list enumeration (OB / FC / DB / SDB)
oida snap7 $TARGET --rack $RACK --slot $SLOT -E

# 2.2 Read a known data block — pick one you OWN from the project
#     (DB1 is conventional but check the project first; do NOT read
#     arbitrary high DB numbers as some firmwares answer unexpectedly).
oida snap7 $TARGET --rack $RACK --slot $SLOT --read-db 1:0:20

# 2.3 Read memory areas (PA = process image output, PE = input, M = marker)
#     These are safe reads; do NOT use --write-* without §3 approval below.
oida snap7 $TARGET --rack $RACK --slot $SLOT --read-area M:0:16
```

Record:
- [ ] 2.1 — block list count: OBs __ / FCs __ / DBs __ / SDBs __
- [ ] 2.2 — DB1 read returned bytes: __ (compare to known-good engineering project)
- [ ] 2.3 — M-area read returned: __

## 3. Safe-write tests (lab device only, with --confirm)

> **DO NOT** run this section on anything that controls real physical
> processes. The audit pattern: write a known marker, read it back,
> restore the original value. Always restore.

```bash
# 3.1 Save current M0.0..M0.15 (16 bytes) so we can restore
oida snap7 $TARGET --rack $RACK --slot $SLOT --read-area M:0:16 \
    --format json -o m-area-pre.json

# 3.2 Write a known marker (0xDE 0xAD 0xBE 0xEF) — REQUIRES --confirm
oida snap7 $TARGET --rack $RACK --slot $SLOT \
    --write-area M:0:DEADBEEF --confirm

# 3.3 Read back and verify
oida snap7 $TARGET --rack $RACK --slot $SLOT --read-area M:0:4

# 3.4 Restore original (use the values from step 3.1)
oida snap7 $TARGET --rack $RACK --slot $SLOT \
    --write-area M:0:<original-hex-from-3.1> --confirm
```

Record:
- [ ] 3.2 — write returned success: Y / N
- [ ] 3.3 — readback shows `DEADBEEF`: Y / N
- [ ] 3.4 — restore confirmed: Y / N
- [ ] PLC remained in RUN throughout: Y / N (if N: STOP everything, file an issue with the pcap)

## 4. State change (DANGEROUS — only with explicit lab sign-off)

> Run/Stop transitions on a PLC with attached I/O will de-energise outputs.
> If your lab CPU has actuators, motors, or anything physical wired up:
> **don't run §4**.

```bash
# 4.1 Read current state (should already be RUN from §1.2)
oida snap7 $TARGET --rack $RACK --slot $SLOT --plc-status

# 4.2 STOP → wait 5 seconds → START → verify back in RUN
oida snap7 $TARGET --rack $RACK --slot $SLOT --plc-stop --confirm
sleep 5
oida snap7 $TARGET --rack $RACK --slot $SLOT --plc-status     # should show STOP
oida snap7 $TARGET --rack $RACK --slot $SLOT --plc-start --confirm
sleep 5
oida snap7 $TARGET --rack $RACK --slot $SLOT --plc-status     # back to RUN
```

Record:
- [ ] 4.2 — state transitions completed: Y / N
- [ ] CPU LEDs match expected sequence (RUN → STOP → RUN): Y / N
- [ ] No diagnostic-buffer alarms triggered (check via TIA Portal / STEP 7): Y / N

## 5. Cross-check: snapshot diff

```bash
oida snap7 $TARGET --rack $RACK --slot $SLOT -i --format json -o snap7-post.json
diff <(jq -S . snap7-pre.json) <(jq -S . snap7-post.json)
```

Expected diff: zero, OR only fields that legitimately change between
runs (timestamps, scan counters). Anything else is a bug — file with
the diff attached.

## 6. Issues to watch for during the session

A. **Snap7 connection refused on first try, succeeds on retry.** Known
   pattern with older S7-300 — the ISO-TSAP setup has a 1-2s warmup.
   `oida` retries internally; verify the success line says "Siemens S7:
   ..." exactly once, not twice.

B. **Password-protected CPU.** S7-300/400 supports a 4-character password.
   If `-i` shows `password_protected: true`, write down which operations
   require the password and don't pass `-P` on the command line (the
   privacy fix in `82e0f439` shows basename only, but still — pass via
   env var if your shell history is shared).

C. **Run/stop with PG/HMI clients connected.** Other engineering clients
   may auto-reconnect after §4.2. Coordinate with anyone using the lab.

D. **Diagnostic buffer fills with "ADS rejected" or "TIME-OUT".** This
   is normal during the scan — but if it overflows it can mask real
   diagnostic entries. Clear the buffer in TIA Portal before §1 and check
   after §4 for any entries that aren't us.

## 7. After the session

- [ ] Confirm CPU in RUN with all OBs running (RUN LED steady, no fault LEDs)
- [ ] Save snap7-pre.json + snap7-post.json + any anomaly logs to a project folder
- [ ] File a GitHub issue for any discrepancy between snap7-pre and snap7-post
      that isn't a timestamp or counter — include the diff and the OIDA
      version (`oida --version`)
- [ ] If anything in §4 triggered an unexpected STOP / FAULT: redact the
      diagnostic-buffer entry and email `fnbriearfz@pm.me` per `SECURITY.md`
      before opening a public issue
