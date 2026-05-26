# FTP — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/ftp.py` (largest single fuzzer file — 2,560 lines) |
| Boofuzz class | `FTPFuzzer` (StatefulFuzzer) |
| Requests | 16 |
| Mutation depth | 2 fuzzable : 0 default : 118 Static (delim-heavy) |
| State machine | StatefulFuzzer + a secondary state path under TLS-mode flags |
| Test coverage | Benchmark `(45, 16000, 80)`. |

## CVE patterns covered

See `ref/ftp/cves/README.md`. FTP CVEs cluster on the command parser
(RFC 959, then 2228 / 2640 / 4217 extensions), pathname handling, and
PORT/PASV reply parsing:

| CVE pattern | FTP fuzzer request | Covered? |
|---|---|---|
| USER / PASS overflow (wuftpd, ProFTPD, vsftpd class) | `FTP_USER`, `FTP_PASS` | ✓ |
| Long command line — buffer overflow on banner read | covered by boofuzz `String` defaults | ✓ |
| PORT / PASV reply parsing — wrong octet count | `FTP_PORT_Reply` | ✓ |
| MKD / RNFR / RNTO pathname traversal | `FTP_Path_Traversal` | ✓ |
| EPSV / EPRT (RFC 2428) — invalid address family | `FTP_EPSV_EPRT` | ✓ |
| SITE / SYST / FEAT verb parsing | `FTP_SITE` | ✓ |
| AUTH TLS / SSL — CCC abuse (CVE-2010-0734) | covered by TLS-mode state path | ✓ |
| MLST / MLSD (RFC 3659) facts parsing | `FTP_MLST` | ✓ |
| ABOR / STAT mid-transfer state confusion | `FTP_Mid_Transfer` | ✓ |

## Coverage notes

This is the largest fuzzer module by line count (2,560). Most of the
volume is in per-command Request definitions and the dual-path TLS
mode handling. Mutation depth looks low on paper (2 fuzzable) but the
"Static + delim" framing is correct for command-line protocols — the
attack surface is the *string content*, and boofuzz mutates that by
default.

The audit S13 noted "dual state-machine path" — the StatefulFuzzer
extends to a second state machine when `--ftps` is enabled. That's
correct design (CCC / AUTH TLS transitions are real protocol states)
but worth knowing the file has two parallel state graphs.

## Optimization recommendations

1. **Per-command-verb sweep request.** Iterate all 30+ standard FTP
   verbs (RFC 959 + 2389 FEAT list + 3659 MLST) against a clean state.
   Catches per-verb parser logic.
2. **Reduce file size** — extract the TLS state path into a separate
   `ftps.py` if it gets larger. Today it's manageable.
