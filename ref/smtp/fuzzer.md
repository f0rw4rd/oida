# SMTP — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/smtp.py` |
| Boofuzz class | `SMTPFuzzer` (BaseFuzzer + state names, **audit B7/B9**) |
| Requests | 12 |
| Mutation depth | 35 fuzzable : 0 default : 96 Static |
| State machine | Declared via state names on RequestInfo but framework doesn't enforce transitions |
| Test coverage | Benchmark `(15, 14000, 30)`. |

## CVE patterns covered

See `ref/smtp/cves/README.md`. SMTP CVEs span the command parser (RFC
5321), MIME/data parsing (RFC 5322), and auth/STARTTLS extensions:

| CVE pattern | SMTP fuzzer request | Covered? |
|---|---|---|
| HELO / EHLO domain length overflow | `SMTP_HELO_EHLO` | ✓ |
| MAIL FROM / RCPT TO address parsing | `SMTP_MAIL_FROM`, `SMTP_RCPT_TO` | ✓ |
| DATA section line-length (RFC 5321 § 4.5.3.1.6: 1000 char limit) | `SMTP_Long_Data` | ✓ |
| AUTH PLAIN / LOGIN credential parsing | `SMTP_AUTH` | ✓ |
| STARTTLS — command after TLS established (CVE-2011-0411 class) | should be state-gated; **audit B7** — not enforced today | ⚠ |
| XCLIENT / XFORWARD postfix extensions | `SMTP_X_Extensions` | ✓ |
| Pipelining abuse (multiple commands in one TCP segment) | `SMTP_Pipelining` | ✓ |
| Long greeting / banner read (server side) | n/a (client-mode fuzzer) | — |

## Known gaps (audit findings)

- **State machine declared but not enforced** (B7). RequestInfo entries
  carry `requires_state="POST_AUTH"` etc. but the framework only uses
  these as metadata tags. A `requires_state="POST_AUTH"` request can
  fire before AUTH succeeds.
- **Should extend `StatefulFuzzer` not `BaseFuzzer`** (B9). Same class
  of issue as OPC UA and HTTP.

## Optimization recommendations

1. **Migrate to `StatefulFuzzer`** with explicit transitions:
   - INIT → GREETING_RECEIVED → HELO_SENT → MAIL_FROM_SET → RCPT_SET →
     DATA_MODE → COMPLETE
   - STARTTLS branch: HELO_SENT → STARTTLS_NEGOTIATING → TLS_HELO_SENT
   - AUTH branch: HELO_SENT → AUTH_IN_PROGRESS → POST_AUTH
2. **Add a CHUNKING (BDAT, RFC 3030) request** — alternative to DATA,
   different parser path.
3. **DSN / NOTIFY parameter** fuzzing on MAIL FROM extensions.
