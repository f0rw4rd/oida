# Security Policy

## Reporting a vulnerability

If you find a security issue in OIDA, please **do not** open a public issue.

Instead, report it through **https://getoida.dev/contact** with:

1. A short description of the issue.
2. The minimal reproduction (input, command, expected vs. actual behaviour).
3. The OIDA version (`oida --version`) and the OS / Python version.
4. Any logs or stack traces (please redact target IPs / credentials).

We aim to:

- Acknowledge within **3 business days**.
- Triage and confirm within **7 business days**.
- Ship a fix on the **next minor** release, or a patch release for high
  severity. We'll coordinate disclosure timing with you.

You will be credited in `CHANGELOG.md` and the release notes unless you ask
us not to.

## What counts as a vulnerability

OIDA is a defensive / offensive-security testing tool. We care about:

- **Scanner code paths that crash, OOM, or hang** on attacker-controlled
  responses (e.g. a malicious BACnet/UPnP device returns an XML bomb).
- **Information disclosure**: any path that writes engagement-sensitive
  data (target IPs, credentials, file paths under client directories) to
  somewhere unintended — global logs, JSON exports, the screen of a
  shared workstation.
- **Privilege misuse**: a `--confirm`-gated write operation that fires
  without the user passing `--confirm`. We treat every help-text promise
  ("requires --confirm") as a hard contract.
- **Dependency CVEs that affect us**: an OIDA-shipped extra (`pip install
  oida[modbus]` etc.) pulls a known-vulnerable library.

## What is NOT a vulnerability

OIDA *targets* ICS devices that often have weak authentication, plaintext
protocols, and pre-auth attack surface. A finding that says "this protocol
has no encryption" is not a vulnerability in OIDA — that is what we are
built to discover.

Similarly:

- A scan disclosing target-device data to the operator running the scan
  is the intended behaviour.
- The fuzzer crashing a target service is its job.
- A test pcap fixture containing real credentials from the wild
  (`tests/fixtures/pcap/`) is intentional — those captures are public
  research material from Wireshark, Zeek, and other published datasets.

## Supply-chain trust boundary

OIDA's dependency tree (146+ packages, see `uv.lock`) draws from three
trust tiers:

1. **Mainstream PyPI packages with broad maintainership** (cryptography,
   requests, pytest, scapy, asyncua, …). Standard PyPI threat model —
   we hash-pin via `uv.lock` and bump on CVE.
2. **Single-maintainer protocol forks needed for OT coverage**:
   `pyshark @ github.com/f0rw4rd/pyshark` (pinned to commit SHA in
   `pyproject.toml` and `uv.lock`), `manuf2`, `yadnp3`, `pyiec61850-ng`,
   `hartip-py`, `profinet-py`. Upstream maintainer-account compromise on
   any of these would be a supply-chain risk; lockfile hash-pinning
   protects against tampering of *known* versions but not against new
   versions we choose to upgrade to. Review diffs before bumping these.
3. **GitHub Actions** in `.github/workflows/`. All third-party actions
   are pinned by full commit SHA (not by tag); upstream tag-overwrite
   attacks won't reach us.

Lockfile drift is enforced by `tests/contracts/test_uv_lockfile_drift.py`
and by CI's `uv sync --frozen` step. Dependabot opens grouped weekly PRs
for CVE bumps (`.github/dependabot.yml`).

## Coordinated disclosure of target-side findings

If you use OIDA to find a vulnerability in a third-party ICS product,
please coordinate disclosure with that vendor — not us. We can advise on
public references (CVE numbering, ICS-CERT advisories) but the
vendor-disclosure timeline is theirs.
