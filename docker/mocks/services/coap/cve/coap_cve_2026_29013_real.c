/**
 * Real CVE-2026-29013 - Uses actual vulnerable libcoap v4.3.4 OSCORE CBOR parser
 *
 * Vulnerability: Out-of-bounds read (CWE-125) in the OSCORE Appendix B.2 CBOR
 *   unwrap path. get_byte_inc() in src/oscore/oscore_cbor.c only bounds-checks
 *   with assert():
 *
 *       static inline uint8_t
 *       get_byte_inc(const uint8_t **buffer, size_t *buf_len) {
 *         assert((*buf_len) > 0);   // compiled out under NDEBUG
 *         (*buf_len)--;             // underflows 0 -> SIZE_MAX
 *         return ((*buffer)++)[0];  // keeps reading off the end
 *       }
 *
 *   oscore_cbor_get_element_size() reads a CBOR control byte and, for a
 *   multi-byte unsigned integer (control byte 0x18..0x1b), loops calling
 *   get_byte_inc() up to 8 times. If the supplied CBOR buffer is shorter than
 *   the encoded length claims, buf_len underflows and the parser reads far past
 *   the buffer -> ASan out-of-bounds read / SIGSEGV.
 *
 *   Inbound reach: coap_oscore_decrypt_pdu() (src/coap_oscore.c) CBOR-unwraps
 *   the attacker-controlled kid_context of a received OSCORE option via
 *   oscore_cbor_get_element_size(&ptr, &length) -- i.e. this is driven straight
 *   from a crafted CoAP request's OSCORE option. This harness invokes that same
 *   genuine library function on the attacker bytes exactly as the inbound path
 *   does (ptr = kid_context.s, length = kid_context.length).
 *
 * CRASH CLASS: (a) unbounded read. Once buf_len underflows to SIZE_MAX the
 *   parser marches off the end of the heap-tight allocation; ASan flags the
 *   first read past the buffer (or a hard SIGSEGV once it leaves the page).
 *   The library is built with -DNDEBUG so the assert() guard is removed -- the
 *   exact "release build" condition the CVE calls out.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-29013
 * Affected: libcoap OSCORE CBOR unwrap (assert-only bounds, NDEBUG release)
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <coap3/coap.h>

#define PORT 5683

/* Prototype for the genuine vulnerable parser. It is exported from
 * src/oscore/oscore_cbor.c but its header (include/oscore/oscore_cbor.h) is
 * EXTRA_DIST and not installed, so we declare it here. Symbol is resolved by
 * linking against libcoap-3. */
size_t oscore_cbor_get_element_size(const uint8_t **buffer, size_t *buf_size);

/*
 * Feed an attacker-controlled CBOR kid_context blob to the genuine vulnerable
 * parser, exactly as coap_oscore_decrypt_pdu() does for a received OSCORE
 * option. The blob is copied into a heap-tight buffer so the over-read past the
 * encoded length lands in the ASan right-redzone.
 */
static void handle_cbor_kid_context(const uint8_t *data, size_t len) {
    uint8_t *buf = malloc(len);
    if (!buf)
        return;
    memcpy(buf, data, len);

    const uint8_t *ptr = buf;
    size_t length = len;

    printf("[*] CBOR-unwrapping %zu-byte kid_context via "
           "oscore_cbor_get_element_size()\n", len);

    /* This is the exact call coap_oscore.c makes on the inbound kid_context. */
    size_t sz = oscore_cbor_get_element_size(&ptr, &length);

    /* If we get here without crashing, report (will not happen on the trigger). */
    printf("[*] element size = %zu (no crash)\n", sz);

    free(buf);
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    setbuf(stdout, NULL);

    printf("===========================================\n");
    printf("  REAL libcoap CVE-2026-29013 Server\n");
    printf("  libcoap v4.3.4 OSCORE CBOR (NDEBUG, vuln)\n");
    printf("  Port: %d (TCP control channel)\n", PORT);
    printf("  Trigger: CBOR kid_context claiming a multi-\n");
    printf("           byte int longer than the buffer ->\n");
    printf("           get_byte_inc buf_len underflow OOB\n");
    printf("===========================================\n");

    coap_startup();

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(server_fd, 4) < 0) { perror("listen"); exit(1); }

    printf("[*] Listening on TCP %d; send a CBOR kid_context blob...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }

        uint8_t buf[4096];
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n > 0)
            handle_cbor_kid_context(buf, (size_t)n);

        close(client_fd);
    }

    coap_cleanup();
    return 0;
}
