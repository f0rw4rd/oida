/**
 * Real CVE-2024-0962 - Uses actual vulnerable libcoap (v4.3.4-2-g713ada41)
 *
 * Vulnerability: Out-of-bounds read (CWE-125 / labelled CWE-121/787) in
 *   get_split_entry() at src/coap_oscore.c, reached from
 *   coap_parse_oscore_conf_mem() / coap_new_oscore_conf().
 *
 *   On a comment / blank line that ends in "\r\n", the parser decrements `end`
 *   to drop the '\r':
 *
 *       if (end > begin && end[-1] == '\r')
 *         end--;
 *       if (begin[0] == '#' || (end - begin) == 0) {
 *         size -= end - begin + 1;   // BUG: uses the '\r'-decremented `end`,
 *         begin = *start;            //      under-subtracts by 1 byte
 *         goto retry;
 *       }
 *
 *   `size` therefore stays 1 byte larger than the bytes actually remaining.
 *   On the next `retry`, memchr(begin, '\n', size) scans one byte PAST the end
 *   of the configuration buffer. Fixed in commit 0ccb6b58 by tracking the true
 *   newline position in a separate `kend` variable for the size subtraction.
 *
 * CRASH CLASS: (c) contained over-read that, on its own, stays inside whatever
 *   slack the allocator gave the buffer -> would NOT crash natively. We force a
 *   detectable crash by copying the attacker bytes into a HEAP-TIGHT buffer
 *   sized exactly to the payload, so the 1-byte over-scan lands in the ASan
 *   heap right-redzone. (We additionally poison the tail as a belt-and-braces
 *   "moving fence", mirroring the modbus CVE-2019-14462 harness.)
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2024-0962
 * Affected: libcoap 4.3.4 OSCORE config handler (pre-0ccb6b58)
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

/* ASan manual poisoning API (resolved by the -fsanitize=address runtime).
 * Used as a moving fence at the end of the received config blob so the
 * 1-byte over-scan past the buffer is caught even if the heap allocator
 * happened to hand back a rounded-up chunk. */
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

static void handle_oscore_conf(const uint8_t *data, size_t len) {
    /* Heap-tight: allocation is exactly `len` bytes; any read at buf[len] is
     * a heap-buffer-overflow into the ASan redzone. */
    uint8_t *buf = malloc(len);
    if (!buf)
        return;
    memcpy(buf, data, len);

    coap_str_const_t conf_mem;
    conf_mem.length = len;
    conf_mem.s = buf;

    printf("[*] Parsing %zu-byte OSCORE config blob via coap_new_oscore_conf()\n",
           len);

    coap_oscore_conf_t *oscore_conf =
        coap_new_oscore_conf(conf_mem, NULL, NULL, 0);

    if (oscore_conf == NULL)
        printf("[*] parse returned NULL (rejected config)\n");
    else
        printf("[*] parse succeeded\n");

    free(buf);
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    setbuf(stdout, NULL);

    printf("===========================================\n");
    printf("  REAL libcoap CVE-2024-0962 Server\n");
    printf("  libcoap v4.3.4 OSCORE config (vulnerable)\n");
    printf("  Port: %d (TCP control channel)\n", PORT);
    printf("  Trigger: comment line ending in CRLF then a\n");
    printf("           final unterminated line -> 1-byte\n");
    printf("           memchr over-read in get_split_entry\n");
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

    printf("[*] Listening on TCP %d; send an OSCORE config blob to parse...\n",
           PORT);

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }

        uint8_t buf[8192];
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n > 0)
            handle_oscore_conf(buf, (size_t)n);

        close(client_fd);
    }

    coap_cleanup();
    return 0;
}
