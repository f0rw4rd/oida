/**
 * Real CVE-2023-35862 - Uses actual vulnerable libcoap (v4.3.1-163-g08cbda80)
 *
 * Vulnerability: Buffer over-read (CWE-125) in coap_parse_oscore_conf_mem()
 *   at src/coap_oscore.c. The OSCORE config parser compares an
 *   attacker-controlled keyword against a table of NUL-terminated global
 *   keyword strings with:
 *
 *       memcmp(oscore_config[i].keyword, keyword.s, keyword.length)
 *
 *   `oscore_config[i].keyword` points at a short string constant in .rodata
 *   (e.g. "alg" = 4 bytes incl. NUL). `keyword.length` is taken verbatim from
 *   the supplied configuration. A keyword LONGER than the shortest table entry
 *   makes memcmp() read past the end of that global string constant -> ASan
 *   global-buffer-overflow.
 *
 *   Fixed in commit 04f3a4a7 ("coap_oscore.c: Fix ASan detected
 *   global-buffer-overflow bug") by switching to coap_string_equal(), which
 *   length-checks both operands.
 *
 * CRASH CLASS: (a) crosses a whole-allocation boundary (reads off the end of a
 *   .rodata global) -> AddressSanitizer aborts NATIVELY. No manual poisoning
 *   needed; the over-read leaves the global's allocation.
 *
 * Reachability: the OSCORE configuration blob is parsed by coap_new_oscore_conf()
 *   -> coap_parse_oscore_conf_mem(). We feed an attacker-controlled blob through
 *   the genuine public API, mirroring an application that hands untrusted OSCORE
 *   configuration material to libcoap.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2023-35862
 * Affected: libcoap 4.3.1 (OSCORE snapshot, pre-04f3a4a7)
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

/*
 * Parse one attacker-supplied OSCORE configuration blob through the genuine
 * vulnerable parser. The blob bytes are copied into a heap buffer sized exactly
 * to the payload so that, in addition to the .rodata over-read, any read past
 * the config buffer also lands on poisoned/redzone heap memory.
 */
static void handle_oscore_conf(const uint8_t *data, size_t len) {
    uint8_t *buf = malloc(len);
    if (!buf)
        return;
    memcpy(buf, data, len);

    coap_str_const_t conf_mem;
    conf_mem.length = len;
    conf_mem.s = buf;

    printf("[*] Parsing %zu-byte OSCORE config blob via coap_new_oscore_conf()\n",
           len);

    /* save_seq_num_func = NULL, param = NULL: pure parse path */
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
    printf("  REAL libcoap CVE-2023-35862 Server\n");
    printf("  libcoap v4.3.1 OSCORE snapshot (vulnerable)\n");
    printf("  Port: %d (TCP control channel)\n", PORT);
    printf("  Trigger: OSCORE config keyword longer than\n");
    printf("           shortest table keyword -> memcmp OOB\n");
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
