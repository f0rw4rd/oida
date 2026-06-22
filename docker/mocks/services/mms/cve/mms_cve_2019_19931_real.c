/**
 * Real CVE-2019-19931 - actual vulnerable libIEC61850 v1.4.0 MMS data decoder.
 *
 * Heap-based buffer overflow (CWE-787) in MmsValue_decodeMmsData() in
 * mms/iso_mms/server/mms_access_result.c (libiec61850 issue #194). When
 * decoding a nested MMS_ARRAY/MMS_STRUCTURE the element bound is computed as
 *     int elementBufLength = newBufPos - bufPos + elementLength;
 *     MmsValue_decodeMmsData(buffer, bufPos, bufPos + elementBufLength, NULL);
 * and the inner element's own declared length is then trusted for the child
 * memcpy (e.g. the OCTET_STRING / BIT_STRING content copy). A crafted inner
 * element whose declared content length exceeds the bytes that back its freshly
 * allocated value writes past that heap chunk. Issue #194 reports a
 *   "WRITE of 18 bytes to a 9-byte region".
 * Affected: 1.4.0 (and earlier). Fixed in the post-1.4.0 hardening of the
 * length handling.
 *
 * This harness feeds the received bytes straight into the genuine vulnerable
 * MmsValue_decodeMmsData(). The over-write leaves the allocation, so ASan
 * aborts NATIVELY (crash class (a)) -- no manual poisoning.
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "mms_value.h"

#define PORT 102
#define RXBUF 65536

static int read_all(int fd, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

static void handle_client(int fd) {
    uint8_t hdr[4];
    if (read_all(fd, hdr, 4) != 4) return;

    uint32_t len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
    if (len == 0 || len > RXBUF) {
        printf("[!] bad length %u\n", len);
        return;
    }

    uint8_t* buffer = (uint8_t*) malloc(len);
    if (!buffer) return;

    if (read_all(fd, buffer, len) != (int) len) {
        free(buffer);
        return;
    }

    printf("[*] Received %u bytes, first tag=0x%02x -> MmsValue_decodeMmsData()\n",
           len, buffer[0]);

    int endBufPos = 0;
    /* THE VULNERABLE CALL: CVE-2019-19931 lives in the nested element decode. */
    MmsValue* value = MmsValue_decodeMmsData(buffer, 0, len, &endBufPos);

    if (value != NULL) {
        printf("[*] decoded ok (no crash this request)\n");
        MmsValue_delete(value);
    } else {
        printf("[*] decode returned NULL\n");
    }

    free(buffer);
}

int main(void) {
    int server_fd, client_fd, opt = 1;
    struct sockaddr_in addr;

    setbuf(stdout, NULL);

    printf("===========================================\n");
    printf("  REAL libIEC61850 CVE-2019-19931 Server\n");
    printf("  Using: libIEC61850 v1.4.0 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Vuln: heap overflow in MmsValue_decodeMmsData (nested element)\n");
    printf("  Trigger: ARRAY/STRUCT element with oversized inner length\n");
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(server_fd, 5) < 0) { perror("listen"); exit(1); }

    printf("[*] Listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }
        printf("[*] Client connected\n");
        handle_client(client_fd);
        close(client_fd);
        printf("[*] Client disconnected\n");
    }
    return 0;
}
