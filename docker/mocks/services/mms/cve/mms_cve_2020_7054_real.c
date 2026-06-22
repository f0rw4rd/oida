/**
 * Real CVE-2020-7054 - actual vulnerable libIEC61850 v1.4.0 MMS data decoder.
 *
 * Heap-based buffer overflow (CWE-787, WRITE) in MmsValue_decodeMmsData()
 * in mms/iso_mms/server/mms_access_result.c when parsing the MMS_BIT_STRING
 * (BER tag 0x84) data type. The decoder computes the bit-string allocation
 * from
 *     bitStringLength = (8 * (dataLength - 1)) - padding;
 *     value = MmsValue_newBitString(bitStringLength);   // allocs |bits|/8 bytes
 *     memcpy(value->value.bitString.buf, buffer + bufPos + 1, dataLength - 1);
 * With a crafted padding byte > the real content, MmsValue_newBitString()
 * (which uses abs(bitSize) and rounds bits->bytes down) allocates FEWER bytes
 * than the (dataLength - 1) the memcpy then writes -> heap write past the
 * allocation. Reported in libiec61850 issue #200 as
 *   "WRITE of size 18 ... 0 bytes to the right of 9-byte region".
 * Fixed after 1.4.0.
 *
 * This harness is the network surface: it accepts a raw TPKT/COTP-style
 * length-prefixed MMS data blob on TCP/102 and feeds the exact received bytes
 * to the genuine vulnerable MmsValue_decodeMmsData() (the same entry the
 * upstream fuzz/fuzz_mms_decode.c harness drives, and the same function the
 * server reaches from the dead #if-0 mmsServer_handleWriteRequest2 path).
 * Because the overflow leaves the heap allocation entirely, ASan aborts
 * NATIVELY -- crash class (a), no manual poisoning needed.
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

/* Read exactly n bytes (or fail). */
static int read_all(int fd, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

/*
 * Wire framing (kept deliberately simple so the PoC is auditable):
 *   [4 bytes big-endian length L][L bytes of raw MMS Data element]
 * The L bytes are handed verbatim to MmsValue_decodeMmsData().
 */
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
    /* THE VULNERABLE CALL: CVE-2020-7054 lives in the 0x84 (BIT_STRING) case. */
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
    printf("  REAL libIEC61850 CVE-2020-7054 Server\n");
    printf("  Using: libIEC61850 v1.4.0 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Vuln: heap overflow in MmsValue_decodeMmsData (MMS_BIT_STRING)\n");
    printf("  Trigger: BER 0x84 with padding > content length\n");
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
