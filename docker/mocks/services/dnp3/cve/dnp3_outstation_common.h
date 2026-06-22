/*
 * Shared TCP outstation harness for the opendnp3 1.1.0 APDU-parser CVE
 * containers. Each CVE binary defines PORT/BANNER/CVE_DESC and includes this
 * header, which provides run_outstation(): a minimal DNP3 outstation that
 * accept()s on TCP 20000, recv()s an application fragment, and drives it
 * straight into the GENUINE vulnerable opendnp3::APDU parser
 * (Write -> Interpret -> BeginRead -> object iteration), exactly the inbound
 * code path a real outstation executes on a received APDU.
 *
 * The APDU buffer is sized to the received fragment length (a moving fence):
 * the 1.1.0 parser's object-iterator (ObjectReadIterator::operator*) hands back
 * data pointers past the validated object extent for under-validated headers
 * (placeholder / range / count object families). With a fragment-tight
 * CopyableBuffer allocation, that over-read crosses the heap allocation and
 * AddressSanitizer reports a heap-buffer-overflow whose buggy address is
 * "0 bytes to the right of" the genuine opendnp3 CopyableBuffer allocation
 * (frames: CopyableBuffer::CopyableBuffer <- APDU::APDU). In a stock outstation
 * the same defect is a silent over-read contained inside the fixed 2048-byte
 * fragment buffer; the fence makes the genuine bug observable.
 *
 * FOR AUTHORIZED SECURITY TESTING ONLY - DO NOT USE IN PRODUCTION.
 */
#ifndef DNP3_OUTSTATION_COMMON_H
#define DNP3_OUTSTATION_COMMON_H

#include <opendnp3/APDU.h>
#include "ObjectReadIterator.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace opendnp3;

/*
 * Drive received application-fragment bytes into the genuine vulnerable parser.
 * Mirrors how an outstation walks a received fragment: APDU::Interpret() parses
 * the object headers, then a SOE consumer iterates the objects and reads their
 * data. We size the APDU fragment buffer to the received length so the parser's
 * over-read lands in the ASan right-redzone of the real fragment allocation.
 */
static void feed_fragment(const uint8_t *data, size_t len) {
    printf("[*] received %zu-byte fragment; driving opendnp3 APDU parser\n", len);
    try {
        APDU apdu(len);          /* fragment-tight buffer == moving fence */
        apdu.Write(data, len);
        apdu.Interpret();        /* genuine APDU::ReadObjectHeader object-header parse */
        volatile uint8_t sink = 0;
        size_t objects = 0;
        for (HeaderReadIterator hdr = apdu.BeginRead(); !hdr.IsEnd(); ++hdr) {
            for (ObjectReadIterator obj = hdr.BeginRead(); !obj.IsEnd(); ++obj) {
                /* operator* returns the parser-computed object-data pointer;
                 * for the under-validated header it points past the fragment.
                 * Reading it is the over-read a real SOE handler would do. */
                const uint8_t *p = *obj;
                sink ^= p[0];
                ++objects;
            }
        }
        (void)sink;
        printf("[*] parsed %zu object(s), no fault\n", objects);
    } catch (const std::exception &e) {
        printf("[*] parser rejected fragment: %s\n", e.what());
    }
}

static int run_outstation(int port, const char *banner) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    setbuf(stdout, NULL);

    printf("===========================================\n");
    printf("%s", banner);
    printf("  opendnp3 1.1.0 (vulnerable) + ASan\n");
    printf("  Port: %d (DNP3/TCP)\n", port);
    printf("===========================================\n");

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 4) < 0) { perror("listen"); return 1; }

    printf("[*] Listening on TCP %d; send a DNP3 application fragment...\n", port);

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }
        uint8_t buf[4096];
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n > 0)
            feed_fragment(buf, (size_t)n);
        close(client_fd);
    }
    return 0;
}

#endif /* DNP3_OUTSTATION_COMMON_H */
