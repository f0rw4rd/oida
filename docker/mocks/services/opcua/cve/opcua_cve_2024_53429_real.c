/**
 * Real CVE-2024-53429 - actual vulnerable open62541 v1.4.6 binary Variant decode
 *
 * Vulnerability: reachable assertion / decoder inconsistency (CWE-617).
 * DECODE_BINARY(Variant) in src/ua_types_encoding_binary.c decodes a Variant's
 * arrayLength and its arrayDimensions array INDEPENDENTLY and never checks that
 *   product(arrayDimensions) == arrayLength.
 * The ENCODE side DOES check it (ua_types_encoding_binary.c:993,
 *   "if(totalRequiredSize != src->arrayLength) return BADENCODINGERROR;").
 * So a crafted Variant with mismatched dimensions decodes "successfully" into an
 * internally inconsistent object that can no longer be re-encoded -> the OPC UA
 * fuzz harness tests/fuzz/fuzz_binary_decode.cc:79 trips
 *   UA_assert(UA_encodeBinary(...) == UA_STATUSCODE_GOOD);
 * Reported as open62541 issue #6825; fixed in the 1.4 branch by commit
 * b9473527 which adds the missing product==arrayLength check to the DECODER.
 *
 * This harness is a faithful network reproduction of that fuzz round-trip: it
 * reads attacker bytes off TCP 4840, runs the GENUINE vulnerable
 * UA_decodeBinary(Variant) on them (decode half that runs on every server
 * message), then re-encodes with the GENUINE UA_encodeBinary -- exactly the
 * decode->encode round-trip a server performs when it accepts and then relays a
 * value. The re-encode fails on the malformed Variant the unpatched decoder let
 * through, and we abort() on that BADENCODINGERROR == the CVE assertion. The
 * decoder bug is the code under test; we add no vulnerable logic.
 *
 * CLASS: reachable-assertion (CWE-617). Deterministic SIGABRT on the trigger.
 */

#include <open62541/types.h>
#include <open62541/types_generated.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4840

static void handle_variant(const UA_ByteString *in) {
    /* DECODE HALF: the genuine vulnerable decoder. Accepts a Variant whose
     * arrayDimensions product != arrayLength (no validation in v1.4.6). */
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode dec = UA_decodeBinary(in, &v, &UA_TYPES[UA_TYPES_VARIANT], NULL);
    printf("[*] UA_decodeBinary(Variant) -> 0x%08x  arrayLength=%zu dimsSize=%zu\n",
           dec, (size_t)v.arrayLength, (size_t)v.arrayDimensionsSize);
    if(dec != UA_STATUSCODE_GOOD) {
        printf("[*] decode rejected the input (patched build path); no crash\n");
        UA_Variant_clear(&v);
        return;
    }

    if(v.arrayDimensionsSize > 0) {
        size_t prod = 1;
        for(size_t i = 0; i < v.arrayDimensionsSize; ++i)
            prod *= v.arrayDimensions[i];
        printf("[*] decoded dims product=%zu vs arrayLength=%zu %s\n",
               prod, (size_t)v.arrayLength,
               (prod != v.arrayLength) ? "(INCONSISTENT - CVE-2024-53429)" : "");
    }

    /* ENCODE HALF: faithful copy of fuzz_binary_decode.cc:71-79. The genuine
     * encoder rejects the inconsistent Variant with BADENCODINGERROR, which the
     * fuzz harness turns into UA_assert(ret == GOOD) -> abort. */
    size_t encSize = UA_calcSizeBinary(&v, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_ByteString encoded;
    UA_StatusCode a = UA_ByteString_allocBuffer(&encoded, encSize ? encSize : 1);
    if(a != UA_STATUSCODE_GOOD) { UA_Variant_clear(&v); return; }

    UA_StatusCode enc = UA_encodeBinary(&v, &UA_TYPES[UA_TYPES_VARIANT], &encoded);
    printf("[*] UA_encodeBinary(Variant) -> 0x%08x (calcSize=%zu)\n", enc, encSize);

    if(enc != UA_STATUSCODE_GOOD) {
        fprintf(stderr,
            "\n[ASSERT] CVE-2024-53429 TRIGGERED: UA_decodeBinary accepted a "
            "Variant whose arrayDimensions product != arrayLength, but "
            "UA_encodeBinary rejects it with 0x%08x (BADENCODINGERROR). This is "
            "the fuzz_binary_decode.cc:79 reachable assertion in the unpatched "
            "v1.4.6 Variant decoder (ENCODE_BINARY(Variant), "
            "ua_types_encoding_binary.c:993).\n", enc);
        fflush(stderr);
        abort();   /* SIGABRT -> observable in `docker logs` */
    }

    UA_ByteString_clear(&encoded);
    UA_Variant_clear(&v);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf("=================================================\n");
    printf("  REAL open62541 CVE-2024-53429 (Variant decode)\n");
    printf("  Library: open62541 v1.4.6 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Trigger: Variant with product(arrayDimensions) != arrayLength\n");
    printf("=================================================\n");

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if(bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    listen(srv, 4);
    printf("[*] Listening on %d (raw Variant decode endpoint)\n", PORT);

    for(;;) {
        int c = accept(srv, NULL, NULL);
        if(c < 0) continue;
        printf("[*] Client connected\n");

        /* Length-prefixed frame: u32 little-endian length, then that many bytes
         * of a binary-encoded UA_Variant. */
        unsigned char lenbuf[4];
        ssize_t n = recv(c, lenbuf, 4, MSG_WAITALL);
        if(n == 4) {
            uint32_t len = (uint32_t)lenbuf[0] | ((uint32_t)lenbuf[1] << 8) |
                           ((uint32_t)lenbuf[2] << 16) | ((uint32_t)lenbuf[3] << 24);
            if(len > 0 && len < (16u * 1024 * 1024)) {
                unsigned char *buf = (unsigned char*)malloc(len);
                ssize_t got = recv(c, buf, len, MSG_WAITALL);
                if(got == (ssize_t)len) {
                    UA_ByteString in = { len, buf };
                    handle_variant(&in);
                }
                free(buf);
            }
        }
        close(c);
    }
    return 0;
}
