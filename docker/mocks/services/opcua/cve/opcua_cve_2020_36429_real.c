/**
 * Real CVE-2020-36429 - actual vulnerable open62541 v1.0.1 JSON encoder
 *
 * Vulnerability: heap out-of-bounds WRITE (CWE-787).
 * In src/ua_types_encoding_json.c the CtxJson struct carries a FIXED-size array
 *   UA_Boolean commaNeeded[UA_JSON_ENCODING_MAX_RECURSION];   // = 100 entries
 * and the array/object writers bump the depth WITHOUT a bound check:
 *   WRITE_JSON_ELEMENT(ArrStart) { ctx->commaNeeded[++ctx->depth] = false; ... }
 *   WRITE_JSON_ELEMENT(ObjStart) { ctx->commaNeeded[ctx->depth] = false; ... }
 * Encoding a value nested deeper than 100 levels writes commaNeeded[>=100],
 * one (or many) past the end of the array inside the heap-allocated CtxJson.
 * Fixed in v1.0.4 (commit chain incl. "Check max recursion depth in more
 * places") by guarding writeJsonArrStart/writeJsonObjStart with
 *   if(ctx->depth >= UA_JSON_ENCODING_MAX_RECURSION - 1) return BADENCODINGERROR;
 *
 * This harness drives the GENUINE vulnerable UA_encodeJson() (the function named
 * in the CVE, "Variant_encodeJson ... OOB write for a large recursion depth").
 * Attacker network input chooses the nesting depth; we then build a chain of
 * Variants, each wrapping the next inside an ExtensionObject (the natural OPC UA
 * recursion the JSON encoder walks), and JSON-encode it -- exactly what a server
 * does when transcoding a received value to JSON. The vulnerable encoder is the
 * code under test; we add no vulnerable logic.
 *
 * CLASS: heap OOB write (CWE-787). ASan catches the write to commaNeeded[>=100]
 * natively (heap-buffer-overflow) -> deterministic abort.
 */

#include <open62541/types.h>
#include <open62541/types_generated.h>
#include <open62541/types_generated_handling.h>

/* Internal JSON encoder from the vulnerable build tree (headers via -I on the
 * source tree; the symbol is exported by the built library). */
#include "ua_types_encoding_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4840
#define MAX_DEPTH 300   /* well past UA_JSON_ENCODING_MAX_RECURSION (100) */

/* Build a chain of `depth` Variants. innermost holds an Int32; each outer
 * Variant wraps the inner one inside a DECODED_NODELETE ExtensionObject. The
 * JSON encoder recurses one level per wrap -> commaNeeded[depth] OOB write. */
static UA_Variant *build_nested(size_t depth, UA_Int32 *leaf,
                                UA_Variant **chain, UA_ExtensionObject **eos) {
    UA_Variant *inner = (UA_Variant*)calloc(1, sizeof(UA_Variant));
    UA_Variant_init(inner);
    UA_Variant_setScalar(inner, leaf, &UA_TYPES[UA_TYPES_INT32]);
    inner->storageType = UA_VARIANT_DATA_NODELETE;
    chain[0] = inner;

    for(size_t i = 1; i < depth; ++i) {
        UA_ExtensionObject *eo = (UA_ExtensionObject*)calloc(1, sizeof(UA_ExtensionObject));
        UA_ExtensionObject_init(eo);
        eo->encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
        eo->content.decoded.type = &UA_TYPES[UA_TYPES_VARIANT];
        eo->content.decoded.data = chain[i - 1];
        eos[i] = eo;

        UA_Variant *outer = (UA_Variant*)calloc(1, sizeof(UA_Variant));
        UA_Variant_init(outer);
        UA_Variant_setScalar(outer, eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        outer->storageType = UA_VARIANT_DATA_NODELETE;
        chain[i] = outer;
    }
    return chain[depth - 1];
}

static void handle_depth(size_t depth) {
    if(depth < 2) depth = 2;
    if(depth > MAX_DEPTH) depth = MAX_DEPTH;
    printf("[*] Encoding a Variant nested %zu levels to JSON "
           "(UA_JSON_ENCODING_MAX_RECURSION=100)\n", depth);

    UA_Int32 leaf = 1337;
    UA_Variant **chain = (UA_Variant**)calloc(depth, sizeof(UA_Variant*));
    UA_ExtensionObject **eos = (UA_ExtensionObject**)calloc(depth, sizeof(void*));
    UA_Variant *root = build_nested(depth, &leaf, chain, eos);

    /* THE VULNERABLE CALL: genuine UA_encodeJson over a deeply-nested value.
     * Each nesting level does commaNeeded[++ctx->depth] with no bound check;
     * past depth 100 this writes out of bounds inside CtxJson on the heap. */
    size_t bufLen = 1 << 16;
    uint8_t *buf = (uint8_t*)malloc(bufLen);
    uint8_t *pos = buf;
    const uint8_t *end = buf + bufLen;
    UA_StatusCode rc = UA_encodeJson(root, &UA_TYPES[UA_TYPES_VARIANT],
                                     &pos, &end, NULL, 0, NULL, 0, true);
    printf("[*] UA_encodeJson -> 0x%08x (encoded %ld bytes)\n",
           rc, (long)(pos - buf));
    if(rc == UA_STATUSCODE_GOOD)
        printf("[*] no overflow caught at depth %zu (patched build path)\n", depth);

    free(buf);
    for(size_t i = 0; i < depth; ++i) { free(chain[i]); }
    for(size_t i = 1; i < depth; ++i) { free(eos[i]); }
    free(chain);
    free(eos);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf("=================================================\n");
    printf("  REAL open62541 CVE-2020-36429 (JSON encode OOB)\n");
    printf("  Library: open62541 v1.0.1 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Trigger: JSON-encode a Variant nested > 100 levels deep\n");
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
    printf("[*] Listening on %d (depth-controlled JSON encode endpoint)\n", PORT);

    for(;;) {
        int c = accept(srv, NULL, NULL);
        if(c < 0) continue;
        printf("[*] Client connected\n");

        /* 2-byte little-endian requested nesting depth. */
        unsigned char d[2];
        ssize_t n = recv(c, d, 2, MSG_WAITALL);
        if(n == 2) {
            size_t depth = (size_t)d[0] | ((size_t)d[1] << 8);
            handle_depth(depth);
        }
        close(c);
    }
    return 0;
}
