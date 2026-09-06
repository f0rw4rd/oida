/**
 * Real CVE-2026-1301 - actual vulnerable open62541 v1.5.0-rc2 JSON PubSub decoder
 *
 * Vulnerability: heap out-of-bounds WRITE (CWE-787), pre-authentication.
 *
 * In src/pubsub/ua_pubsub_networkmessage_json.c the function
 *   DataSetPayload_decodeJsonInternal()
 * sizes the DataSetMessage keyFrameFields array to the number of key/value
 * pairs *present in the received JSON payload*:
 *
 *     size_t length = (ctx->ctx.tokens[index].size) / 2;            // pairs in payload
 *     dsm->data.keyFrameFields = UA_Array_new(length, ...DATAVALUE);// length entries
 *     ...
 *     for(size_t i = 0; i < length; ++i) {
 *         decode fieldName;
 *         size_t index = decodingFieldIndex(emd, fieldName, i);     // index into METADATA
 *         UA_DataValue_clear(&dsm->data.keyFrameFields[index]);     // <-- NO BOUND CHECK
 *         decodeJsonJumpTable[DATAVALUE](&dsm->data.keyFrameFields[index], ...);
 *     }
 *
 * decodingFieldIndex() resolves the field NAME against the receiver's configured
 * encoding metadata (emd->fields[]) and returns the metadata index of that name.
 * If the configured metadata declares MORE fields than the payload carries
 * (the normal case for sparse / delta updates), a payload field whose name maps
 * to a metadata index >= length yields keyFrameFields[index] OUT OF BOUNDS of the
 * `length`-element allocation -> heap-buffer-overflow WRITE in UA_DataValue_clear
 * (and again in the subsequent DataValue decode).
 *
 * Fixed in v1.5.0 by commit 425ff6345 ("fix(pubsub): Out-of-bounds field index
 * from FieldMetadata names") which adds:
 *     if(index >= length) { UA_String_clear(&fieldName); return BADDECODINGERROR; }
 *
 * Reported by Andrew Fasano (NIST CAISI). Advisory ICSA-26-036-03.
 * Affected: open62541 >=1.5-rc1, <1.5-rc2 fix line (built here at v1.5.0-rc2,
 * which still carries the unguarded write). Reachable BEFORE authentication via
 * a UDP/MQTT JSON PubSub NetworkMessage processed by a JSON-enabled receiver.
 *
 * --- THIS HARNESS ---
 * Models a real OPC UA PubSub-over-JSON receiver. It owns a *configured*
 * DataSetReader: encoding metadata with 8 named fields (DataSetWriterId 1) -- this
 * is static receiver configuration, NOT attacker input. It then reads the raw JSON
 * NetworkMessage bytes off the network and feeds them, unmodified, to the GENUINE
 * exported library entry point UA_NetworkMessage_decodeJson(). The attacker controls
 * only the JSON bytes. The OOB write happens inside the library, on library data
 * (the heap UA_DataValue array), and is caught natively by ASan. The harness contains
 * NO abort()/exit() on a status code -- the fault is a real memory error in
 * DataSetPayload_decodeJsonInternal, exactly the function named by the fix commit.
 *
 * CLASS: heap OOB write (CWE-787). ASan -> heap-buffer-overflow WRITE -> SIGABRT.
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <open62541/types.h>
#include <open62541/types_generated.h>
#include <open62541/pubsub.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4840
#define MAX_MSG (1 << 16)

/* The receiver's static configuration: 8 named fields. A genuine DataSetReader
 * declares the fields it expects (here indices 0..7). Field "Energy" sits at
 * index 7. This is configuration the operator sets, not attacker-controlled. */
#define METADATA_FIELDS 8
static const char *field_names[METADATA_FIELDS] = {
    "Temperature", "Pressure", "Humidity", "Vibration",
    "Voltage", "Current", "Status", "Energy"
};

/* Decode one received JSON NetworkMessage with the genuine library decoder.
 * `json`/`json_len` are attacker bytes straight off the socket. */
static void decode_message(const unsigned char *json, size_t json_len) {
    UA_FieldMetaData fmd[METADATA_FIELDS];
    memset(fmd, 0, sizeof(fmd));
    for(size_t i = 0; i < METADATA_FIELDS; i++)
        fmd[i].name = UA_STRING((char *)(uintptr_t)field_names[i]);

    UA_DataSetMessage_EncodingMetaData emd;
    memset(&emd, 0, sizeof(emd));
    emd.dataSetWriterId = 1;
    emd.fields = fmd;
    emd.fieldsSize = METADATA_FIELDS;   /* 8 configured fields */

    UA_NetworkMessage_EncodingOptions eo;
    memset(&eo, 0, sizeof(eo));
    eo.metaData = &emd;
    eo.metaDataSize = 1;

    UA_ByteString bs;
    bs.length = json_len;
    bs.data = (UA_Byte *)(uintptr_t)json;

    UA_NetworkMessage nm;
    memset(&nm, 0, sizeof(nm));

    printf("[*] Feeding %zu bytes of JSON NetworkMessage to "
           "UA_NetworkMessage_decodeJson (8 configured metadata fields)\n", json_len);

    /* THE VULNERABLE CALL: genuine exported decoder. With a payload smaller than
     * the configured metadata and a field name resolving to a metadata index
     * past the (payload-sized) keyFrameFields allocation, the unguarded
     * keyFrameFields[index] write in DataSetPayload_decodeJsonInternal goes OOB. */
    UA_StatusCode rc = UA_NetworkMessage_decodeJson(&bs, &nm, &eo, NULL);

    printf("[*] decodeJson returned 0x%08x (no OOB on this input -> patched/benign path)\n", rc);
    UA_NetworkMessage_clear(&nm);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf("=================================================\n");
    printf("  REAL open62541 CVE-2026-1301 (JSON PubSub OOB write)\n");
    printf("  Library: open62541 v1.5.0-rc2 (vulnerable)\n");
    printf("  Func:    DataSetPayload_decodeJsonInternal\n");
    printf("  Port:    %d\n", PORT);
    printf("  Trigger: JSON PubSub msg, payload field name maps to a\n");
    printf("           metadata index past the payload-sized allocation\n");
    printf("=================================================\n");

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    listen(srv, 4);
    printf("[*] Listening on %d (raw JSON NetworkMessage endpoint)\n", PORT);

    for(;;) {
        int c = accept(srv, NULL, NULL);
        if(c < 0) continue;
        printf("[*] Client connected\n");

        unsigned char buf[MAX_MSG];
        size_t total = 0;
        ssize_t n;
        /* Read the whole JSON message until peer half-closes or buffer fills. */
        while(total < sizeof(buf) - 1 &&
              (n = recv(c, buf + total, sizeof(buf) - 1 - total, 0)) > 0) {
            total += (size_t)n;
        }
        if(total > 0) {
            buf[total] = 0;
            decode_message(buf, total);
        }
        close(c);
    }
    return 0;
}
