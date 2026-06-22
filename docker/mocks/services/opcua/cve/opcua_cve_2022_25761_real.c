/**
 * Real CVE-2022-25761 - actual vulnerable open62541 v1.2.4 SecureChannel
 *
 * Vulnerability: Denial of Service (CWE-770, missing limit on resources).
 * open62541 < 1.2.5 / 1.3-rc1..< 1.3.1 leave localMaxChunkCount and
 * localMaxMessageSize at 0 (== unlimited). In src/ua_securechannel.c the
 * resource-limit guard inside processChunks() is:
 *     if((config.localMaxChunkCount  != 0 && decryptedChunksCount  > ...) ||
 *        (config.localMaxMessageSize != 0 && decryptedChunksLength > ...))
 *         return UA_STATUSCODE_BADTCPMESSAGETOOLARGE;
 * With both limits 0 the guard is DEAD: every INTERMEDIATE MSG chunk is appended
 * to channel->decryptedChunks and only drained when a FINAL chunk arrives. An
 * attacker that streams INTERMEDIATE chunks and never sends FINAL grows the heap
 * without bound -> OOM. Reported by Team82 (Claroty); fixed in v1.2.5 / v1.3.1
 * by commit b79db1ac (default chunk/message limits).
 *
 * This harness feeds attacker bytes straight into the GENUINE vulnerable
 * UA_SecureChannel_processBuffer() -- the exact entry point open62541's own
 * tests/fuzz/fuzz_tcp_message.cc drives -- with the GENUINE default
 * UA_ConnectionConfig (limits = 0) and a real SecurityPolicy#None attached via
 * UA_SecureChannel_setSecurityPolicy(). The unbounded-accumulation code is the
 * code under test; we add no vulnerable logic. The build defines
 * FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION so the channelId / token / sequence
 * checks are skipped exactly as in the upstream fuzzer, letting None MSG chunks
 * reach the accumulation path without a full OPN handshake.
 *
 * CLASS: resource-exhaustion DoS (NOT memory corruption) -> ASan does not abort.
 * The failure is made OBSERVABLE by a self-watchdog that measures the bytes the
 * SecureChannel is currently retaining and SIGABRTs once it crosses a threshold
 * the patched build caps; the container also runs under a hard memory limit so
 * the kernel OOM-killer (exit 137) reaps it if the watchdog were bypassed.
 */

#include <open62541/types.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ua_securechannel.h"

#define PORT 4840
/* A single legitimate message is bounded by localMaxMessageSize in a patched
 * build. Retaining a quarter-GB of never-finalised chunks proves the leak. */
#define RETAINED_ABORT_BYTES (256ull * 1024 * 1024)

static volatile size_t g_retained = 0;
static volatile int    g_active = 0;

static void *watchdog(void *arg) {
    (void)arg;
    for(;;) {
        if(g_active && g_retained > RETAINED_ABORT_BYTES) {
            fprintf(stderr,
                "\n[WATCHDOG] CVE-2022-25761 TRIGGERED: real open62541 v1.2.4 "
                "SecureChannel retained %zu bytes of INTERMEDIATE MSG chunks "
                "with no FINAL chunk. localMaxChunkCount=0 / localMaxMessageSize=0 "
                "leave the processChunks() resource guard dead -> unbounded "
                "accumulation in src/ua_securechannel.c.\n", g_retained);
            fflush(stderr);
            abort();   /* SIGABRT -> observable in `docker logs` */
        }
        usleep(50 * 1000);
    }
    return NULL;
}

static UA_StatusCode
msgCallback(void *app, UA_SecureChannel *ch, UA_MessageType mt,
            UA_UInt32 reqId, UA_ByteString *msg) {
    (void)app; (void)ch; (void)mt; (void)reqId; (void)msg;
    return UA_STATUSCODE_GOOD;   /* only reached if a FINAL chunk completes a msg */
}

static size_t retained_bytes(UA_SecureChannel *ch) {
    size_t held = ch->incompleteChunk.length;
    UA_Chunk *c;
    SIMPLEQ_FOREACH(c, &ch->completeChunks, pointers) held += c->bytes.length;
    SIMPLEQ_FOREACH(c, &ch->decryptedChunks, pointers) held += c->bytes.length;
    held += ch->decryptedChunksLength;
    return held;
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf("=================================================\n");
    printf("  REAL open62541 CVE-2022-25761 (chunk DoS)\n");
    printf("  Library: open62541 v1.2.4 (vulnerable)\n");
    printf("  Port: %d  Trigger: unlimited INTERMEDIATE MSG chunks\n", PORT);
    printf("  Default config: localMaxChunkCount=0 localMaxMessageSize=0\n");
    printf("=================================================\n");

    pthread_t wd;
    pthread_create(&wd, NULL, watchdog, NULL);

    /* GENUINE default connection config -> the unlimited limits (the bug). */
    UA_ConnectionConfig cc;
    memset(&cc, 0, sizeof(cc));
    cc.recvBufferSize       = 1 << 16;
    cc.sendBufferSize       = 1 << 16;
    cc.localMaxMessageSize  = 0;   /* THE BUG: 0 == unlimited */
    cc.remoteMaxMessageSize = 0;
    cc.localMaxChunkCount   = 0;   /* THE BUG: 0 == unlimited */
    cc.remoteMaxChunkCount  = 0;

    /* Real SecurityPolicy#None to attach to the channel. */
    UA_SecurityPolicy sp;
    memset(&sp, 0, sizeof(sp));
    UA_ByteString nocert = UA_BYTESTRING_NULL;
    UA_StatusCode spr = UA_SecurityPolicy_None(&sp, nocert, UA_Log_Stdout);
    if(spr != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "UA_SecurityPolicy_None failed 0x%08x\n", spr);
        return 1;
    }

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
    printf("[*] Listening on %d (real SecureChannel + SecurityPolicy#None)\n", PORT);

    for(;;) {
        int c = accept(srv, NULL, NULL);
        if(c < 0) continue;
        printf("[*] Client connected; feeding bytes to real SecureChannel\n");

        UA_SecureChannel channel;
        UA_SecureChannel_init(&channel, &cc);
        UA_SecureChannel_setSecurityPolicy(&channel, &sp, &nocert);
        channel.securityMode = UA_MESSAGESECURITYMODE_NONE;
        channel.securityToken.channelId = 1;
        channel.securityToken.tokenId = 1;
        /* A live, non-expired token so checkSymHeader's lifetime check passes
         * (otherwise the very first chunk closes the channel). */
        channel.securityToken.createdAt = UA_DateTime_nowMonotonic();
        channel.securityToken.revisedLifetime = 3600000;   /* 1h */
        channel.state = UA_SECURECHANNELSTATE_OPEN;

        g_retained = 0;
        g_active = 1;
        size_t nchunks = 0;
        printf("[*] channel.config.recvBufferSize=%u localMaxChunkCount=%u "
               "localMaxMessageSize=%u\n",
               channel.config.recvBufferSize, channel.config.localMaxChunkCount,
               channel.config.localMaxMessageSize);

        /* Feed ONE complete chunk per processBuffer call, each in its own heap
         * buffer that lives for the whole connection (a real network layer
         * hands fresh buffers and the channel copies what it keeps). Reading
         * whole chunks avoids the incompleteChunk/realloc span path so the
         * INTERMEDIATE chunks land cleanly in decryptedChunks and accumulate -
         * which is exactly the CVE-2022-25761 unbounded growth. */
        for(;;) {
            UA_Byte hdr[8];
            ssize_t h = recv(c, hdr, 8, MSG_WAITALL);
            if(h != 8) break;
            uint32_t msgSize = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                               ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
            if(msgSize < 8 || msgSize > cc.recvBufferSize) break;

            UA_Byte *chunkbuf = (UA_Byte*)malloc(msgSize);   /* lives for the conn */
            memcpy(chunkbuf, hdr, 8);
            size_t got = 8;
            while(got < msgSize) {
                ssize_t r = recv(c, chunkbuf + got, msgSize - got, MSG_WAITALL);
                if(r <= 0) break;
                got += (size_t)r;
            }
            if(got != msgSize) { free(chunkbuf); break; }

            UA_ByteString buffer = { msgSize, chunkbuf };
            /* THE VULNERABLE CALL: genuine library, genuine default config. */
            UA_StatusCode rc =
                UA_SecureChannel_processBuffer(&channel, NULL, msgCallback, &buffer);

            g_retained = retained_bytes(&channel);
            nchunks++;
            if(nchunks <= 3 || (nchunks % 256) == 0)
                printf("[*] chunk %zu sz=%u rc=0x%08x decryptedChunksCount=%zu "
                       "decryptedChunksLength=%zu retained~%zu MB\n",
                       nchunks, msgSize, rc, channel.decryptedChunksCount,
                       channel.decryptedChunksLength, g_retained / (1024 * 1024));
            /* Safe to free: UA_SecureChannel_processBuffer ends with
             * persistCompleteChunks(), which UA_ByteString_copy()s every chunk
             * the channel retains into channel-owned heap. So memory growth we
             * observe is the LIBRARY's retained chunk queue (the CVE), not our
             * input buffer. */
            free(chunkbuf);
        }

        g_active = 0;
        printf("[*] Client gone; clearing channel (retained=%zu)\n",
               retained_bytes(&channel));
        UA_SecureChannel_close(&channel);
        UA_SecureChannel_deleteBuffered(&channel);
        close(c);
    }

    sp.clear(&sp);
    return 0;
}
