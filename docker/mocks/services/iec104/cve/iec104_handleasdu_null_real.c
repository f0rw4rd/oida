/**
 * Real lib60870-C CS104 slave NULL-pointer dereference (CWE-476)
 * via a short I-frame whose ASDU body is smaller than the ASDU header.
 *
 * Vulnerability (confirmed present at tags v0.9.4, v2.0.0, v2.0.1, v2.1.0,
 * v2.1.1; fixed in v2.2.0 / commit 1b0c06d8 "CS104 slave: added more
 * message integrity checks"):
 *
 *   src/iec60870/cs104/cs104_slave.c :: handleMessage(), I-frame branch
 *
 *     CS101_ASDU asdu =
 *         CS101_ASDU_createFromBuffer(&(self->slave->alParameters),
 *                                     buffer + 6, msgSize - 6);
 *     handleASDU(self, asdu);          // <-- asdu may be NULL, NOT checked
 *     CS101_ASDU_destroy(asdu);
 *
 *   src/iec60870/cs101/cs101_asdu.c :: CS101_ASDU_createFromBuffer()
 *     int asduHeaderLength = 2 + sizeOfCOT(2) + sizeOfCA(2);   // = 6
 *     if (msgLength < asduHeaderLength) return NULL;            // short body
 *
 *   src/iec60870/cs104/cs104_slave.c :: handleASDU()
 *     uint8_t cot = CS101_ASDU_getCOT(asdu);   // CS101_ASDU_getCOT(NULL)
 *                                              //  -> self->asdu[2] on NULL
 *                                              //  -> SIGSEGV (read @ 0x2)
 *
 * Reachability (unauthenticated, single crafted frame over CS104/TCP 2404):
 *   1. STARTDT_ACT (U-frame 68 04 07 00 00 00) sets self->isActive = true.
 *   2. A short I-frame with total on-wire size in [7..11] bytes. For the
 *      first I-frame N(S) must equal receiveCount (0) and N(R) (0) passes
 *      checkSequenceNumber against the empty sent-buffer.
 *      msgSize-6 is then 1..5 < 6  ->  createFromBuffer returns NULL  ->
 *      handleASDU(NULL) -> getCOT(NULL) -> NULL deref.
 *
 * This is a genuine NULL-pointer dereference (read of address ~0x2), so it
 * SIGSEGVs natively. ASan is used only to produce a clean, symbolized
 * SEGV report pointing at the exact function:file:line. No poison fence is
 * needed - the access is past nothing, it is a literal NULL deref.
 *
 * Distinct from the two sibling tasks:
 *   - NOT the C_TS_TA_1 (107) getElementEx per-element NULL deref (that is a
 *     newer-tag switch-case bug; here the WHOLE asdu is NULL and the crash
 *     precedes the switch entirely - and type 107 does not even exist yet).
 *   - NOT the CS101_ASDU_createFromBuffer index/elementSize math: here
 *     createFromBuffer behaves correctly (returns NULL by design); the bug
 *     is the CALLER in cs104_slave.c failing to NULL-check the result.
 *
 * Minimal CS104 slave modelled on
 * lib60870-C/examples/cs104_server/simple_server.c at v2.0.0.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"

static bool running = true;

static void
sigint_handler(int signalId)
{
    (void) signalId;
    running = false;
}

/* NOTE: CS104_Slave_setRawMessageHandler does not exist at v2.0.0, so we do
 * not register one. The crash is independent of any handler - it fires in the
 * library's own handleMessage/handleASDU dispatch. */

int
main(int argc, char** argv)
{
    (void) argc;
    (void) argv;

    setbuf(stdout, NULL);

    const char* portStr = getenv("IEC104_PORT");
    int port = portStr ? atoi(portStr) : 2404;
    if (port <= 0)
        port = 2404;

    signal(SIGINT, sigint_handler);

    printf("===========================================\n");
    printf("  REAL lib60870-C CS104 handleASDU NULL-deref Server\n");
    printf("  Using: lib60870-C v2.0.0 (vulnerable)\n");
    printf("  Port: %d\n", port);
    printf("  Trigger: STARTDT_ACT then a short I-frame (7..11 bytes);\n");
    printf("           createFromBuffer returns NULL, handleASDU(NULL)\n");
    printf("           -> CS101_ASDU_getCOT(NULL) NULL deref\n");
    printf("===========================================\n");

    CS104_Slave slave = CS104_Slave_create(100, 100);

    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

    CS104_Slave_start(slave);

    if (CS104_Slave_isRunning(slave) == false) {
        printf("[!] Starting CS104 slave failed!\n");
        CS104_Slave_destroy(slave);
        return 1;
    }

    printf("[*] Listening on 0.0.0.0:%d ...\n", port);

    while (running)
        Thread_sleep(100);

    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    return 0;
}
