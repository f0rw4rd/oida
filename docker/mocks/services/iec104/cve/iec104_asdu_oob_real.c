/**
 * Real lib60870-C CS104 slave heap out-of-bounds READ (CWE-125).
 *
 * Distinct from GHSA-75pr (NULL deref in C_TS_TA_1) and from the *contained*
 * GHSA-7v97 read at v2.4.0. This is the SAME class of bug as GHSA-7v97
 * (unbounded element parse driven by an oversized VSQ), but at tag v2.2.0 it
 * is GENUINELY network-reachable and the read crosses the heap allocation,
 * so AddressSanitizer catches it NATIVELY (no poison fence required).
 *
 * ---------------------------------------------------------------------------
 * ROOT CAUSE (confirmed by reading source at tag v2.2.0, commit 4414e78):
 *
 *   The "unified length checks when decoding information objects" were added
 *   in commit 58001d6 (2019-12-01), which first ships in tag v2.2.1. At
 *   v2.2.0 and earlier, EVERY per-element parser in
 *   src/iec60870/cs101/cs101_information_objects.c lacks the
 *       int minSize = startIndex + dataSize;
 *       if (minSize > msgSize) return NULL;
 *   guard. The parsers receive `msgSize` (== self->payloadSize, honest) but
 *   never compare against it. E.g. FileDirectory_getFromBuffer() has no size
 *   check at all and reads msg[startIndex] directly:
 *       cs101_information_objects.c :: FileDirectory_getFromBuffer()
 *       -> InformationObject_getFromBuffer()
 *       -> InformationObject_ParseObjectAddress()   reads msg[startIndex]
 *
 *   The CS104 slave receive path:
 *       cs104_slave.c handleMessage() -> CS101_ASDU_createFromBuffer(buffer+6,
 *       msgSize-6) -> handleASDU(). createFromBufferEx points self->payload
 *       into the 260-byte heap recvBuffer (member of the GLOBAL_CALLOC'd
 *       sMasterConnection) and sets payloadSize = honest received length.
 *
 *       CS101_ASDU_getNumberOfElements() returns VSQ & 0x7f (attacker-chosen,
 *       up to 127) with NO validation that those elements fit payloadSize.
 *       CS101_ASDU_getElementEx(asdu, NULL, index) computes
 *           startIndex = index * (sizeOfIOA + elementSize)
 *       and hands it to the unguarded parser.
 *
 *   For TypeID F_DR_TA_1 (126, "File directory") elementSize = 13 and
 *   sizeOfIOA = 3, so with index = 126 the parser reads at
 *       startIndex = 126 * (3 + 13) = 2016
 *   bytes past payload start -- far beyond the 260-byte recvBuffer and beyond
 *   the whole sMasterConnection heap object -> heap-buffer-overflow READ.
 *
 *   F_DR_TA_1 is NOT one of the TypeIDs the slave handles internally, so
 *   handleASDU() falls through to the user asduHandler (cs104_slave.c ~1916).
 *   The handler below iterates every VSQ-declared element, driving the OOB.
 *
 *   Fixed in v2.2.1 / commit 58001d6 (the 62 added minSize>msgSize guards).
 *
 * ---------------------------------------------------------------------------
 * Reachability: pre-auth over CS104/TCP 2404. Send STARTDT_ACT to activate,
 * then a single crafted I-frame (TypeID 126, VSQ=127, tiny body). No custom
 * server config beyond registering the element-iterating asduHandler -- which
 * is exactly how a real File-directory-capable slave would be written.
 *
 * Modelled on lib60870-C/examples/cs104_server/simple_server.c at v2.2.0.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"

static volatile bool running = true;

static void
sigint_handler(int signalId)
{
    (void)signalId;
    running = false;
}

/* Log raw inbound APDUs so the PoC trail is visible in `docker logs`. */
static void
rawMessageHandler(void *parameter, IMasterConnection connection, uint8_t *msg, int msgSize, bool sent)
{
    (void)parameter;
    (void)connection;
    printf(sent ? "SEND:" : "RCVD:");
    for (int i = 0; i < msgSize; i++)
        printf(" %02x", msg[i]);
    printf("\n");
}

/* Catch-all ASDU handler for TypeIDs not handled internally by the slave
 * (e.g. F_DR_TA_1 / 126). We iterate EVERY VSQ-declared element: with a
 * crafted oversized VSQ this drives CS101_ASDU_getElementEx() far past the
 * received payload -> unguarded FileDirectory_getFromBuffer ->
 * InformationObject_ParseObjectAddress OOB read (v2.2.0). */
static bool
asduHandler(void *parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    (void)parameter;
    (void)connection;

    int typeId = CS101_ASDU_getTypeID(asdu);
    int count = CS101_ASDU_getNumberOfElements(asdu);

    printf("[*] asduHandler: TypeID=%d VSQ-count=%d (iterating all elements)\n",
           typeId, count);

    for (int i = 0; i < count; i++) {
        /* getElement(i) -> getElementEx with startIndex = i*(sizeOfIOA+elemSize).
         * At v2.2.0 the parser has no msgSize bound check -> OOB read. */
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (io) {
            (void)InformationObject_getObjectAddress(io);
            InformationObject_destroy(io);
        }
    }

    return true;
}

int
main(void)
{
    const char *portEnv = getenv("IEC104_PORT");
    int port = portEnv ? atoi(portEnv) : 2404;
    if (port <= 0)
        port = 2404;

    setbuf(stdout, NULL);

    signal(SIGINT, sigint_handler);

    printf("===========================================\n");
    printf("  REAL lib60870-C ASDU element OOB-read Slave\n");
    printf("  Using: lib60870-C v2.2.0 (vulnerable)\n");
    printf("  CWE-125 heap OOB read in ParseObjectAddress\n");
    printf("  via unguarded FileDirectory_getFromBuffer\n");
    printf("  Port: %d\n", port);
    printf("  Trigger: I-frame TypeID 126 (F_DR_TA_1), VSQ=127,\n");
    printf("           tiny body -> getElement(126) reads +2016 bytes\n");
    printf("===========================================\n");

    CS104_Slave slave = CS104_Slave_create(10, 10);
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

    CS104_Slave_setRawMessageHandler(slave, rawMessageHandler, NULL);
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);

    CS104_Slave_start(slave);

    if (CS104_Slave_isRunning(slave) == false) {
        printf("[!] Starting server failed!\n");
        CS104_Slave_destroy(slave);
        return 1;
    }

    printf("[*] Listening on 0.0.0.0:%d ...\n", port);

    while (running)
        Thread_sleep(50);

    printf("[*] Stopping server\n");
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    return 0;
}
