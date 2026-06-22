/**
 * Real GHSA-75pr-rr3v-j6px (CWE-690/476) - lib60870-C CS104 slave
 * NULL pointer dereference in the test-command handler.
 *
 * Vulnerability (confirmed at tag v2.3.5, fixed in v2.3.6 / commit 0c5487f):
 *   src/iec60870/cs104/cs104_slave.c :: handleASDU(), case C_TS_TA_1 (107)
 *
 *     TestCommandWithCP56Time2a tc =
 *         (TestCommandWithCP56Time2a) CS101_ASDU_getElementEx(asdu, &_io, 0);
 *
 *     // Verify IOA = 0  <-- NO "if (tc)" guard at v2.3.5
 *     if (InformationObject_getObjectAddress((InformationObject) tc) != 0)
 *         ...
 *
 * When the test-command ASDU is truncated (payloadSize < 9),
 * TestCommandWithCP56Time2a_getFromBuffer() hits its
 * "minSize > msgSize -> return NULL" path, so getElementEx returns NULL.
 * The slave then dereferences tc->objectAddress (in
 * InformationObject_getObjectAddress) -> SIGSEGV.
 *
 * The deref lives inside the "cot != CS101_COT_ACTIVATION" branch, so the
 * PoC sends C_TS_TA_1 with a COT other than activation(6) and a truncated body.
 *
 * This is a minimal CS104 slave modelled on
 * lib60870-C/examples/cs104_server/simple_server.c at v2.3.5.
 * Pre-auth, reachable over CS104/TCP 2404. No custom handler is needed:
 * the built-in test-command handling in cs104_slave.c is the vulnerable code.
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

/* Log every raw APDU sent/received so the PoC trail is visible in docker logs. */
static void
rawMessageHandler(void* parameter, IMasterConnection connection, uint8_t* msg, int msgSize, bool sent)
{
    (void) parameter;
    (void) connection;
    printf(sent ? "SEND: " : "RCVD: ");
    for (int i = 0; i < msgSize; i++)
        printf("%02x ", msg[i]);
    printf("\n");
}

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
    printf("  REAL lib60870-C GHSA-75pr-rr3v-j6px Server\n");
    printf("  Using: lib60870-C v2.3.5 (vulnerable)\n");
    printf("  Port: %d\n", port);
    printf("  Trigger: truncated C_TS_TA_1 (107) test command,\n");
    printf("           COT != activation -> NULL deref in handleASDU\n");
    printf("===========================================\n");

    CS104_Slave slave = CS104_Slave_create(100, 100);

    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);
    CS104_Slave_setRawMessageHandler(slave, rawMessageHandler, NULL);

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
