/*
 * goose_publisher_real.c -- env-configurable IEC 61850 GOOSE publisher
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A long-running GOOSE publisher built on libiec61850 (MZ Automation,
 * https://github.com/mz-automation/libiec61850, GPLv3 / commercial dual
 * license). This file links against libiec61850 and uses its genuine
 * GoosePublisher API to emit REAL IEC 61850-8-1 GOOSE frames
 * (EtherType 0x88B8, dst MAC 01:0c:cd:01:xx:xx) -- not a hand-rolled
 * BER simulation.
 *
 * It generalises the upstream examples/goose_publisher/goose_publisher_example.c
 * (which hardcodes AppID/GoCBRef/dataset and runs only 4 iterations) into a
 * forever-running, fully env-driven publisher so multiple distinct
 * configurations can run side by side for OIDA's GOOSE listener tests.
 *
 * Environment variables (all optional, with defaults):
 *   GOOSE_INTERFACE       Network interface to publish on        (default: eth0)
 *   GOOSE_APPID           Application ID, decimal or 0x-hex       (default: 4096 = 0x1000)
 *   GOOSE_GOCB_REF        GoCB reference string                  (default: simpleIOGenericIO/LLN0$GO$gcb01)
 *   GOOSE_DATASET_REF     Dataset reference string               (default: simpleIOGenericIO/LLN0$dataset1)
 *   GOOSE_GO_ID           GOOSE ID string                        (default: value of GOOSE_GOCB_REF)
 *   GOOSE_CONF_REV        Configuration revision                 (default: 1)
 *   GOOSE_VLAN_ID         VLAN id (0 = no VLAN tag)              (default: 0)
 *   GOOSE_VLAN_PRIORITY   VLAN priority                          (default: 4)
 *   GOOSE_TTL_MS          timeAllowedToLive in ms                (default: 2000)
 *   GOOSE_INTERVAL_MS     Retransmission interval in ms          (default: 1000)
 *   GOOSE_STATE_INTERVAL_MS  Simulated state-change interval ms  (default: 10000)
 *   GOOSE_DST_LAST_OCTET  Last octet of dst MAC 01:0c:cd:01:00:xx (default: 1)
 *
 * Must run with NET_RAW (raw L2 socket). Run as root / --cap-add=NET_RAW.
 *
 * FOR AUTHORIZED SECURITY TESTING ONLY.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "mms_value.h"
#include "goose_publisher.h"
#include "hal_thread.h"

static volatile sig_atomic_t running = 1;

static void
stop_handler(int sig)
{
    (void) sig;
    running = 0;
}

static const char *
env_str(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

static long
env_long(const char *name, long fallback)
{
    const char *v = getenv(name);
    if (!v || !*v)
        return fallback;
    /* strtol with base 0 handles both decimal and 0x-hex */
    return strtol(v, NULL, 0);
}

int
main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGTERM, stop_handler);
    signal(SIGINT, stop_handler);

    /* interface: argv[1] overrides env overrides default, matching upstream */
    const char *interface = (argc > 1) ? argv[1] : env_str("GOOSE_INTERFACE", "eth0");

    long appId          = env_long("GOOSE_APPID", 0x1000);
    const char *gocbRef = env_str("GOOSE_GOCB_REF", "simpleIOGenericIO/LLN0$GO$gcb01");
    const char *datSet  = env_str("GOOSE_DATASET_REF", "simpleIOGenericIO/LLN0$dataset1");
    const char *goId    = env_str("GOOSE_GO_ID", gocbRef);
    long confRev        = env_long("GOOSE_CONF_REV", 1);
    long vlanId         = env_long("GOOSE_VLAN_ID", 0);
    long vlanPrio       = env_long("GOOSE_VLAN_PRIORITY", 4);
    long ttlMs          = env_long("GOOSE_TTL_MS", 2000);
    long intervalMs     = env_long("GOOSE_INTERVAL_MS", 1000);
    long stateIntMs     = env_long("GOOSE_STATE_INTERVAL_MS", 10000);
    long dstLast        = env_long("GOOSE_DST_LAST_OCTET", 1);

    printf("===========================================\n");
    printf("  REAL IEC 61850 GOOSE Publisher (libiec61850)\n");
    printf("  Interface   : %s\n", interface);
    printf("  AppID       : %ld (0x%04lX)\n", appId, appId & 0xFFFF);
    printf("  GoCBRef     : %s\n", gocbRef);
    printf("  DataSetRef  : %s\n", datSet);
    printf("  GoID        : %s\n", goId);
    printf("  ConfRev     : %ld\n", confRev);
    printf("  VLAN        : id=%ld prio=%ld\n", vlanId, vlanPrio);
    printf("  TTL         : %ld ms\n", ttlMs);
    printf("  Interval    : %ld ms\n", intervalMs);
    printf("  StateChange : every %ld ms\n", stateIntMs);
    printf("  Dst MAC     : 01:0c:cd:01:00:%02lx\n", dstLast & 0xFF);
    printf("  FOR AUTHORIZED SECURITY TESTING ONLY\n");
    printf("===========================================\n");

    /* Build the dataset: a representative protection-IED payload.
     * Members (4): BOOLEAN breaker pos, INT32 tap pos, INT32 measurement, BINARY-TIME.
     * The first two members are mutated on each state change for observable variation. */
    LinkedList dataSetValues = LinkedList_create();
    MmsValue *valBool  = MmsValue_newBoolean(false);
    MmsValue *valTap   = MmsValue_newIntegerFromInt32(0);
    MmsValue *valMeas  = MmsValue_newIntegerFromInt32(2305);
    MmsValue *valTime  = MmsValue_newBinaryTime(false);
    LinkedList_add(dataSetValues, valBool);
    LinkedList_add(dataSetValues, valTap);
    LinkedList_add(dataSetValues, valMeas);
    LinkedList_add(dataSetValues, valTime);

    CommParameters gooseCommParameters;
    gooseCommParameters.appId = (uint16_t) appId;
    gooseCommParameters.dstAddress[0] = 0x01;
    gooseCommParameters.dstAddress[1] = 0x0c;
    gooseCommParameters.dstAddress[2] = 0xcd;
    gooseCommParameters.dstAddress[3] = 0x01;
    gooseCommParameters.dstAddress[4] = 0x00;
    gooseCommParameters.dstAddress[5] = (uint8_t) dstLast;
    gooseCommParameters.vlanId = (uint16_t) vlanId;
    gooseCommParameters.vlanPriority = (uint8_t) vlanPrio;

    GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters, interface);

    if (!publisher) {
        printf("Failed to create GOOSE publisher. The interface '%s' may not exist "
               "or NET_RAW/root is required.\n", interface);
        LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);
        return 1;
    }

    GoosePublisher_setGoID(publisher, (char *) goId);
    GoosePublisher_setGoCbRef(publisher, (char *) gocbRef);
    GoosePublisher_setConfRev(publisher, (uint32_t) confRev);
    GoosePublisher_setDataSetRef(publisher, (char *) datSet);
    GoosePublisher_setTimeAllowedToLive(publisher, (uint32_t) ttlMs);

    long elapsedSinceState = 0;
    bool breakerOpen = false;
    int32_t tap = 0;
    unsigned long published = 0;

    while (running) {
        /* Simulate a process value change: bump stNum (resets sqNum), mutate data. */
        if (elapsedSinceState >= stateIntMs) {
            elapsedSinceState = 0;
            breakerOpen = !breakerOpen;
            tap++;
            MmsValue_setBoolean(valBool, breakerOpen);
            MmsValue_setInt32(valTap, tap);
            GoosePublisher_increaseStNum(publisher);  /* stNum++, sqNum -> 0 */
            printf("State change: breaker=%s tap=%d (stNum bumped)\n",
                   breakerOpen ? "OPEN" : "CLOSED", tap);
        }

        if (GoosePublisher_publish(publisher, dataSetValues) == -1)
            printf("Error sending GOOSE message!\n");
        else
            published++;

        if (published % 60 == 0 && published > 0)
            printf("Published %lu GOOSE frames\n", published);

        Thread_sleep((int) intervalMs);
        elapsedSinceState += intervalMs;
    }

    printf("Shutting down after %lu frames\n", published);
    GoosePublisher_destroy(publisher);
    LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);
    return 0;
}
