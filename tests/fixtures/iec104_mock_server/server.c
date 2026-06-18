/*
 * IEC 104 Mock Server with File Transfer Support
 * For testing c104 Python library
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "cs104_slave.h"
#include "cs101_file_service.h"
#include "hal_thread.h"
#include "hal_time.h"

static bool running = true;

/* Force unbuffered output */
#define LOG(fmt, ...) do { \
    printf(fmt, ##__VA_ARGS__); \
    fflush(stdout); \
} while(0)

void sigint_handler(int signalId) {
    LOG("[SIGNAL] Caught SIGINT, shutting down...\n");
    running = false;
}

static sCS101_StaticASDU _asdu;
static uint8_t ioBuf[250];

/* File data */
static int fileSize = 256;
static uint8_t fileData[256];

static uint64_t getFileDate(CS101_IFileProvider self) {
    LOG("[FILE] getFileDate() called\n");
    return Hal_getTimeInMs();
}

static int getFileSize(CS101_IFileProvider self) {
    LOG("[FILE] getFileSize() -> %d bytes\n", fileSize);
    return fileSize;
}

static int getSectionSize(CS101_IFileProvider self, int sectionNumber) {
    int size = (sectionNumber == 0) ? fileSize : 0;
    LOG("[FILE] getSectionSize(section=%d) -> %d bytes\n", sectionNumber, size);
    return size;
}

static bool getSegmentData(CS101_IFileProvider self, int sectionNumber, int offset, int size, uint8_t* data) {
    LOG("[FILE] getSegmentData(section=%d, offset=%d, size=%d)\n", sectionNumber, offset, size);
    if (sectionNumber == 0 && offset + size <= fileSize) {
        memcpy(data, fileData + offset, size);
        LOG("[FILE] -> Data copied successfully\n");
        return true;
    }
    LOG("[FILE] -> ERROR: Invalid section or offset\n");
    return false;
}

static void transferComplete(CS101_IFileProvider self, bool success) {
    LOG("[FILE] Transfer complete: %s\n", success ? "SUCCESS" : "FAILED");
}

static struct sCS101_IFileProvider fileProviders[2];
static int numberOfFiles = 2;

static void initializeFiles() {
    LOG("[INIT] Initializing files...\n");

    /* File 1: test.dat at IOA 30000 */
    fileProviders[0].ca = 1;
    fileProviders[0].ioa = 30000;
    fileProviders[0].nof = CS101_NOF_TRANSPARENT_FILE;
    fileProviders[0].object = NULL;
    fileProviders[0].getFileSize = getFileSize;
    fileProviders[0].getFileDate = getFileDate;
    fileProviders[0].getSectionSize = getSectionSize;
    fileProviders[0].getSegmentData = getSegmentData;
    fileProviders[0].transferComplete = transferComplete;
    LOG("[INIT] File 1: CA=1, IOA=30000, type=TRANSPARENT\n");

    /* File 2: config.dat at IOA 30001 */
    fileProviders[1].ca = 1;
    fileProviders[1].ioa = 30001;
    fileProviders[1].nof = CS101_NOF_TRANSPARENT_FILE;
    fileProviders[1].object = NULL;
    fileProviders[1].getFileSize = getFileSize;
    fileProviders[1].getFileDate = getFileDate;
    fileProviders[1].getSectionSize = getSectionSize;
    fileProviders[1].getSegmentData = getSegmentData;
    fileProviders[1].transferComplete = transferComplete;
    LOG("[INIT] File 2: CA=1, IOA=30001, type=TRANSPARENT\n");

    /* Initialize file data with pattern */
    for (int i = 0; i < fileSize; i++) {
        fileData[i] = (uint8_t)(i & 0xFF);
    }
    LOG("[INIT] File data initialized (%d bytes)\n", fileSize);
}

static CS101_IFileProvider getNextFile(void* parameter, CS101_IFileProvider continueAfter) {
    LOG("[FILE] getNextFile() called, continueAfter=%p\n", (void*)continueAfter);

    if (continueAfter == NULL) {
        LOG("[FILE] -> Returning first file (IOA=30000)\n");
        return &fileProviders[0];
    }

    for (int i = 0; i < numberOfFiles - 1; i++) {
        if (continueAfter == &fileProviders[i]) {
            LOG("[FILE] -> Returning file %d (IOA=%d)\n", i+1, fileProviders[i+1].ioa);
            return &fileProviders[i + 1];
        }
    }

    LOG("[FILE] -> No more files (returning NULL)\n");
    return NULL;
}

static CS101_IFileProvider getFile(void* parameter, int ca, int ioa, uint16_t nof, int* errCode) {
    LOG("[FILE] getFile(CA=%d, IOA=%d, NOF=%d)\n", ca, ioa, nof);

    for (int i = 0; i < numberOfFiles; i++) {
        if ((ca == fileProviders[i].ca) && (ioa == fileProviders[i].ioa)) {
            LOG("[FILE] -> Found file at index %d\n", i);
            *errCode = 0;
            return &fileProviders[i];
        }
    }

    LOG("[FILE] -> File NOT FOUND\n");
    *errCode = 1;
    return NULL;
}

static bool interrogationHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi) {
    LOG("[CMD] Interrogation received (QOI=%d)\n", qoi);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

    LOG("[CMD] Sending ACT_CON...\n");
    IMasterConnection_sendACT_CON(connection, asdu, false);

    CS101_ASDU newAsdu = CS101_ASDU_initializeStatic(&_asdu, alParams, false,
        CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);

    CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
        MeasuredValueScaled_create((MeasuredValueScaled)&ioBuf, 100, 1234, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
        MeasuredValueScaled_create((MeasuredValueScaled)&ioBuf, 101, 5678, IEC60870_QUALITY_GOOD));

    LOG("[CMD] Sending M_ME_NB_1 (IOA 100, 101)...\n");
    IMasterConnection_sendASDU(connection, newAsdu);

    newAsdu = CS101_ASDU_initializeStatic(&_asdu, alParams, false,
        CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);

    CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
        SinglePointInformation_create((SinglePointInformation)&ioBuf, 200, true, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
        SinglePointInformation_create((SinglePointInformation)&ioBuf, 201, false, IEC60870_QUALITY_GOOD));

    LOG("[CMD] Sending M_SP_NA_1 (IOA 200, 201)...\n");
    IMasterConnection_sendASDU(connection, newAsdu);

    LOG("[CMD] Sending ACT_TERM...\n");
    IMasterConnection_sendACT_TERM(connection, asdu);

    return true;
}

static bool asduHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu) {
    int typeId = CS101_ASDU_getTypeID(asdu);
    int cot = CS101_ASDU_getCOT(asdu);
    int ca = CS101_ASDU_getCA(asdu);

    LOG("[ASDU] Received: TypeID=%d (%s), COT=%d, CA=%d\n",
        typeId,
        (typeId == 122) ? "F_SC_NA_1" :
        (typeId == 126) ? "F_DR_TA_1" :
        (typeId == 100) ? "C_IC_NA_1" : "OTHER",
        cot, ca);

    /* Log information objects */
    int numElements = CS101_ASDU_getNumberOfElements(asdu);
    LOG("[ASDU] Number of elements: %d\n", numElements);

    for (int i = 0; i < numElements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (io) {
            int ioa = InformationObject_getObjectAddress(io);
            LOG("[ASDU] Element %d: IOA=%d\n", i, ioa);
            InformationObject_destroy(io);
        }
    }

    /* Return false to let plugins (file server) handle it */
    LOG("[ASDU] Passing to plugins...\n");
    return false;
}

static bool connectionRequestHandler(void* parameter, const char* ipAddress) {
    LOG("[CONN] Connection request from %s -> ACCEPTED\n", ipAddress);
    return true;
}

static void connectionEventHandler(void* parameter, IMasterConnection con, CS104_PeerConnectionEvent event) {
    const char* eventName;
    switch (event) {
        case CS104_CON_EVENT_CONNECTION_OPENED:
            eventName = "OPENED";
            break;
        case CS104_CON_EVENT_CONNECTION_CLOSED:
            eventName = "CLOSED";
            break;
        case CS104_CON_EVENT_ACTIVATED:
            eventName = "ACTIVATED (STARTDT)";
            break;
        case CS104_CON_EVENT_DEACTIVATED:
            eventName = "DEACTIVATED (STOPDT)";
            break;
        default:
            eventName = "UNKNOWN";
    }
    LOG("[CONN] Event: %s (connection=%p)\n", eventName, (void*)con);
}

static void rawMessageHandler(void* parameter, IMasterConnection con, uint8_t* msg, int msgSize, bool sent) {
    LOG("[RAW] %s (%d bytes): ", sent ? "TX" : "RX", msgSize);
    for (int i = 0; i < msgSize && i < 50; i++) {
        printf("%02x ", msg[i]);
    }
    if (msgSize > 50) printf("...");
    printf("\n");
    fflush(stdout);

    /* Decode APDU type */
    if (msgSize >= 6) {
        uint8_t ctrl = msg[2];
        if ((ctrl & 0x01) == 0) {
            /* I-frame */
            if (msgSize >= 10) {
                uint8_t typeId = msg[6];
                uint8_t cot = msg[8] & 0x3F;
                LOG("[RAW] -> I-frame: TypeID=%d, COT=%d\n", typeId, cot);
            }
        } else if ((ctrl & 0x03) == 1) {
            LOG("[RAW] -> S-frame\n");
        } else {
            uint8_t uType = (ctrl >> 2) & 0x3F;
            const char* uName = "UNKNOWN";
            if (uType == 1) uName = "STARTDT ACT";
            else if (uType == 2) uName = "STARTDT CON";
            else if (uType == 4) uName = "STOPDT ACT";
            else if (uType == 8) uName = "STOPDT CON";
            else if (uType == 16) uName = "TESTFR ACT";
            else if (uType == 32) uName = "TESTFR CON";
            LOG("[RAW] -> U-frame: %s\n", uName);
        }
    }
}

int main(int argc, char** argv) {
    /* Disable stdout buffering */
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    LOG("============================================\n");
    LOG("  IEC 104 Mock Server with File Transfer\n");
    LOG("============================================\n");
    LOG("Port: 2404\n");
    LOG("Common Address: 1\n");
    LOG("Files available:\n");
    LOG("  - IOA 30000: test.dat (256 bytes)\n");
    LOG("  - IOA 30001: config.dat (256 bytes)\n");
    LOG("============================================\n\n");

    LOG("[INIT] Creating CS104 slave...\n");
    CS104_Slave slave = CS104_Slave_create(100, 100);

    if (slave == NULL) {
        LOG("[ERROR] Failed to create CS104 slave!\n");
        return 1;
    }

    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, 2404);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);
    LOG("[INIT] Server configured: 0.0.0.0:2404\n");

    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);

    LOG("[INIT] Setting up handlers...\n");
    CS104_Slave_setInterrogationHandler(slave, interrogationHandler, NULL);
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);
    CS104_Slave_setConnectionRequestHandler(slave, connectionRequestHandler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, connectionEventHandler, NULL);
    CS104_Slave_setRawMessageHandler(slave, rawMessageHandler, NULL);

    /* Setup file server */
    LOG("[INIT] Creating file server...\n");
    CS101_FileServer fileServer = CS101_FileServer_create(alParams);

    if (fileServer == NULL) {
        LOG("[ERROR] Failed to create file server!\n");
        CS104_Slave_destroy(slave);
        return 1;
    }

    initializeFiles();

    struct sCS101_FilesAvailable filesAvailable;
    filesAvailable.getFile = getFile;
    filesAvailable.getNextFile = getNextFile;
    filesAvailable.parameter = NULL;

    CS101_FileServer_setFilesAvailableIfc(fileServer, &filesAvailable);
    CS104_Slave_addPlugin(slave, CS101_FileServer_getSlavePlugin(fileServer));
    LOG("[INIT] File server plugin added\n");

    LOG("[INIT] Starting server...\n");
    CS104_Slave_start(slave);

    if (!CS104_Slave_isRunning(slave)) {
        LOG("[ERROR] Failed to start server!\n");
        CS101_FileServer_destroy(fileServer);
        CS104_Slave_destroy(slave);
        return 1;
    }

    LOG("[READY] Server running. Waiting for connections...\n\n");

    while (running) {
        Thread_sleep(100);
    }

    LOG("\n[SHUTDOWN] Stopping server...\n");
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    CS101_FileServer_destroy(fileServer);
    LOG("[SHUTDOWN] Server stopped.\n");

    return 0;
}
