/*
 * IEC 60870-5-104/101 Mock Server
 *
 * A comprehensive mock server using lib60870 for testing MSF-ICS IEC 104/101 scanner.
 * Supports multiple data types, general interrogation, commands, and file transfer.
 *
 * IEC 104 Mode (TCP):
 *   Build: gcc -o iec104_server iec104_server.c -l60870 -lpthread
 *   Usage: ./iec104_server -p 2404
 *
 * IEC 101 Mode (Serial):
 *   Usage: ./iec104_server -s /dev/ttyUSB0 -b 9600 -a 1
 *
 * Both modes simultaneously:
 *   Usage: ./iec104_server -p 2404 -s /dev/ttyUSB0 -b 9600
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <getopt.h>

/* IEC 104 (TCP) */
#include "cs104_slave.h"

/* IEC 101 (Serial) */
#include "cs101_slave.h"
#include "hal_serial.h"
#include "link_layer_parameters.h"

/* Common */
#include "cs101_file_service.h"
#include "hal_time.h"
#include "hal_thread.h"

/* Configuration */
#define DEFAULT_PORT 2404
#define COMMON_ADDRESS 1

/* Data point ranges */
#define SP_START_IOA 100      /* Single points: 100-119 */
#define SP_COUNT 20
#define DP_START_IOA 200      /* Double points: 200-209 */
#define DP_COUNT 10
#define ST_START_IOA 300      /* Step positions: 300-309 */
#define ST_COUNT 10
#define BO_START_IOA 400      /* Bitstrings: 400-409 */
#define BO_COUNT 10
#define ME_NA_START_IOA 500   /* Normalized values: 500-519 */
#define ME_NA_COUNT 20
#define ME_NB_START_IOA 600   /* Scaled values: 600-619 */
#define ME_NB_COUNT 20
#define ME_NC_START_IOA 700   /* Float values: 700-719 */
#define ME_NC_COUNT 20
#define IT_START_IOA 800      /* Integrated totals: 800-809 */
#define IT_COUNT 10

/* File transfer IOAs */
#define FILE_DIR_IOA 10000
#define FILE_CONFIG_IOA 10001
#define FILE_LOG_IOA 10002
#define FILE_EVENTS_IOA 10003

/* File transfer configuration */
#define NUM_FILES 3
#define MAX_FILE_SIZE 4096
#define SEGMENT_SIZE 200

/* Data storage */
static bool single_points[SP_COUNT];
static uint8_t double_points[DP_COUNT];
static int8_t step_positions[ST_COUNT];
static uint32_t bitstrings[BO_COUNT];
static float normalized_values[ME_NA_COUNT];
static int16_t scaled_values[ME_NB_COUNT];
static float float_values[ME_NC_COUNT];
static int32_t integrated_totals[IT_COUNT];

/* Server state */
static bool running = true;
static CS104_Slave slave = NULL;
static int verbose = 0;

/* IEC 101 state */
static CS101_Slave cs101_slave = NULL;
static SerialPort serialPort = NULL;
static char* serial_port_path = NULL;
static int baud_rate = 9600;
static int link_address = 1;
static bool balanced_mode = false;

/* File transfer state */
static CS101_FileServer fileServer = NULL;
static struct sCS101_IFileProvider fileProviders[NUM_FILES];
static uint8_t fileData[NUM_FILES][MAX_FILE_SIZE];
static int fileSizes[NUM_FILES];
static const char* fileNames[NUM_FILES] = {"config.xml", "events.log", "parameters.cfg"};
static int fileIOAs[NUM_FILES] = {FILE_CONFIG_IOA, FILE_LOG_IOA, FILE_EVENTS_IOA};

/* File receiver for uploads */
static struct sCS101_IFileReceiver uploadReceiver;
static FILE* uploadFile = NULL;

/* Custom file transfer state (since we're not using the plugin) */
typedef enum {
    FT_STATE_IDLE = 0,
    FT_STATE_FILE_SELECTED,
    FT_STATE_SECTION_READY,
    FT_STATE_TRANSMITTING,
    FT_STATE_WAITING_SECTION_ACK,
    FT_STATE_WAITING_FILE_ACK
} FileTransferState;

static FileTransferState ftState = FT_STATE_IDLE;
static int ftSelectedFile = -1;
static int ftCurrentSection = 0;
static int ftCurrentOffset = 0;
static IMasterConnection ftConnection = NULL;

/* Signal handler */
static void signal_handler(int signum) {
    printf("\n[*] Received signal %d, shutting down...\n", signum);
    running = false;
}

/* Initialize data points with realistic values */
static void init_data_points(void) {
    srand(time(NULL));

    /* Single points - alternating pattern */
    for (int i = 0; i < SP_COUNT; i++) {
        single_points[i] = (i % 2 == 0);
    }

    /* Double points - intermediate, on, off pattern */
    for (int i = 0; i < DP_COUNT; i++) {
        double_points[i] = (i % 3) + 1;  /* 1=off, 2=on, 3=intermediate */
    }

    /* Step positions */
    for (int i = 0; i < ST_COUNT; i++) {
        step_positions[i] = (i * 10) - 50;  /* -50 to +40 */
    }

    /* Bitstrings */
    for (int i = 0; i < BO_COUNT; i++) {
        bitstrings[i] = (uint32_t)(rand() & 0xFFFFFFFF);
    }

    /* Normalized values (0.0 to 1.0) */
    for (int i = 0; i < ME_NA_COUNT; i++) {
        normalized_values[i] = (float)i / (float)ME_NA_COUNT;
    }

    /* Scaled values */
    for (int i = 0; i < ME_NB_COUNT; i++) {
        scaled_values[i] = (int16_t)(i * 1000 - 10000);
    }

    /* Float values - simulate process values */
    for (int i = 0; i < ME_NC_COUNT; i++) {
        float_values[i] = 100.0f + (float)i * 10.0f + ((float)(rand() % 100) / 10.0f);
    }

    /* Integrated totals */
    for (int i = 0; i < IT_COUNT; i++) {
        integrated_totals[i] = i * 10000;
    }

    printf("[*] Initialized %d data points\n",
           SP_COUNT + DP_COUNT + ST_COUNT + BO_COUNT +
           ME_NA_COUNT + ME_NB_COUNT + ME_NC_COUNT + IT_COUNT);
}

/* ========================================================================
 * File Transfer Implementation (Type IDs 120-127)
 * ======================================================================== */

/* Get file index from IOA */
static int get_file_index(int ioa) {
    for (int i = 0; i < NUM_FILES; i++) {
        if (fileIOAs[i] == ioa)
            return i;
    }
    return -1;
}

/* File provider callbacks */
static uint64_t file_getFileDate(CS101_IFileProvider self) {
    /* Return current time as file date */
    return Hal_getTimeInMs();
}

static int file_getFileSize(CS101_IFileProvider self) {
    int idx = get_file_index(self->ioa);
    if (idx >= 0) {
        printf("[FILE] getFileSize(IOA=%d) -> %d bytes\n", self->ioa, fileSizes[idx]);
        return fileSizes[idx];
    }
    return 0;
}

static int file_getSectionSize(CS101_IFileProvider self, int sectionNumber) {
    /* Single section file - return full file size for section 0 */
    if (sectionNumber == 0) {
        int idx = get_file_index(self->ioa);
        if (idx >= 0) {
            printf("[FILE] getSectionSize(IOA=%d, section=%d) -> %d\n",
                   self->ioa, sectionNumber, fileSizes[idx]);
            return fileSizes[idx];
        }
    }
    return 0;
}

static bool file_getSegmentData(CS101_IFileProvider self, int sectionNumber,
                                 int offset, int size, uint8_t* data) {
    int idx = get_file_index(self->ioa);
    if (idx >= 0 && sectionNumber == 0) {
        if (offset + size <= fileSizes[idx]) {
            memcpy(data, fileData[idx] + offset, size);
            printf("[FILE] getSegmentData(IOA=%d, offset=%d, size=%d) -> OK\n",
                   self->ioa, offset, size);
            return true;
        }
    }
    printf("[FILE] getSegmentData(IOA=%d) -> FAILED\n", self->ioa);
    return false;
}

static void file_transferComplete(CS101_IFileProvider self, bool success) {
    printf("[FILE] Transfer complete (IOA=%d, success=%d)\n", self->ioa, success);
}

/* Directory listing callbacks */
static int currentFileIndex = 0;

static CS101_IFileProvider files_getNextFile(void* parameter, CS101_IFileProvider continueAfter) {
    if (continueAfter == NULL) {
        currentFileIndex = 0;
    } else {
        currentFileIndex++;
    }

    if (currentFileIndex < NUM_FILES) {
        printf("[FILE] getNextFile -> %s (IOA=%d)\n",
               fileNames[currentFileIndex], fileIOAs[currentFileIndex]);
        return &fileProviders[currentFileIndex];
    }

    printf("[FILE] getNextFile -> NULL (end of directory)\n");
    return NULL;
}

static CS101_IFileProvider files_getFile(void* parameter, int ca, int ioa,
                                          uint16_t nof, int* errCode) {
    printf("[FILE] getFile(CA=%d, IOA=%d, NOF=%d)\n", ca, ioa, nof);

    for (int i = 0; i < NUM_FILES; i++) {
        if (fileIOAs[i] == ioa && ca == COMMON_ADDRESS) {
            *errCode = 0;
            return &fileProviders[i];
        }
    }

    *errCode = 2;  /* Unknown IOA */
    return NULL;
}

/* File upload (receive) callbacks */
static void upload_finished(CS101_IFileReceiver self, CS101_FileErrorCode result) {
    printf("[FILE] Upload finished (result=%d)\n", result);
    if (uploadFile) {
        fclose(uploadFile);
        uploadFile = NULL;
    }
    if (result != CS101_FILE_ERROR_SUCCESS) {
        remove("/tmp/iec104_upload.dat");
    }
}

static void upload_segmentReceived(CS101_IFileReceiver self, uint8_t sectionName,
                                    int offset, int size, uint8_t* data) {
    printf("[FILE] Upload segment (section=%d, offset=%d, size=%d)\n",
           sectionName, offset, size);
    if (uploadFile) {
        fwrite(data, size, 1, uploadFile);
    }
}

static CS101_IFileReceiver file_fileReadyHandler(void* parameter, int ca, int ioa,
                                                   uint16_t nof, int lengthOfFile, int* err) {
    printf("[FILE] File ready handler (CA=%d, IOA=%d, NOF=%d, len=%d)\n",
           ca, ioa, nof, lengthOfFile);

    /* Accept uploads to IOA 10100 */
    if (ca == COMMON_ADDRESS && ioa == 10100) {
        uploadFile = fopen("/tmp/iec104_upload.dat", "wb");
        if (uploadFile) {
            uploadReceiver.object = uploadFile;
            uploadReceiver.finished = upload_finished;
            uploadReceiver.segmentReceived = upload_segmentReceived;
            *err = 0;
            printf("[FILE] Accepting file upload\n");
            return &uploadReceiver;
        }
    }

    *err = 2;  /* Unknown IOA */
    printf("[FILE] Rejecting file upload\n");
    return NULL;
}

/* Initialize file transfer subsystem */
static void init_file_transfer(CS101_AppLayerParameters alParams) {
    printf("[*] Initializing file transfer...\n");

    /* Create sample file content */
    const char* configXml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<config>\n"
        "  <device name=\"IEC104-Mock\" version=\"1.0\"/>\n"
        "  <network>\n"
        "    <port>2404</port>\n"
        "    <address>1</address>\n"
        "  </network>\n"
        "  <security>\n"
        "    <authentication>none</authentication>\n"
        "    <encryption>false</encryption>\n"
        "  </security>\n"
        "</config>\n";

    const char* eventsLog =
        "2024-01-01 00:00:00 [INFO] System started\n"
        "2024-01-01 00:00:01 [INFO] Network interface up\n"
        "2024-01-01 00:00:02 [INFO] IEC 104 server listening on port 2404\n"
        "2024-01-01 00:01:00 [INFO] Connection from 192.168.1.100\n"
        "2024-01-01 00:01:05 [INFO] General interrogation received\n"
        "2024-01-01 00:02:00 [WARN] Connection timeout from 192.168.1.100\n"
        "2024-01-01 00:05:00 [INFO] Connection from 192.168.1.101\n"
        "2024-01-01 00:05:10 [INFO] File transfer request received\n";

    const char* paramsCfg =
        "# IEC 104 Parameters\n"
        "COMMON_ADDRESS=1\n"
        "T0_TIMEOUT=30\n"
        "T1_TIMEOUT=15\n"
        "T2_TIMEOUT=10\n"
        "T3_TIMEOUT=20\n"
        "K_VALUE=12\n"
        "W_VALUE=8\n"
        "MAX_ASDU_SIZE=253\n";

    /* Copy file content */
    fileSizes[0] = strlen(configXml);
    memcpy(fileData[0], configXml, fileSizes[0]);

    fileSizes[1] = strlen(eventsLog);
    memcpy(fileData[1], eventsLog, fileSizes[1]);

    fileSizes[2] = strlen(paramsCfg);
    memcpy(fileData[2], paramsCfg, fileSizes[2]);

    /* Initialize file providers */
    for (int i = 0; i < NUM_FILES; i++) {
        fileProviders[i].ca = COMMON_ADDRESS;
        fileProviders[i].ioa = fileIOAs[i];
        fileProviders[i].nof = CS101_NOF_TRANSPARENT_FILE;
        fileProviders[i].object = NULL;
        fileProviders[i].getFileDate = file_getFileDate;
        fileProviders[i].getFileSize = file_getFileSize;
        fileProviders[i].getSectionSize = file_getSectionSize;
        fileProviders[i].getSegmentData = file_getSegmentData;
        fileProviders[i].transferComplete = file_transferComplete;

        printf("  - %s (IOA=%d, size=%d bytes)\n",
               fileNames[i], fileIOAs[i], fileSizes[i]);
    }

    /* Create file server */
    fileServer = CS101_FileServer_create(alParams);

    /* Set file availability interface */
    static struct sCS101_FilesAvailable filesAvailable;
    filesAvailable.getNextFile = files_getNextFile;
    filesAvailable.getFile = files_getFile;
    filesAvailable.parameter = NULL;

    CS101_FileServer_setFilesAvailableIfc(fileServer, &filesAvailable);
    CS101_FileServer_setFileReadyHandler(fileServer, file_fileReadyHandler, NULL);

    printf("[*] File transfer initialized with %d files\n", NUM_FILES);
}

/* Simulate data changes */
static void simulate_data_changes(void) {
    /* Randomly toggle a single point */
    int sp_idx = rand() % SP_COUNT;
    single_points[sp_idx] = !single_points[sp_idx];

    /* Update float values with sine wave */
    static float t = 0;
    t += 0.1f;
    for (int i = 0; i < ME_NC_COUNT; i++) {
        float base = 100.0f + (float)i * 10.0f;
        float_values[i] = base + 20.0f * sinf(t + i * 0.5f) + ((float)(rand() % 20) - 10.0f) / 10.0f;
    }

    /* Increment integrated totals */
    for (int i = 0; i < IT_COUNT; i++) {
        integrated_totals[i] += rand() % 100;
    }
}

/* Get current timestamp */
static CP56Time2a get_current_time(void) {
    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());
    return timestamp;
}

/* Connection event handler */
static void connection_event_handler(void* parameter, IMasterConnection connection, CS104_PeerConnectionEvent event) {
    char* eventStr = "UNKNOWN";
    switch (event) {
        case CS104_CON_EVENT_CONNECTION_OPENED:
            eventStr = "OPENED";
            break;
        case CS104_CON_EVENT_CONNECTION_CLOSED:
            eventStr = "CLOSED";
            break;
        case CS104_CON_EVENT_ACTIVATED:
            eventStr = "ACTIVATED";
            break;
        case CS104_CON_EVENT_DEACTIVATED:
            eventStr = "DEACTIVATED";
            break;
    }
    printf("[+] Connection event: %s\n", eventStr);
}

/* Raw message handler for IEC 101 debugging */
static void rawMessageHandler101(void* parameter, uint8_t* msg, int msgSize, bool sent) {
    if (sent) {
        printf("[101] TX: ");
    } else {
        printf("[101] RX: ");
    }
    for (int i = 0; i < msgSize; i++) {
        printf("%02x ", msg[i]);
    }
    printf("\n");
    fflush(stdout);
}

/* Clock synchronization handler */
static bool clock_sync_handler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, CP56Time2a newTime) {
    printf("[*] Clock synchronization received\n");
    return true;
}

/* Interrogation handler - sends all data points */
static bool interrogation_handler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi) {
    printf("[GI] General interrogation handler called! QOI=%d\n", qoi);
    fflush(stdout);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

    /* Send single point information (M_SP_NA_1, Type 1) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < SP_COUNT; i++) {
            InformationObject io = (InformationObject) SinglePointInformation_create(NULL,
                SP_START_IOA + i, single_points[i], IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d single points (Type 1)\n", SP_COUNT);
    }

    /* Send double point information (M_DP_NA_1, Type 3) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < DP_COUNT; i++) {
            InformationObject io = (InformationObject) DoublePointInformation_create(NULL,
                DP_START_IOA + i, (DoublePointValue)double_points[i], IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d double points (Type 3)\n", DP_COUNT);
    }

    /* Send step position information (M_ST_NA_1, Type 5) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < ST_COUNT; i++) {
            InformationObject io = (InformationObject) StepPositionInformation_create(NULL,
                ST_START_IOA + i, step_positions[i], false, IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d step positions (Type 5)\n", ST_COUNT);
    }

    /* Send bitstring (M_BO_NA_1, Type 7) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < BO_COUNT; i++) {
            InformationObject io = (InformationObject) BitString32_create(NULL,
                BO_START_IOA + i, bitstrings[i]);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d bitstrings (Type 7)\n", BO_COUNT);
    }

    /* Send normalized measured values (M_ME_NA_1, Type 9) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < ME_NA_COUNT; i++) {
            InformationObject io = (InformationObject) MeasuredValueNormalized_create(NULL,
                ME_NA_START_IOA + i, normalized_values[i], IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d normalized values (Type 9)\n", ME_NA_COUNT);
    }

    /* Send scaled measured values (M_ME_NB_1, Type 11) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < ME_NB_COUNT; i++) {
            InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL,
                ME_NB_START_IOA + i, scaled_values[i], IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d scaled values (Type 11)\n", ME_NB_COUNT);
    }

    /* Send short float measured values (M_ME_NC_1, Type 13) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < ME_NC_COUNT; i++) {
            InformationObject io = (InformationObject) MeasuredValueShort_create(NULL,
                ME_NC_START_IOA + i, float_values[i], IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d float values (Type 13)\n", ME_NC_COUNT);
    }

    /* Send integrated totals (M_IT_NA_1, Type 15) */
    {
        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                                0, COMMON_ADDRESS, false, false);
        for (int i = 0; i < IT_COUNT; i++) {
            BinaryCounterReading bcr = BinaryCounterReading_create(NULL, integrated_totals[i], 0, false, false, false);
            InformationObject io = (InformationObject) IntegratedTotals_create(NULL,
                IT_START_IOA + i, bcr);
            CS101_ASDU_addInformationObject(newAsdu, io);
            InformationObject_destroy(io);
            BinaryCounterReading_destroy(bcr);
        }
        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);
        if (verbose) printf("  Sent %d integrated totals (Type 15)\n", IT_COUNT);
    }

    /* Send interrogation termination */
    CS101_ASDU termAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_TERMINATION,
                                             0, COMMON_ADDRESS, false, false);
    CS101_ASDU_setTypeID(termAsdu, C_IC_NA_1);
    InformationObject io = (InformationObject) InterrogationCommand_create(NULL, 0, qoi);
    CS101_ASDU_addInformationObject(termAsdu, io);
    InformationObject_destroy(io);
    IMasterConnection_sendASDU(connection, termAsdu);
    CS101_ASDU_destroy(termAsdu);

    int total = SP_COUNT + DP_COUNT + ST_COUNT + BO_COUNT + ME_NA_COUNT + ME_NB_COUNT + ME_NC_COUNT + IT_COUNT;
    printf("[*] Interrogation complete: sent %d data points\n", total);

    return true;
}

/* Counter interrogation handler */
static bool counter_interrogation_handler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, QualifierOfCIC qcc) {
    printf("[*] Counter interrogation (QCC=%d)\n", qcc);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

    /* Send integrated totals - use COT_INTERROGATED_BY_STATION since counter-specific COT may not exist */
    CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                            0, COMMON_ADDRESS, false, false);
    for (int i = 0; i < IT_COUNT; i++) {
        BinaryCounterReading bcr = BinaryCounterReading_create(NULL, integrated_totals[i], 0, false, false, false);
        InformationObject io = (InformationObject) IntegratedTotals_create(NULL,
            IT_START_IOA + i, bcr);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
        BinaryCounterReading_destroy(bcr);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);

    return true;
}

/* Read command handler */
static bool read_handler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, int ioa) {
    printf("[*] Read command for IOA %d\n", ioa);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);
    CS101_ASDU newAsdu = NULL;
    InformationObject io = NULL;

    /* Single points */
    if (ioa >= SP_START_IOA && ioa < SP_START_IOA + SP_COUNT) {
        int idx = ioa - SP_START_IOA;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST, 0, COMMON_ADDRESS, false, false);
        io = (InformationObject) SinglePointInformation_create(NULL, ioa, single_points[idx], IEC60870_QUALITY_GOOD);
    }
    /* Double points */
    else if (ioa >= DP_START_IOA && ioa < DP_START_IOA + DP_COUNT) {
        int idx = ioa - DP_START_IOA;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST, 0, COMMON_ADDRESS, false, false);
        io = (InformationObject) DoublePointInformation_create(NULL, ioa, (DoublePointValue)double_points[idx], IEC60870_QUALITY_GOOD);
    }
    /* Float values */
    else if (ioa >= ME_NC_START_IOA && ioa < ME_NC_START_IOA + ME_NC_COUNT) {
        int idx = ioa - ME_NC_START_IOA;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST, 0, COMMON_ADDRESS, false, false);
        io = (InformationObject) MeasuredValueShort_create(NULL, ioa, float_values[idx], IEC60870_QUALITY_GOOD);
    }
    else {
        printf("  IOA %d not found\n", ioa);
        return false;
    }

    if (newAsdu && io) {
        CS101_ASDU_addInformationObject(newAsdu, io);
        IMasterConnection_sendASDU(connection, newAsdu);
        InformationObject_destroy(io);
        CS101_ASDU_destroy(newAsdu);
        return true;
    }

    return false;
}

/* ASDU handler for commands */
static bool asdu_handler(void* parameter, IMasterConnection connection, CS101_ASDU asdu) {
    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);
    IEC60870_5_TypeID typeId = CS101_ASDU_getTypeID(asdu);
    int ioa = InformationObject_getObjectAddress(CS101_ASDU_getElement(asdu, 0));

    printf("[ASDU] Type=%d IOA=%d COT=%d CA=%d\n",
           typeId, ioa, CS101_ASDU_getCOT(asdu), CS101_ASDU_getCA(asdu));
    fflush(stdout);

    if (verbose) {
        printf("[*] Received ASDU Type=%d IOA=%d\n", typeId, ioa);
    }

    switch (typeId) {
        case C_SC_NA_1: /* Single command */
        {
            SingleCommand sc = (SingleCommand) CS101_ASDU_getElement(asdu, 0);
            bool value = SingleCommand_getState(sc);
            printf("[!] Single command: IOA=%d Value=%d\n", ioa, value);

            /* Update single point if in range */
            if (ioa >= SP_START_IOA && ioa < SP_START_IOA + SP_COUNT) {
                single_points[ioa - SP_START_IOA] = value;

                /* Send confirmation */
                CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_CON,
                                                        0, COMMON_ADDRESS, false, false);
                InformationObject io = (InformationObject) SingleCommand_create(NULL, ioa, value, false, 0);
                CS101_ASDU_addInformationObject(newAsdu, io);
                IMasterConnection_sendASDU(connection, newAsdu);
                InformationObject_destroy(io);
                CS101_ASDU_destroy(newAsdu);
            }
            break;
        }

        case C_DC_NA_1: /* Double command */
        {
            DoubleCommand dc = (DoubleCommand) CS101_ASDU_getElement(asdu, 0);
            int value = DoubleCommand_getState(dc);
            printf("[!] Double command: IOA=%d Value=%d\n", ioa, value);

            if (ioa >= DP_START_IOA && ioa < DP_START_IOA + DP_COUNT) {
                double_points[ioa - DP_START_IOA] = value;

                /* Send confirmation */
                CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_CON,
                                                        0, COMMON_ADDRESS, false, false);
                InformationObject io = (InformationObject) DoubleCommand_create(NULL, ioa, value, false, 0);
                CS101_ASDU_addInformationObject(newAsdu, io);
                IMasterConnection_sendASDU(connection, newAsdu);
                InformationObject_destroy(io);
                CS101_ASDU_destroy(newAsdu);
            }
            break;
        }

        case C_RC_NA_1: /* Step command */
        {
            StepCommand rc = (StepCommand) CS101_ASDU_getElement(asdu, 0);
            int value = StepCommand_getState(rc);
            printf("[!] Step command: IOA=%d Value=%d\n", ioa, value);

            if (ioa >= ST_START_IOA && ioa < ST_START_IOA + ST_COUNT) {
                /* HIGHER=1, LOWER=2 in IEC 104 */
                if (value == 1)
                    step_positions[ioa - ST_START_IOA]++;
                else if (value == 2)
                    step_positions[ioa - ST_START_IOA]--;

                /* Send confirmation */
                CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_CON,
                                                        0, COMMON_ADDRESS, false, false);
                InformationObject io = (InformationObject) StepCommand_create(NULL, ioa, value, false, 0);
                CS101_ASDU_addInformationObject(newAsdu, io);
                IMasterConnection_sendASDU(connection, newAsdu);
                InformationObject_destroy(io);
                CS101_ASDU_destroy(newAsdu);
            }
            break;
        }

        case C_SE_NA_1: /* Setpoint (normalized) */
        {
            SetpointCommandNormalized scn = (SetpointCommandNormalized) CS101_ASDU_getElement(asdu, 0);
            float value = SetpointCommandNormalized_getValue(scn);
            printf("[!] Setpoint command (normalized): IOA=%d Value=%.4f\n", ioa, value);

            if (ioa >= ME_NA_START_IOA && ioa < ME_NA_START_IOA + ME_NA_COUNT) {
                normalized_values[ioa - ME_NA_START_IOA] = value;

                /* Send confirmation */
                CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_CON,
                                                        0, COMMON_ADDRESS, false, false);
                InformationObject io = (InformationObject) SetpointCommandNormalized_create(NULL, ioa, value, false, 0);
                CS101_ASDU_addInformationObject(newAsdu, io);
                IMasterConnection_sendASDU(connection, newAsdu);
                InformationObject_destroy(io);
                CS101_ASDU_destroy(newAsdu);
            }
            break;
        }

        case C_SE_NB_1: /* Setpoint (scaled) */
        {
            SetpointCommandScaled scs = (SetpointCommandScaled) CS101_ASDU_getElement(asdu, 0);
            int value = SetpointCommandScaled_getValue(scs);
            printf("[!] Setpoint command (scaled): IOA=%d Value=%d\n", ioa, value);

            if (ioa >= ME_NB_START_IOA && ioa < ME_NB_START_IOA + ME_NB_COUNT) {
                scaled_values[ioa - ME_NB_START_IOA] = (int16_t) value;

                /* Send confirmation */
                CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_CON,
                                                        0, COMMON_ADDRESS, false, false);
                InformationObject io = (InformationObject) SetpointCommandScaled_create(NULL, ioa, value, false, 0);
                CS101_ASDU_addInformationObject(newAsdu, io);
                IMasterConnection_sendASDU(connection, newAsdu);
                InformationObject_destroy(io);
                CS101_ASDU_destroy(newAsdu);
            }
            break;
        }

        case C_SE_NC_1: /* Set point (float) */
        {
            SetpointCommandShort spc = (SetpointCommandShort) CS101_ASDU_getElement(asdu, 0);
            float value = SetpointCommandShort_getValue(spc);
            printf("[!] Setpoint command (float): IOA=%d Value=%.2f\n", ioa, value);

            if (ioa >= ME_NC_START_IOA && ioa < ME_NC_START_IOA + ME_NC_COUNT) {
                float_values[ioa - ME_NC_START_IOA] = value;

                /* Send confirmation */
                CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION_CON,
                                                        0, COMMON_ADDRESS, false, false);
                InformationObject io = (InformationObject) SetpointCommandShort_create(NULL, ioa, value, false, 0);
                CS101_ASDU_addInformationObject(newAsdu, io);
                IMasterConnection_sendASDU(connection, newAsdu);
                InformationObject_destroy(io);
                CS101_ASDU_destroy(newAsdu);
            }
            break;
        }

        case C_TS_NA_1: /* Test command */
            printf("[*] Test command received\n");
            break;

        case C_RP_NA_1: /* Reset process */
            printf("[!] Reset process command received\n");
            init_data_points();
            break;

        case F_SC_NA_1: /* 122 - File call/select (directory listing) */
        {
            FileCallOrSelect fcs = (FileCallOrSelect) CS101_ASDU_getElement(asdu, 0);
            if (fcs) {
                uint8_t scq = FileCallOrSelect_getSCQ(fcs);
                CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);

                printf("[FILE] Received F_SC_NA_1: IOA=%d SCQ=%d COT=%d ftState=%d ftSelectedFile=%d\n",
                       ioa, scq, cot, ftState, ftSelectedFile);
                fflush(stdout);

                /* Handle directory call - c104 uses SCQ=1 with COT=REQUEST for directory */
                if (cot == CS101_COT_REQUEST) {
                    printf("[FILE] Directory listing requested (SCQ=%d)\n", scq);

                    /* Send F_DR_TA_1 (Type 126) for each file */
                    for (int i = 0; i < NUM_FILES; i++) {
                        CS101_ASDU dirAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);

                        CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());
                        uint8_t sof = (i == NUM_FILES - 1) ? 0x20 : 0x00;  /* LFD for last */

                        InformationObject dirEntry = (InformationObject)
                            FileDirectory_create(NULL, fileIOAs[i],
                                CS101_NOF_TRANSPARENT_FILE, fileSizes[i], sof, timestamp);

                        CS101_ASDU_addInformationObject(dirAsdu, dirEntry);
                        IMasterConnection_sendASDU(connection, dirAsdu);
                        InformationObject_destroy(dirEntry);
                        CS101_ASDU_destroy(dirAsdu);

                        printf("[FILE] Sent directory entry: %s (IOA=%d, size=%d)\n",
                               fileNames[i], fileIOAs[i], fileSizes[i]);
                    }

                    /* Send F_LS_NA_1 to mark end of directory */
                    CS101_ASDU lastAsdu = CS101_ASDU_create(alParams, false,
                        CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                    InformationObject lastSection = (InformationObject)
                        FileLastSegmentOrSection_create(NULL, ioa, 0, 0, 1, 0);
                    CS101_ASDU_addInformationObject(lastAsdu, lastSection);
                    IMasterConnection_sendASDU(connection, lastAsdu);
                    InformationObject_destroy(lastSection);
                    CS101_ASDU_destroy(lastAsdu);
                    printf("[FILE] Sent end of directory marker\n");
                }
                /* Handle file select (SCQ=1) */
                else if (scq == 1 && cot == CS101_COT_FILE_TRANSFER) {
                    int fileIdx = get_file_index(ioa);
                    printf("[FILE] File select: IOA=%d fileIdx=%d\n", ioa, fileIdx);
                    fflush(stdout);

                    if (fileIdx >= 0) {
                        ftSelectedFile = fileIdx;
                        ftState = FT_STATE_FILE_SELECTED;
                        ftConnection = connection;

                        /* Send F_FR_NA_1 (File Ready) */
                        CS101_ASDU frAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        InformationObject fr = (InformationObject)
                            FileReady_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE, fileSizes[fileIdx], true);
                        CS101_ASDU_addInformationObject(frAsdu, fr);
                        IMasterConnection_sendASDU(connection, frAsdu);
                        InformationObject_destroy(fr);
                        CS101_ASDU_destroy(frAsdu);
                        printf("[FILE] Sent FILE_READY: size=%d, ftState=%d\n", fileSizes[fileIdx], ftState);
                        fflush(stdout);
                    }
                }
                /* Handle file request/call (SCQ=2) */
                else if (scq == 2 && cot == CS101_COT_FILE_TRANSFER) {
                    printf("[FILE] File request: IOA=%d state=%d\n", ioa, ftState);
                    fflush(stdout);

                    if (ftState == FT_STATE_FILE_SELECTED && ftSelectedFile >= 0) {
                        ftCurrentSection = 1;
                        ftCurrentOffset = 0;
                        ftState = FT_STATE_SECTION_READY;

                        /* Send F_SR_NA_1 (Section Ready) */
                        CS101_ASDU srAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        InformationObject sr = (InformationObject)
                            SectionReady_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                                ftCurrentSection, fileSizes[ftSelectedFile], false);
                        CS101_ASDU_addInformationObject(srAsdu, sr);
                        IMasterConnection_sendASDU(connection, srAsdu);
                        InformationObject_destroy(sr);
                        CS101_ASDU_destroy(srAsdu);
                        printf("[FILE] Sent SECTION_READY: section=%d size=%d\n",
                               ftCurrentSection, fileSizes[ftSelectedFile]);
                    }
                }
                /* Handle section request (SCQ=6) - start transmitting segments */
                else if (scq == 6 && cot == CS101_COT_FILE_TRANSFER) {
                    uint8_t nos = FileCallOrSelect_getNameOfSection(fcs);
                    printf("[FILE] Section request: IOA=%d section=%d state=%d ftSelectedFile=%d\n",
                           ioa, nos, ftState, ftSelectedFile);
                    fflush(stdout);

                    if (ftState == FT_STATE_SECTION_READY && ftSelectedFile >= 0) {
                        ftState = FT_STATE_TRANSMITTING;
                        ftCurrentOffset = 0;

                        /* Send all segments */
                        int remaining = fileSizes[ftSelectedFile];
                        while (remaining > 0) {
                            int segSize = (remaining > SEGMENT_SIZE) ? SEGMENT_SIZE : remaining;

                            CS101_ASDU sgAsdu = CS101_ASDU_create(alParams, false,
                                CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                            InformationObject sg = (InformationObject)
                                FileSegment_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                                    ftCurrentSection, &fileData[ftSelectedFile][ftCurrentOffset], segSize);
                            CS101_ASDU_addInformationObject(sgAsdu, sg);
                            IMasterConnection_sendASDU(connection, sgAsdu);
                            InformationObject_destroy(sg);
                            CS101_ASDU_destroy(sgAsdu);

                            printf("[FILE] Sent segment: offset=%d size=%d\n", ftCurrentOffset, segSize);
                            ftCurrentOffset += segSize;
                            remaining -= segSize;
                        }

                        /* Send F_LS_NA_1 (Last Section) with LSQ=3 (section complete) */
                        CS101_ASDU lsAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        InformationObject ls = (InformationObject)
                            FileLastSegmentOrSection_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                                ftCurrentSection, 3, 0);  /* LSQ=3 = section complete */
                        CS101_ASDU_addInformationObject(lsAsdu, ls);
                        IMasterConnection_sendASDU(connection, lsAsdu);
                        InformationObject_destroy(ls);
                        CS101_ASDU_destroy(lsAsdu);
                        printf("[FILE] Sent LAST_SECTION (LSQ=3)\n");
                        ftState = FT_STATE_WAITING_SECTION_ACK;
                    }
                }
                /* Handle file delete (SCQ=4) - DANGEROUS operation */
                else if (scq == 4 && cot == CS101_COT_FILE_TRANSFER) {
                    int fileIdx = get_file_index(ioa);
                    printf("[FILE] Delete request: IOA=%d fileIdx=%d\n", ioa, fileIdx);
                    fflush(stdout);

                    /* Send F_AF_NA_1 acknowledgment */
                    CS101_ASDU ackAsdu = CS101_ASDU_create(alParams, false,
                        CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);

                    if (fileIdx >= 0) {
                        /* Mark file as deleted (set size to 0) */
                        fileSizes[fileIdx] = 0;
                        printf("[FILE] File IOA=%d deleted (marked as empty)\n", ioa);

                        /* Positive ACK (AFQ=1) */
                        InformationObject ack = (InformationObject)
                            FileACK_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE, 0, 1);
                        CS101_ASDU_addInformationObject(ackAsdu, ack);
                        IMasterConnection_sendASDU(connection, ackAsdu);
                        InformationObject_destroy(ack);
                    } else {
                        /* Negative ACK (AFQ=2) - file not found */
                        printf("[FILE] Delete failed - file not found\n");
                        InformationObject ack = (InformationObject)
                            FileACK_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE, 0, 2);
                        CS101_ASDU_addInformationObject(ackAsdu, ack);
                        IMasterConnection_sendASDU(connection, ackAsdu);
                        InformationObject_destroy(ack);
                    }
                    CS101_ASDU_destroy(ackAsdu);
                }
            }
            break;
        }

        case F_AF_NA_1: /* 124 - File/Section ACK */
        {
            FileACK ack = (FileACK) CS101_ASDU_getElement(asdu, 0);
            if (ack) {
                uint8_t afq = FileACK_getAFQ(ack);
                printf("[FILE] Received ACK: AFQ=%d state=%d\n", afq, ftState);

                if (afq == 3 && ftState == FT_STATE_WAITING_SECTION_ACK) {
                    /* Positive section ACK - send file complete */
                    CS101_ASDU lsAsdu = CS101_ASDU_create(alParams, false,
                        CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                    InformationObject ls = (InformationObject)
                        FileLastSegmentOrSection_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                            ftCurrentSection, 1, 0);  /* LSQ=1 = file complete */
                    CS101_ASDU_addInformationObject(lsAsdu, ls);
                    IMasterConnection_sendASDU(connection, lsAsdu);
                    InformationObject_destroy(ls);
                    CS101_ASDU_destroy(lsAsdu);
                    printf("[FILE] Sent LAST_SECTION (LSQ=1) - file complete\n");
                    ftState = FT_STATE_WAITING_FILE_ACK;
                }
                else if (afq == 1 && ftState == FT_STATE_WAITING_FILE_ACK) {
                    /* Positive file ACK - transfer complete */
                    printf("[FILE] Transfer complete\n");
                    ftState = FT_STATE_IDLE;
                    ftSelectedFile = -1;
                    ftConnection = NULL;
                }
            }
            break;
        }

        default:
            if (verbose) {
                printf("  Unhandled ASDU type: %d\n", typeId);
            }
            return false;
    }

    return true;
}

/* Print usage */
static void print_usage(const char* prog) {
    printf("IEC 60870-5-104/101 Mock Server\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p, --port PORT     TCP port for IEC 104 (default: %d, 0 to disable)\n", DEFAULT_PORT);
    printf("  -s, --serial PORT   Serial port for IEC 101 (e.g., /dev/ttyUSB0)\n");
    printf("  -b, --baud RATE     Baud rate for serial (default: 9600)\n");
    printf("  -a, --address ADDR  Link layer address for IEC 101 (default: 1)\n");
    printf("  -m, --mode MODE     IEC 101 mode: balanced or unbalanced (default: unbalanced)\n");
    printf("  -v, --verbose       Verbose output\n");
    printf("  -h, --help          Show this help\n");
    printf("\nExamples:\n");
    printf("  IEC 104 only:   %s -p 2404\n", prog);
    printf("  IEC 101 only:   %s -p 0 -s /dev/ttyUSB0 -b 9600\n", prog);
    printf("  Both modes:     %s -p 2404 -s /dev/ttyUSB0 -b 9600\n", prog);
    printf("\nData points:\n");
    printf("  Single points (M_SP_NA_1):     IOA %d-%d\n", SP_START_IOA, SP_START_IOA + SP_COUNT - 1);
    printf("  Double points (M_DP_NA_1):     IOA %d-%d\n", DP_START_IOA, DP_START_IOA + DP_COUNT - 1);
    printf("  Step positions (M_ST_NA_1):    IOA %d-%d\n", ST_START_IOA, ST_START_IOA + ST_COUNT - 1);
    printf("  Bitstrings (M_BO_NA_1):        IOA %d-%d\n", BO_START_IOA, BO_START_IOA + BO_COUNT - 1);
    printf("  Normalized (M_ME_NA_1):        IOA %d-%d\n", ME_NA_START_IOA, ME_NA_START_IOA + ME_NA_COUNT - 1);
    printf("  Scaled (M_ME_NB_1):            IOA %d-%d\n", ME_NB_START_IOA, ME_NB_START_IOA + ME_NB_COUNT - 1);
    printf("  Float (M_ME_NC_1):             IOA %d-%d\n", ME_NC_START_IOA, ME_NC_START_IOA + ME_NC_COUNT - 1);
    printf("  Integrated totals (M_IT_NA_1): IOA %d-%d\n", IT_START_IOA, IT_START_IOA + IT_COUNT - 1);
    printf("\nFile transfer (Type IDs 120-127):\n");
    printf("  Directory:     IOA %d\n", FILE_DIR_IOA);
    printf("  config.xml:    IOA %d\n", FILE_CONFIG_IOA);
    printf("  events.log:    IOA %d\n", FILE_LOG_IOA);
    printf("  parameters.cfg: IOA %d\n", FILE_EVENTS_IOA);
    printf("  Upload target: IOA 10100\n");
}

int main(int argc, char** argv) {
    int port = DEFAULT_PORT;
    int opt;
    int option_index = 0;

    /* Long options */
    static struct option long_options[] = {
        {"port",    required_argument, 0, 'p'},
        {"serial",  required_argument, 0, 's'},
        {"baud",    required_argument, 0, 'b'},
        {"address", required_argument, 0, 'a'},
        {"mode",    required_argument, 0, 'm'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0,         0,                 0, 0}
    };

    /* Parse arguments */
    while ((opt = getopt_long(argc, argv, "p:s:b:a:m:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 's':
                serial_port_path = strdup(optarg);
                break;
            case 'b':
                baud_rate = atoi(optarg);
                break;
            case 'a':
                link_address = atoi(optarg);
                break;
            case 'm':
                if (strcmp(optarg, "balanced") == 0) {
                    balanced_mode = true;
                } else if (strcmp(optarg, "unbalanced") == 0) {
                    balanced_mode = false;
                } else {
                    fprintf(stderr, "Invalid mode: %s (use 'balanced' or 'unbalanced')\n", optarg);
                    return 1;
                }
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Validate configuration */
    if (port == 0 && serial_port_path == NULL) {
        fprintf(stderr, "Error: Must enable at least IEC 104 (port) or IEC 101 (serial)\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("========================================\n");
    printf("IEC 60870-5-104/101 Mock Server\n");
    printf("========================================\n");

    /* Initialize data */
    init_data_points();

    /* Application layer parameters (shared between IEC 104 and 101) */
    CS101_AppLayerParameters alParams = NULL;

    /* ========================================
     * IEC 104 (TCP) Setup
     * ======================================== */
    if (port > 0) {
        /* Create IEC 104 slave */
        slave = CS104_Slave_create(10, 10);

        /* Configure */
        CS104_Slave_setLocalPort(slave, port);
        CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

        /* Get app layer parameters for file transfer */
        alParams = CS104_Slave_getAppLayerParameters(slave);

        /* Set handlers */
        CS104_Slave_setConnectionEventHandler(slave, connection_event_handler, NULL);
        CS104_Slave_setClockSyncHandler(slave, clock_sync_handler, NULL);
        CS104_Slave_setInterrogationHandler(slave, interrogation_handler, NULL);
        CS104_Slave_setCounterInterrogationHandler(slave, counter_interrogation_handler, NULL);
        CS104_Slave_setReadHandler(slave, read_handler, NULL);
        CS104_Slave_setASDUHandler(slave, asdu_handler, NULL);

        printf("[*] IEC 104: Configured for port %d\n", port);
    }

    /* ========================================
     * IEC 101 (Serial) Setup
     * ======================================== */
    if (serial_port_path != NULL) {
        /* Create serial port */
        serialPort = SerialPort_create(serial_port_path, baud_rate, 8, 'E', 1);

        if (serialPort == NULL) {
            fprintf(stderr, "[!] Failed to create serial port: %s\n", serial_port_path);
            if (slave) CS104_Slave_destroy(slave);
            return 1;
        }

        /* Create IEC 101 slave */
        if (balanced_mode) {
            /* Balanced mode - used for point-to-point connections */
            cs101_slave = CS101_Slave_create(serialPort, NULL, NULL, IEC60870_LINK_LAYER_BALANCED);
            printf("[*] IEC 101: Balanced mode\n");
        } else {
            /* Unbalanced mode - used for multi-drop configurations */
            cs101_slave = CS101_Slave_create(serialPort, NULL, NULL, IEC60870_LINK_LAYER_UNBALANCED);
            printf("[*] IEC 101: Unbalanced mode\n");
        }

        if (cs101_slave == NULL) {
            fprintf(stderr, "[!] Failed to create IEC 101 slave\n");
            SerialPort_destroy(serialPort);
            if (slave) CS104_Slave_destroy(slave);
            return 1;
        }

        /* Set link layer address */
        CS101_Slave_setLinkLayerAddress(cs101_slave, link_address);

        /* Get app layer parameters if not already set (IEC 101-only mode) */
        if (alParams == NULL) {
            alParams = CS101_Slave_getAppLayerParameters(cs101_slave);
        }

        /* Configure application layer parameters to match IEC 104 defaults */
        alParams->sizeOfCOT = 2;
        alParams->sizeOfCA = 2;
        alParams->sizeOfIOA = 3;
        printf("[*] IEC 101: App params: COT=%d, CA=%d, IOA=%d\n",
               alParams->sizeOfCOT, alParams->sizeOfCA, alParams->sizeOfIOA);

        /* Set handlers (same as IEC 104) */
        CS101_Slave_setClockSyncHandler(cs101_slave, clock_sync_handler, NULL);
        CS101_Slave_setInterrogationHandler(cs101_slave, interrogation_handler, NULL);
        CS101_Slave_setCounterInterrogationHandler(cs101_slave, counter_interrogation_handler, NULL);
        CS101_Slave_setReadHandler(cs101_slave, read_handler, NULL);
        CS101_Slave_setASDUHandler(cs101_slave, asdu_handler, NULL);

        /* Set raw message handler for debugging */
        CS101_Slave_setRawMessageHandler(cs101_slave, rawMessageHandler101, NULL);

        /* Set link layer address for other station (master) */
        CS101_Slave_setLinkLayerAddressOtherStation(cs101_slave, 0);

        /* Configure link layer parameters */
        LinkLayerParameters llParams = CS101_Slave_getLinkLayerParameters(cs101_slave);
        llParams->timeoutForAck = 500;
        llParams->addressLength = 1;

        /* Open serial port - CRITICAL: must be done before CS101_Slave_run() */
        if (!SerialPort_open(serialPort)) {
            fprintf(stderr, "[!] Failed to open serial port: %s\n", serial_port_path);
            CS101_Slave_destroy(cs101_slave);
            SerialPort_destroy(serialPort);
            if (slave) CS104_Slave_destroy(slave);
            return 1;
        }

        printf("[*] IEC 101: Configured on %s @ %d baud (link addr: %d)\n",
               serial_port_path, baud_rate, link_address);
    }

    /* Initialize file transfer subsystem */
    if (alParams) {
        init_file_transfer(alParams);
    }

    /* NOTE: FileServer plugin disabled - custom ASDU handler implements file transfer.
     * The custom handler provides directory listing (COT=REQUEST) and file transfer.
     * CS104_Slave_addPlugin(slave, CS101_FileServer_getSlavePlugin(fileServer));
     */

    /* ========================================
     * Start Servers
     * ======================================== */
    bool any_started = false;

    /* Start IEC 104 server */
    if (slave) {
        CS104_Slave_start(slave);
        if (CS104_Slave_isRunning(slave)) {
            printf("[*] IEC 104: Listening on port %d\n", port);
            any_started = true;
        } else {
            printf("[!] IEC 104: Failed to start on port %d\n", port);
        }
    }

    /* IEC 101 slave - do NOT use CS101_Slave_start() as it creates a worker thread.
     * Instead, call CS101_Slave_run() directly in the main loop (non-threaded mode). */
    if (cs101_slave) {
        printf("[*] IEC 101: Ready on %s\n", serial_port_path);
        any_started = true;
    }

    if (!any_started) {
        printf("[!] No protocols started successfully\n");
        if (slave) CS104_Slave_destroy(slave);
        if (cs101_slave) CS101_Slave_destroy(cs101_slave);
        if (serialPort) SerialPort_destroy(serialPort);
        return 1;
    }

    printf("[*] Press Ctrl+C to stop\n\n");

    /* ========================================
     * Main Loop
     * ======================================== */
    uint64_t lastSimUpdate = Hal_getTimeInMs();
    while (running) {
        /* IEC 101 requires polling - call CS101_Slave_run() to process serial data */
        if (cs101_slave) {
            CS101_Slave_run(cs101_slave);
        }

        /* Simulate data changes every 5 seconds */
        uint64_t now = Hal_getTimeInMs();
        if (now - lastSimUpdate >= 5000) {
            simulate_data_changes();
            if (verbose) {
                printf("[*] Data values updated\n");
            }
            lastSimUpdate = now;
        }

        /* Small sleep to prevent busy-waiting */
        Thread_sleep(10);
    }

    /* Cleanup */
    printf("[*] Stopping server...\n");

    /* Stop and destroy IEC 104 slave */
    if (slave) {
        CS104_Slave_stop(slave);
        CS104_Slave_destroy(slave);
        printf("[*] IEC 104: Stopped\n");
    }

    /* Stop and destroy IEC 101 slave */
    if (cs101_slave) {
        CS101_Slave_stop(cs101_slave);
        CS101_Slave_destroy(cs101_slave);
        printf("[*] IEC 101: Stopped\n");
    }

    /* Close and destroy serial port */
    if (serialPort) {
        SerialPort_close(serialPort);
        SerialPort_destroy(serialPort);
    }

    /* Free serial port path */
    if (serial_port_path) {
        free(serial_port_path);
    }

    /* Cleanup file server */
    if (fileServer) {
        CS101_FileServer_destroy(fileServer);
    }

    printf("[*] Server stopped\n");

    return 0;
}
