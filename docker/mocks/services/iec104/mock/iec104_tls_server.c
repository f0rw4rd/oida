/*
 * IEC 60870-5-104 TLS Mock Server
 *
 * Fork of iec104_server.c with TLS support via lib60870's mbedTLS integration.
 * Uses CS104_Slave_createSecure() for IEC 62351-3 compliant TLS transport.
 *
 * Default port: 19998 (IEC 62351-3 standard TLS port)
 *
 * Build requires lib60870 compiled with -DWITH_MBEDTLS=1
 *
 * Usage: ./iec104_tls_server -p 19998 \
 *          --tls-cert /certs/server.pem \
 *          --tls-key /certs/server.key \
 *          --ca-cert /certs/ca.pem
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

/* TLS */
#include "tls_config.h"

/* Common */
#include "cs101_file_service.h"
#include "hal_time.h"
#include "hal_thread.h"

/* Configuration */
#define DEFAULT_PORT 19998
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

/* TLS configuration paths */
static const char* tls_cert_path = "/certs/server.pem";
static const char* tls_key_path = "/certs/server.key";
static const char* ca_cert_path = "/certs/ca.pem";

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

/* Custom file transfer state */
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

    for (int i = 0; i < SP_COUNT; i++)
        single_points[i] = (i % 2 == 0);

    for (int i = 0; i < DP_COUNT; i++)
        double_points[i] = (i % 3) + 1;

    for (int i = 0; i < ST_COUNT; i++)
        step_positions[i] = (i * 10) - 50;

    for (int i = 0; i < BO_COUNT; i++)
        bitstrings[i] = (uint32_t)(rand() & 0xFFFFFFFF);

    for (int i = 0; i < ME_NA_COUNT; i++)
        normalized_values[i] = (float)i / (float)ME_NA_COUNT;

    for (int i = 0; i < ME_NB_COUNT; i++)
        scaled_values[i] = (int16_t)(i * 1000 - 10000);

    for (int i = 0; i < ME_NC_COUNT; i++)
        float_values[i] = 100.0f + (float)i * 10.0f + ((float)(rand() % 100) / 10.0f);

    for (int i = 0; i < IT_COUNT; i++)
        integrated_totals[i] = i * 10000;

    printf("[*] Initialized %d data points\n",
           SP_COUNT + DP_COUNT + ST_COUNT + BO_COUNT +
           ME_NA_COUNT + ME_NB_COUNT + ME_NC_COUNT + IT_COUNT);
}

/* ========================================================================
 * File Transfer Implementation (Type IDs 120-127)
 * ======================================================================== */

static int get_file_index(int ioa) {
    for (int i = 0; i < NUM_FILES; i++) {
        if (fileIOAs[i] == ioa)
            return i;
    }
    return -1;
}

static uint64_t file_getFileDate(CS101_IFileProvider self) {
    return Hal_getTimeInMs();
}

static int file_getFileSize(CS101_IFileProvider self) {
    int idx = get_file_index(self->ioa);
    if (idx >= 0) return fileSizes[idx];
    return 0;
}

static int file_getSectionSize(CS101_IFileProvider self, int sectionNumber) {
    if (sectionNumber == 0) {
        int idx = get_file_index(self->ioa);
        if (idx >= 0) return fileSizes[idx];
    }
    return 0;
}

static bool file_getSegmentData(CS101_IFileProvider self, int sectionNumber,
                                 int offset, int size, uint8_t* data) {
    int idx = get_file_index(self->ioa);
    if (idx >= 0 && sectionNumber == 0) {
        if (offset + size <= fileSizes[idx]) {
            memcpy(data, fileData[idx] + offset, size);
            return true;
        }
    }
    return false;
}

static void file_transferComplete(CS101_IFileProvider self, bool success) {
    printf("[FILE] Transfer complete (IOA=%d, success=%d)\n", self->ioa, success);
}

static int currentFileIndex = 0;

static CS101_IFileProvider files_getNextFile(void* parameter, CS101_IFileProvider continueAfter) {
    if (continueAfter == NULL)
        currentFileIndex = 0;
    else
        currentFileIndex++;

    if (currentFileIndex < NUM_FILES)
        return &fileProviders[currentFileIndex];
    return NULL;
}

static CS101_IFileProvider files_getFile(void* parameter, int ca, int ioa,
                                          uint16_t nof, int* errCode) {
    for (int i = 0; i < NUM_FILES; i++) {
        if (fileIOAs[i] == ioa && ca == COMMON_ADDRESS) {
            *errCode = 0;
            return &fileProviders[i];
        }
    }
    *errCode = 2;
    return NULL;
}

static void upload_finished(CS101_IFileReceiver self, CS101_FileErrorCode result) {
    if (uploadFile) {
        fclose(uploadFile);
        uploadFile = NULL;
    }
    if (result != CS101_FILE_ERROR_SUCCESS)
        remove("/tmp/iec104_upload.dat");
}

static void upload_segmentReceived(CS101_IFileReceiver self, uint8_t sectionName,
                                    int offset, int size, uint8_t* data) {
    if (uploadFile)
        fwrite(data, size, 1, uploadFile);
}

static CS101_IFileReceiver file_fileReadyHandler(void* parameter, int ca, int ioa,
                                                   uint16_t nof, int lengthOfFile, int* err) {
    if (ca == COMMON_ADDRESS && ioa == 10100) {
        uploadFile = fopen("/tmp/iec104_upload.dat", "wb");
        if (uploadFile) {
            uploadReceiver.object = uploadFile;
            uploadReceiver.finished = upload_finished;
            uploadReceiver.segmentReceived = upload_segmentReceived;
            *err = 0;
            return &uploadReceiver;
        }
    }
    *err = 2;
    return NULL;
}

static void init_file_transfer(CS101_AppLayerParameters alParams) {
    printf("[*] Initializing file transfer...\n");

    const char* configXml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<config>\n"
        "  <device name=\"IEC104-TLS-Mock\" version=\"1.0\"/>\n"
        "  <network>\n"
        "    <port>19998</port>\n"
        "    <address>1</address>\n"
        "    <tls>enabled</tls>\n"
        "  </network>\n"
        "  <security>\n"
        "    <authentication>none</authentication>\n"
        "    <encryption>TLS 1.2+</encryption>\n"
        "  </security>\n"
        "</config>\n";

    const char* eventsLog =
        "2024-01-01 00:00:00 [INFO] System started\n"
        "2024-01-01 00:00:01 [INFO] TLS initialized\n"
        "2024-01-01 00:00:02 [INFO] IEC 104 TLS server listening on port 19998\n"
        "2024-01-01 00:01:00 [INFO] TLS connection from 192.168.1.100\n"
        "2024-01-01 00:01:05 [INFO] General interrogation received\n";

    const char* paramsCfg =
        "# IEC 104 TLS Parameters\n"
        "COMMON_ADDRESS=1\n"
        "T0_TIMEOUT=30\n"
        "T1_TIMEOUT=15\n"
        "T2_TIMEOUT=10\n"
        "T3_TIMEOUT=20\n"
        "K_VALUE=12\n"
        "W_VALUE=8\n"
        "TLS_MIN_VERSION=1.2\n";

    fileSizes[0] = strlen(configXml);
    memcpy(fileData[0], configXml, fileSizes[0]);
    fileSizes[1] = strlen(eventsLog);
    memcpy(fileData[1], eventsLog, fileSizes[1]);
    fileSizes[2] = strlen(paramsCfg);
    memcpy(fileData[2], paramsCfg, fileSizes[2]);

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
    }

    fileServer = CS101_FileServer_create(alParams);

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
    int sp_idx = rand() % SP_COUNT;
    single_points[sp_idx] = !single_points[sp_idx];

    static float t = 0;
    t += 0.1f;
    for (int i = 0; i < ME_NC_COUNT; i++) {
        float base = 100.0f + (float)i * 10.0f;
        float_values[i] = base + 20.0f * sinf(t + i * 0.5f) + ((float)(rand() % 20) - 10.0f) / 10.0f;
    }

    for (int i = 0; i < IT_COUNT; i++)
        integrated_totals[i] += rand() % 100;
}

/* Connection event handler */
static void connection_event_handler(void* parameter, IMasterConnection connection, CS104_PeerConnectionEvent event) {
    char* eventStr = "UNKNOWN";
    switch (event) {
        case CS104_CON_EVENT_CONNECTION_OPENED:  eventStr = "OPENED"; break;
        case CS104_CON_EVENT_CONNECTION_CLOSED:  eventStr = "CLOSED"; break;
        case CS104_CON_EVENT_ACTIVATED:          eventStr = "ACTIVATED"; break;
        case CS104_CON_EVENT_DEACTIVATED:        eventStr = "DEACTIVATED"; break;
    }
    printf("[+] Connection event: %s (TLS)\n", eventStr);
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
    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);
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
    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);
    CS101_ASDU newAsdu = NULL;
    InformationObject io = NULL;

    if (ioa >= SP_START_IOA && ioa < SP_START_IOA + SP_COUNT) {
        int idx = ioa - SP_START_IOA;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST, 0, COMMON_ADDRESS, false, false);
        io = (InformationObject) SinglePointInformation_create(NULL, ioa, single_points[idx], IEC60870_QUALITY_GOOD);
    } else if (ioa >= DP_START_IOA && ioa < DP_START_IOA + DP_COUNT) {
        int idx = ioa - DP_START_IOA;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST, 0, COMMON_ADDRESS, false, false);
        io = (InformationObject) DoublePointInformation_create(NULL, ioa, (DoublePointValue)double_points[idx], IEC60870_QUALITY_GOOD);
    } else if (ioa >= ME_NC_START_IOA && ioa < ME_NC_START_IOA + ME_NC_COUNT) {
        int idx = ioa - ME_NC_START_IOA;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST, 0, COMMON_ADDRESS, false, false);
        io = (InformationObject) MeasuredValueShort_create(NULL, ioa, float_values[idx], IEC60870_QUALITY_GOOD);
    } else {
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

    switch (typeId) {
        case C_SC_NA_1: {
            SingleCommand sc = (SingleCommand) CS101_ASDU_getElement(asdu, 0);
            bool value = SingleCommand_getState(sc);
            if (ioa >= SP_START_IOA && ioa < SP_START_IOA + SP_COUNT) {
                single_points[ioa - SP_START_IOA] = value;
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
        case C_DC_NA_1: {
            DoubleCommand dc = (DoubleCommand) CS101_ASDU_getElement(asdu, 0);
            int value = DoubleCommand_getState(dc);
            if (ioa >= DP_START_IOA && ioa < DP_START_IOA + DP_COUNT)
                double_points[ioa - DP_START_IOA] = value;
            break;
        }
        case C_SE_NC_1: {
            SetpointCommandShort spc = (SetpointCommandShort) CS101_ASDU_getElement(asdu, 0);
            float value = SetpointCommandShort_getValue(spc);
            if (ioa >= ME_NC_START_IOA && ioa < ME_NC_START_IOA + ME_NC_COUNT)
                float_values[ioa - ME_NC_START_IOA] = value;
            break;
        }
        case C_TS_NA_1:
            break;
        case C_RP_NA_1:
            init_data_points();
            break;
        case F_SC_NA_1: {
            FileCallOrSelect fcs = (FileCallOrSelect) CS101_ASDU_getElement(asdu, 0);
            if (fcs) {
                uint8_t scq = FileCallOrSelect_getSCQ(fcs);
                CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);

                if (cot == CS101_COT_REQUEST) {
                    for (int i = 0; i < NUM_FILES; i++) {
                        CS101_ASDU dirAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());
                        uint8_t sof = (i == NUM_FILES - 1) ? 0x20 : 0x00;
                        InformationObject dirEntry = (InformationObject)
                            FileDirectory_create(NULL, fileIOAs[i],
                                CS101_NOF_TRANSPARENT_FILE, fileSizes[i], sof, timestamp);
                        CS101_ASDU_addInformationObject(dirAsdu, dirEntry);
                        IMasterConnection_sendASDU(connection, dirAsdu);
                        InformationObject_destroy(dirEntry);
                        CS101_ASDU_destroy(dirAsdu);
                    }
                    CS101_ASDU lastAsdu = CS101_ASDU_create(alParams, false,
                        CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                    InformationObject lastSection = (InformationObject)
                        FileLastSegmentOrSection_create(NULL, ioa, 0, 0, 1, 0);
                    CS101_ASDU_addInformationObject(lastAsdu, lastSection);
                    IMasterConnection_sendASDU(connection, lastAsdu);
                    InformationObject_destroy(lastSection);
                    CS101_ASDU_destroy(lastAsdu);
                } else if (scq == 1 && cot == CS101_COT_FILE_TRANSFER) {
                    int fileIdx = get_file_index(ioa);
                    if (fileIdx >= 0) {
                        ftSelectedFile = fileIdx;
                        ftState = FT_STATE_FILE_SELECTED;
                        ftConnection = connection;
                        CS101_ASDU frAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        InformationObject fr = (InformationObject)
                            FileReady_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE, fileSizes[fileIdx], true);
                        CS101_ASDU_addInformationObject(frAsdu, fr);
                        IMasterConnection_sendASDU(connection, frAsdu);
                        InformationObject_destroy(fr);
                        CS101_ASDU_destroy(frAsdu);
                    }
                } else if (scq == 2 && cot == CS101_COT_FILE_TRANSFER) {
                    if (ftState == FT_STATE_FILE_SELECTED && ftSelectedFile >= 0) {
                        ftCurrentSection = 1;
                        ftCurrentOffset = 0;
                        ftState = FT_STATE_SECTION_READY;
                        CS101_ASDU srAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        InformationObject sr = (InformationObject)
                            SectionReady_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                                ftCurrentSection, fileSizes[ftSelectedFile], false);
                        CS101_ASDU_addInformationObject(srAsdu, sr);
                        IMasterConnection_sendASDU(connection, srAsdu);
                        InformationObject_destroy(sr);
                        CS101_ASDU_destroy(srAsdu);
                    }
                } else if (scq == 6 && cot == CS101_COT_FILE_TRANSFER) {
                    if (ftState == FT_STATE_SECTION_READY && ftSelectedFile >= 0) {
                        ftState = FT_STATE_TRANSMITTING;
                        ftCurrentOffset = 0;
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
                            ftCurrentOffset += segSize;
                            remaining -= segSize;
                        }
                        CS101_ASDU lsAsdu = CS101_ASDU_create(alParams, false,
                            CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                        InformationObject ls = (InformationObject)
                            FileLastSegmentOrSection_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                                ftCurrentSection, 3, 0);
                        CS101_ASDU_addInformationObject(lsAsdu, ls);
                        IMasterConnection_sendASDU(connection, lsAsdu);
                        InformationObject_destroy(ls);
                        CS101_ASDU_destroy(lsAsdu);
                        ftState = FT_STATE_WAITING_SECTION_ACK;
                    }
                } else if (scq == 4 && cot == CS101_COT_FILE_TRANSFER) {
                    int fileIdx = get_file_index(ioa);
                    CS101_ASDU ackAsdu = CS101_ASDU_create(alParams, false,
                        CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                    if (fileIdx >= 0) {
                        fileSizes[fileIdx] = 0;
                        InformationObject ack = (InformationObject)
                            FileACK_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE, 0, 1);
                        CS101_ASDU_addInformationObject(ackAsdu, ack);
                        IMasterConnection_sendASDU(connection, ackAsdu);
                        InformationObject_destroy(ack);
                    } else {
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
        case F_AF_NA_1: {
            FileACK ack = (FileACK) CS101_ASDU_getElement(asdu, 0);
            if (ack) {
                uint8_t afq = FileACK_getAFQ(ack);
                if (afq == 3 && ftState == FT_STATE_WAITING_SECTION_ACK) {
                    CS101_ASDU lsAsdu = CS101_ASDU_create(alParams, false,
                        CS101_COT_FILE_TRANSFER, 0, COMMON_ADDRESS, false, false);
                    InformationObject ls = (InformationObject)
                        FileLastSegmentOrSection_create(NULL, ioa, CS101_NOF_TRANSPARENT_FILE,
                            ftCurrentSection, 1, 0);
                    CS101_ASDU_addInformationObject(lsAsdu, ls);
                    IMasterConnection_sendASDU(connection, lsAsdu);
                    InformationObject_destroy(ls);
                    CS101_ASDU_destroy(lsAsdu);
                    ftState = FT_STATE_WAITING_FILE_ACK;
                } else if (afq == 1 && ftState == FT_STATE_WAITING_FILE_ACK) {
                    ftState = FT_STATE_IDLE;
                    ftSelectedFile = -1;
                    ftConnection = NULL;
                }
            }
            break;
        }
        default:
            return false;
    }
    return true;
}

/* Print usage */
static void print_usage(const char* prog) {
    printf("IEC 60870-5-104 TLS Mock Server\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p, --port PORT         TCP port (default: %d)\n", DEFAULT_PORT);
    printf("      --tls-cert PATH     Server certificate (default: /certs/server.pem)\n");
    printf("      --tls-key PATH      Server private key (default: /certs/server.key)\n");
    printf("      --ca-cert PATH      CA certificate (default: /certs/ca.pem)\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help\n");
}

int main(int argc, char** argv) {
    int port = DEFAULT_PORT;
    int opt;
    int option_index = 0;

    static struct option long_options[] = {
        {"port",     required_argument, 0, 'p'},
        {"tls-cert", required_argument, 0, 'C'},
        {"tls-key",  required_argument, 0, 'K'},
        {"ca-cert",  required_argument, 0, 'A'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0,          0,                 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'C': tls_cert_path = optarg; break;
            case 'K': tls_key_path = optarg; break;
            case 'A': ca_cert_path = optarg; break;
            case 'v': verbose = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("========================================\n");
    printf("IEC 60870-5-104 TLS Mock Server\n");
    printf("========================================\n");

    init_data_points();

    /* ========================================
     * TLS Configuration
     * ======================================== */
    printf("[*] Setting up TLS...\n");
    printf("[*]   Certificate: %s\n", tls_cert_path);
    printf("[*]   Private key: %s\n", tls_key_path);
    printf("[*]   CA cert:     %s\n", ca_cert_path);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    if (tlsConfig == NULL) {
        fprintf(stderr, "[!] Failed to create TLS configuration\n");
        return 1;
    }

    TLSConfiguration_setMinTlsVersion(tlsConfig, TLS_VERSION_TLS_1_2);
    TLSConfiguration_setMaxTlsVersion(tlsConfig, TLS_VERSION_TLS_1_2);
    TLSConfiguration_setChainValidation(tlsConfig, false);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    /* lib60870 defaults put static RSA first (MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256),
     * which breaks with mbedtls 3.6 PSA crypto backend (handshake returns -0x1).
     * Clear defaults and use only ECDHE suites which work correctly with PSA. */
    TLSConfiguration_clearCipherSuiteList(tlsConfig);
    TLSConfiguration_addCipherSuite(tlsConfig, 0xC02F); /* ECDHE-RSA-AES128-GCM-SHA256 */
    TLSConfiguration_addCipherSuite(tlsConfig, 0xC030); /* ECDHE-RSA-AES256-GCM-SHA384 */
    TLSConfiguration_addCipherSuite(tlsConfig, 0xC027); /* ECDHE-RSA-AES128-CBC-SHA256 */
    TLSConfiguration_addCipherSuite(tlsConfig, 0xC028); /* ECDHE-RSA-AES256-CBC-SHA384 */

    if (!TLSConfiguration_setOwnKeyFromFile(tlsConfig, tls_key_path, NULL)) {
        fprintf(stderr, "[!] Failed to load server key: %s\n", tls_key_path);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    if (!TLSConfiguration_setOwnCertificateFromFile(tlsConfig, tls_cert_path)) {
        fprintf(stderr, "[!] Failed to load server certificate: %s\n", tls_cert_path);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    if (!TLSConfiguration_addCACertificateFromFile(tlsConfig, ca_cert_path)) {
        fprintf(stderr, "[!] Failed to load CA certificate: %s\n", ca_cert_path);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    printf("[*] TLS configured (TLS 1.2+, no client auth required)\n");

    /* ========================================
     * IEC 104 Secure Slave Setup
     * ======================================== */
    slave = CS104_Slave_createSecure(10, 10, tlsConfig);

    if (slave == NULL) {
        fprintf(stderr, "[!] Failed to create secure IEC 104 slave\n");
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    CS104_Slave_setLocalPort(slave, port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);

    CS104_Slave_setConnectionEventHandler(slave, connection_event_handler, NULL);
    CS104_Slave_setClockSyncHandler(slave, clock_sync_handler, NULL);
    CS104_Slave_setInterrogationHandler(slave, interrogation_handler, NULL);
    CS104_Slave_setCounterInterrogationHandler(slave, counter_interrogation_handler, NULL);
    CS104_Slave_setReadHandler(slave, read_handler, NULL);
    CS104_Slave_setASDUHandler(slave, asdu_handler, NULL);

    init_file_transfer(alParams);

    /* ========================================
     * Start Server
     * ======================================== */
    CS104_Slave_start(slave);

    if (CS104_Slave_isRunning(slave)) {
        printf("[*] IEC 104 TLS: Listening on port %d\n", port);
    } else {
        printf("[!] IEC 104 TLS: Failed to start on port %d\n", port);
        CS104_Slave_destroy(slave);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    printf("[*] Press Ctrl+C to stop\n\n");

    /* Main Loop */
    uint64_t lastSimUpdate = Hal_getTimeInMs();
    while (running) {
        uint64_t now = Hal_getTimeInMs();
        if (now - lastSimUpdate >= 5000) {
            simulate_data_changes();
            lastSimUpdate = now;
        }
        Thread_sleep(10);
    }

    /* Cleanup */
    printf("[*] Stopping server...\n");
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    TLSConfiguration_destroy(tlsConfig);

    if (fileServer)
        CS101_FileServer_destroy(fileServer);

    printf("[*] Server stopped\n");
    return 0;
}
