/*
 * IEC 60870-5-104 Test Server
 *
 * Comprehensive test bed for OIDA IEC 104 scanner development.
 * Supports multiple data types, file transfer, and command handling.
 *
 * Based on lib60870-C library (https://github.com/mz-automation/lib60870)
 *
 * Build: See CMakeLists.txt or Makefile
 * Usage: ./iec104_test_server [port] [--verbose]
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define DEFAULT_PORT        2404
#define COMMON_ADDRESS      1
#define MAX_QUEUE_SIZE      100
#define MAX_LOW_PRIO_QUEUE  50

/* IOA (Information Object Address) Ranges for different data types */
#define IOA_SINGLE_POINT_START      100
#define IOA_SINGLE_POINT_COUNT      20

#define IOA_DOUBLE_POINT_START      200
#define IOA_DOUBLE_POINT_COUNT      10

#define IOA_STEP_POSITION_START     300
#define IOA_STEP_POSITION_COUNT     5

#define IOA_BITSTRING_START         400
#define IOA_BITSTRING_COUNT         5

#define IOA_MEASURED_NORM_START     500
#define IOA_MEASURED_NORM_COUNT     20

#define IOA_MEASURED_SCALED_START   600
#define IOA_MEASURED_SCALED_COUNT   20

#define IOA_MEASURED_FLOAT_START    700
#define IOA_MEASURED_FLOAT_COUNT    20

#define IOA_INTEGRATED_TOTALS_START 800
#define IOA_INTEGRATED_TOTALS_COUNT 10

#define IOA_PROTECTION_START        900
#define IOA_PROTECTION_COUNT        5

/* File transfer IOAs */
#define IOA_FILE_DIRECTORY          10000
#define IOA_FILE_CONFIG             10001
#define IOA_FILE_EVENTS             10002
#define IOA_FILE_DISTURBANCE        10003

/* ==========================================================================
 * Global State
 * ========================================================================== */

static bool running = true;
static bool verbose = false;
static CS104_Slave slave = NULL;

/* Simulated data values */
static bool     single_points[IOA_SINGLE_POINT_COUNT];
static uint8_t  double_points[IOA_DOUBLE_POINT_COUNT];  /* 0=intermediate, 1=off, 2=on, 3=indeterminate */
static int8_t   step_positions[IOA_STEP_POSITION_COUNT];
static uint32_t bitstrings[IOA_BITSTRING_COUNT];
static float    measured_norm[IOA_MEASURED_NORM_COUNT];
static int16_t  measured_scaled[IOA_MEASURED_SCALED_COUNT];
static float    measured_float[IOA_MEASURED_FLOAT_COUNT];
static int32_t  integrated_totals[IOA_INTEGRATED_TOTALS_COUNT];

/* File transfer state */
typedef struct {
    int ioa;
    char filename[256];
    uint8_t *data;
    size_t size;
    size_t offset;
    bool active;
} FileTransferState;

static FileTransferState file_transfers[4];
static const char* test_files[] = {
    "config.xml",
    "events.log",
    "disturbance_001.comtrade",
    "parameters.cfg"
};

/* ==========================================================================
 * Logging
 * ========================================================================== */

#define LOG_INFO(fmt, ...)  printf("[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  printf("[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) if(verbose) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

/* ==========================================================================
 * Signal Handler
 * ========================================================================== */

static void sigint_handler(int signalId)
{
    LOG_INFO("Received shutdown signal");
    running = false;
}

/* ==========================================================================
 * Data Initialization
 * ========================================================================== */

static void initialize_data(void)
{
    LOG_INFO("Initializing simulated data points...");

    srand(time(NULL));

    /* Single point information (M_SP_NA_1 / M_SP_TB_1) */
    for (int i = 0; i < IOA_SINGLE_POINT_COUNT; i++) {
        single_points[i] = (rand() % 2) == 1;
    }

    /* Double point information (M_DP_NA_1 / M_DP_TB_1) */
    for (int i = 0; i < IOA_DOUBLE_POINT_COUNT; i++) {
        double_points[i] = (rand() % 3) + 1;  /* 1=off, 2=on, 3=indeterminate */
    }

    /* Step position information (M_ST_NA_1) */
    for (int i = 0; i < IOA_STEP_POSITION_COUNT; i++) {
        step_positions[i] = (rand() % 127) - 64;  /* -64 to +63 */
    }

    /* Bitstring 32-bit (M_BO_NA_1) */
    for (int i = 0; i < IOA_BITSTRING_COUNT; i++) {
        bitstrings[i] = rand();
    }

    /* Measured value normalized (M_ME_NA_1) - range -1.0 to +1.0 */
    for (int i = 0; i < IOA_MEASURED_NORM_COUNT; i++) {
        measured_norm[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }

    /* Measured value scaled (M_ME_NB_1) - range -32768 to +32767 */
    for (int i = 0; i < IOA_MEASURED_SCALED_COUNT; i++) {
        measured_scaled[i] = (rand() % 65536) - 32768;
    }

    /* Measured value short float (M_ME_NC_1) */
    for (int i = 0; i < IOA_MEASURED_FLOAT_COUNT; i++) {
        measured_float[i] = ((float)rand() / RAND_MAX) * 1000.0f;
    }

    /* Integrated totals (M_IT_NA_1) */
    for (int i = 0; i < IOA_INTEGRATED_TOTALS_COUNT; i++) {
        integrated_totals[i] = rand() % 1000000;
    }

    LOG_INFO("  - %d single points (IOA %d-%d)",
             IOA_SINGLE_POINT_COUNT, IOA_SINGLE_POINT_START,
             IOA_SINGLE_POINT_START + IOA_SINGLE_POINT_COUNT - 1);
    LOG_INFO("  - %d double points (IOA %d-%d)",
             IOA_DOUBLE_POINT_COUNT, IOA_DOUBLE_POINT_START,
             IOA_DOUBLE_POINT_START + IOA_DOUBLE_POINT_COUNT - 1);
    LOG_INFO("  - %d step positions (IOA %d-%d)",
             IOA_STEP_POSITION_COUNT, IOA_STEP_POSITION_START,
             IOA_STEP_POSITION_START + IOA_STEP_POSITION_COUNT - 1);
    LOG_INFO("  - %d bitstrings (IOA %d-%d)",
             IOA_BITSTRING_COUNT, IOA_BITSTRING_START,
             IOA_BITSTRING_START + IOA_BITSTRING_COUNT - 1);
    LOG_INFO("  - %d measured normalized (IOA %d-%d)",
             IOA_MEASURED_NORM_COUNT, IOA_MEASURED_NORM_START,
             IOA_MEASURED_NORM_START + IOA_MEASURED_NORM_COUNT - 1);
    LOG_INFO("  - %d measured scaled (IOA %d-%d)",
             IOA_MEASURED_SCALED_COUNT, IOA_MEASURED_SCALED_START,
             IOA_MEASURED_SCALED_START + IOA_MEASURED_SCALED_COUNT - 1);
    LOG_INFO("  - %d measured float (IOA %d-%d)",
             IOA_MEASURED_FLOAT_COUNT, IOA_MEASURED_FLOAT_START,
             IOA_MEASURED_FLOAT_START + IOA_MEASURED_FLOAT_COUNT - 1);
    LOG_INFO("  - %d integrated totals (IOA %d-%d)",
             IOA_INTEGRATED_TOTALS_COUNT, IOA_INTEGRATED_TOTALS_START,
             IOA_INTEGRATED_TOTALS_START + IOA_INTEGRATED_TOTALS_COUNT - 1);
}

/* ==========================================================================
 * File Transfer Support
 * ========================================================================== */

static void initialize_files(const char* data_dir)
{
    LOG_INFO("Initializing file transfer support...");

    /* Initialize file transfer state */
    memset(file_transfers, 0, sizeof(file_transfers));

    file_transfers[0].ioa = IOA_FILE_CONFIG;
    file_transfers[1].ioa = IOA_FILE_EVENTS;
    file_transfers[2].ioa = IOA_FILE_DISTURBANCE;
    file_transfers[3].ioa = IOA_FILE_DIRECTORY;

    for (int i = 0; i < 4; i++) {
        snprintf(file_transfers[i].filename, sizeof(file_transfers[i].filename),
                 "%s/%s", data_dir, test_files[i]);
    }

    LOG_INFO("  - File directory at IOA %d", IOA_FILE_DIRECTORY);
    LOG_INFO("  - Config file at IOA %d", IOA_FILE_CONFIG);
    LOG_INFO("  - Events file at IOA %d", IOA_FILE_EVENTS);
    LOG_INFO("  - Disturbance file at IOA %d", IOA_FILE_DISTURBANCE);
}

/* ==========================================================================
 * Interrogation Handler
 * ========================================================================== */

static bool interrogation_handler(void* parameter, IMasterConnection connection,
                                   CS101_ASDU asdu, uint8_t qoi)
{
    LOG_INFO("Interrogation request received (QOI=%d)", qoi);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

    /* Send activation confirmation */
    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
    IMasterConnection_sendASDU(connection, asdu);

    /* Create new ASDU for response data */
    CS101_ASDU newAsdu;

    /* ===== Single Point Information (M_SP_NA_1 = 1) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_SINGLE_POINT_COUNT; i++) {
        InformationObject io = (InformationObject)
            SinglePointInformation_create(NULL, IOA_SINGLE_POINT_START + i,
                                          single_points[i], IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d single point values", IOA_SINGLE_POINT_COUNT);

    /* ===== Double Point Information (M_DP_NA_1 = 3) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_DOUBLE_POINT_COUNT; i++) {
        InformationObject io = (InformationObject)
            DoublePointInformation_create(NULL, IOA_DOUBLE_POINT_START + i,
                                          (DoublePointValue)double_points[i],
                                          IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d double point values", IOA_DOUBLE_POINT_COUNT);

    /* ===== Step Position Information (M_ST_NA_1 = 5) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_STEP_POSITION_COUNT; i++) {
        InformationObject io = (InformationObject)
            StepPositionInformation_create(NULL, IOA_STEP_POSITION_START + i,
                                           step_positions[i], false,
                                           IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d step position values", IOA_STEP_POSITION_COUNT);

    /* ===== Bitstring 32-bit (M_BO_NA_1 = 7) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_BITSTRING_COUNT; i++) {
        InformationObject io = (InformationObject)
            BitString32_create(NULL, IOA_BITSTRING_START + i,
                               bitstrings[i]);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d bitstring values", IOA_BITSTRING_COUNT);

    /* ===== Measured Value Normalized (M_ME_NA_1 = 9) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_MEASURED_NORM_COUNT; i++) {
        InformationObject io = (InformationObject)
            MeasuredValueNormalized_create(NULL, IOA_MEASURED_NORM_START + i,
                                           measured_norm[i], IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d measured normalized values", IOA_MEASURED_NORM_COUNT);

    /* ===== Measured Value Scaled (M_ME_NB_1 = 11) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_MEASURED_SCALED_COUNT; i++) {
        InformationObject io = (InformationObject)
            MeasuredValueScaled_create(NULL, IOA_MEASURED_SCALED_START + i,
                                       measured_scaled[i], IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d measured scaled values", IOA_MEASURED_SCALED_COUNT);

    /* ===== Measured Value Short Float (M_ME_NC_1 = 13) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_MEASURED_FLOAT_COUNT; i++) {
        InformationObject io = (InformationObject)
            MeasuredValueShort_create(NULL, IOA_MEASURED_FLOAT_START + i,
                                      measured_float[i], IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d measured float values", IOA_MEASURED_FLOAT_COUNT);

    /* ===== Integrated Totals (M_IT_NA_1 = 15) ===== */
    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                 0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_INTEGRATED_TOTALS_COUNT; i++) {
        BinaryCounterReading bcr = BinaryCounterReading_create(NULL, integrated_totals[i],
                                                                0, false, false, false);
        InformationObject io = (InformationObject)
            IntegratedTotals_create(NULL, IOA_INTEGRATED_TOTALS_START + i, bcr);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
        BinaryCounterReading_destroy(bcr);
    }
    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);
    LOG_DEBUG("  Sent %d integrated totals", IOA_INTEGRATED_TOTALS_COUNT);

    /* Send activation termination */
    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_TERMINATION);
    IMasterConnection_sendASDU(connection, asdu);

    LOG_INFO("Interrogation complete - sent all data points");

    return true;
}

/* ==========================================================================
 * Counter Interrogation Handler
 * ========================================================================== */

static bool counter_interrogation_handler(void* parameter, IMasterConnection connection,
                                           CS101_ASDU asdu, QualifierOfCIC qcc)
{
    LOG_INFO("Counter interrogation request received (QCC=%d)", qcc);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

    /* Send activation confirmation */
    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
    IMasterConnection_sendASDU(connection, asdu);

    /* Send integrated totals */
    CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
                                            0, COMMON_ADDRESS, false, false);

    for (int i = 0; i < IOA_INTEGRATED_TOTALS_COUNT; i++) {
        BinaryCounterReading bcr = BinaryCounterReading_create(NULL, integrated_totals[i],
                                                                0, false, false, false);
        InformationObject io = (InformationObject)
            IntegratedTotals_create(NULL, IOA_INTEGRATED_TOTALS_START + i, bcr);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);
        BinaryCounterReading_destroy(bcr);
    }

    IMasterConnection_sendASDU(connection, newAsdu);
    CS101_ASDU_destroy(newAsdu);

    /* Send activation termination */
    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_TERMINATION);
    IMasterConnection_sendASDU(connection, asdu);

    return true;
}

/* ==========================================================================
 * Read Handler (C_RD_NA_1 = 102)
 * ========================================================================== */

static bool read_handler(void* parameter, IMasterConnection connection,
                         CS101_ASDU asdu, int ioa)
{
    LOG_INFO("Read request for IOA %d", ioa);

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);
    CS101_ASDU newAsdu = NULL;
    InformationObject io = NULL;

    /* Determine which data point was requested */
    if (ioa >= IOA_SINGLE_POINT_START &&
        ioa < IOA_SINGLE_POINT_START + IOA_SINGLE_POINT_COUNT) {
        int idx = ioa - IOA_SINGLE_POINT_START;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST,
                                     0, COMMON_ADDRESS, false, false);
        io = (InformationObject)SinglePointInformation_create(NULL, ioa,
                                                               single_points[idx],
                                                               IEC60870_QUALITY_GOOD);
    }
    else if (ioa >= IOA_MEASURED_FLOAT_START &&
             ioa < IOA_MEASURED_FLOAT_START + IOA_MEASURED_FLOAT_COUNT) {
        int idx = ioa - IOA_MEASURED_FLOAT_START;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST,
                                     0, COMMON_ADDRESS, false, false);
        io = (InformationObject)MeasuredValueShort_create(NULL, ioa,
                                                           measured_float[idx],
                                                           IEC60870_QUALITY_GOOD);
    }
    else if (ioa >= IOA_MEASURED_SCALED_START &&
             ioa < IOA_MEASURED_SCALED_START + IOA_MEASURED_SCALED_COUNT) {
        int idx = ioa - IOA_MEASURED_SCALED_START;
        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_REQUEST,
                                     0, COMMON_ADDRESS, false, false);
        io = (InformationObject)MeasuredValueScaled_create(NULL, ioa,
                                                            measured_scaled[idx],
                                                            IEC60870_QUALITY_GOOD);
    }
    else {
        LOG_WARN("  Unknown IOA %d - sending negative response", ioa);
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
        IMasterConnection_sendASDU(connection, asdu);
        return true;
    }

    if (newAsdu && io) {
        CS101_ASDU_addInformationObject(newAsdu, io);
        IMasterConnection_sendASDU(connection, newAsdu);
        InformationObject_destroy(io);
        CS101_ASDU_destroy(newAsdu);
        LOG_DEBUG("  Sent value for IOA %d", ioa);
    }

    return true;
}

/* ==========================================================================
 * ASDU Handler (Commands)
 * ========================================================================== */

static bool asdu_handler(void* parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    IEC60870_5_TypeID typeId = CS101_ASDU_getTypeID(asdu);
    CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);

    LOG_DEBUG("Received ASDU type %d, COT %d", typeId, cot);

    switch (typeId) {

        /* ===== Single Command (C_SC_NA_1 = 45) ===== */
        case C_SC_NA_1: {
            SingleCommand sc = (SingleCommand)CS101_ASDU_getElement(asdu, 0);
            int ioa = InformationObject_getObjectAddress((InformationObject)sc);
            bool state = SingleCommand_getState(sc);

            LOG_INFO("Single Command: IOA=%d, State=%s, Select=%s",
                     ioa, state ? "ON" : "OFF",
                     SingleCommand_isSelect(sc) ? "SELECT" : "EXECUTE");

            if (ioa >= IOA_SINGLE_POINT_START &&
                ioa < IOA_SINGLE_POINT_START + IOA_SINGLE_POINT_COUNT) {

                /* Execute command (update value) */
                if (!SingleCommand_isSelect(sc)) {
                    single_points[ioa - IOA_SINGLE_POINT_START] = state;
                    LOG_INFO("  Command executed - IOA %d now %s", ioa, state ? "ON" : "OFF");
                }

                /* Send positive confirmation */
                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            } else {
                /* Unknown IOA */
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                CS101_ASDU_setNegative(asdu, true);
            }

            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Double Command (C_DC_NA_1 = 46) ===== */
        case C_DC_NA_1: {
            DoubleCommand dc = (DoubleCommand)CS101_ASDU_getElement(asdu, 0);
            int ioa = InformationObject_getObjectAddress((InformationObject)dc);
            int state = DoubleCommand_getState(dc);

            LOG_INFO("Double Command: IOA=%d, State=%d, Select=%s",
                     ioa, state,
                     DoubleCommand_isSelect(dc) ? "SELECT" : "EXECUTE");

            if (ioa >= IOA_DOUBLE_POINT_START &&
                ioa < IOA_DOUBLE_POINT_START + IOA_DOUBLE_POINT_COUNT) {

                if (!DoubleCommand_isSelect(dc)) {
                    double_points[ioa - IOA_DOUBLE_POINT_START] = state;
                    LOG_INFO("  Command executed - IOA %d now %d", ioa, state);
                }

                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            } else {
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                CS101_ASDU_setNegative(asdu, true);
            }

            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Regulating Step Command (C_RC_NA_1 = 47) ===== */
        case C_RC_NA_1: {
            StepCommand rc = (StepCommand)CS101_ASDU_getElement(asdu, 0);
            int ioa = InformationObject_getObjectAddress((InformationObject)rc);
            StepCommandValue scv = StepCommand_getState(rc);

            LOG_INFO("Step Command: IOA=%d, Direction=%s",
                     ioa, (scv == IEC60870_STEP_HIGHER) ? "HIGHER" : "LOWER");

            if (ioa >= IOA_STEP_POSITION_START &&
                ioa < IOA_STEP_POSITION_START + IOA_STEP_POSITION_COUNT) {

                int idx = ioa - IOA_STEP_POSITION_START;
                if (scv == IEC60870_STEP_HIGHER && step_positions[idx] < 63) {
                    step_positions[idx]++;
                } else if (scv == IEC60870_STEP_LOWER && step_positions[idx] > -64) {
                    step_positions[idx]--;
                }
                LOG_INFO("  Step position now %d", step_positions[idx]);

                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            } else {
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                CS101_ASDU_setNegative(asdu, true);
            }

            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Set Point Normalized (C_SE_NA_1 = 48) ===== */
        case C_SE_NA_1: {
            SetpointCommandNormalized spn = (SetpointCommandNormalized)CS101_ASDU_getElement(asdu, 0);
            int ioa = InformationObject_getObjectAddress((InformationObject)spn);
            float value = SetpointCommandNormalized_getValue(spn);

            LOG_INFO("Setpoint Normalized: IOA=%d, Value=%.4f", ioa, value);

            if (ioa >= IOA_MEASURED_NORM_START &&
                ioa < IOA_MEASURED_NORM_START + IOA_MEASURED_NORM_COUNT) {

                measured_norm[ioa - IOA_MEASURED_NORM_START] = value;
                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            } else {
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                CS101_ASDU_setNegative(asdu, true);
            }

            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Set Point Scaled (C_SE_NB_1 = 49) ===== */
        case C_SE_NB_1: {
            SetpointCommandScaled sps = (SetpointCommandScaled)CS101_ASDU_getElement(asdu, 0);
            int ioa = InformationObject_getObjectAddress((InformationObject)sps);
            int16_t value = SetpointCommandScaled_getValue(sps);

            LOG_INFO("Setpoint Scaled: IOA=%d, Value=%d", ioa, value);

            if (ioa >= IOA_MEASURED_SCALED_START &&
                ioa < IOA_MEASURED_SCALED_START + IOA_MEASURED_SCALED_COUNT) {

                measured_scaled[ioa - IOA_MEASURED_SCALED_START] = value;
                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            } else {
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                CS101_ASDU_setNegative(asdu, true);
            }

            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Set Point Short Float (C_SE_NC_1 = 50) ===== */
        case C_SE_NC_1: {
            SetpointCommandShort spc = (SetpointCommandShort)CS101_ASDU_getElement(asdu, 0);
            int ioa = InformationObject_getObjectAddress((InformationObject)spc);
            float value = SetpointCommandShort_getValue(spc);

            LOG_INFO("Setpoint Float: IOA=%d, Value=%.4f", ioa, value);

            if (ioa >= IOA_MEASURED_FLOAT_START &&
                ioa < IOA_MEASURED_FLOAT_START + IOA_MEASURED_FLOAT_COUNT) {

                measured_float[ioa - IOA_MEASURED_FLOAT_START] = value;
                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            } else {
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                CS101_ASDU_setNegative(asdu, true);
            }

            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Clock Synchronization (C_CS_NA_1 = 103) ===== */
        case C_CS_NA_1: {
            ClockSynchronizationCommand csc = (ClockSynchronizationCommand)CS101_ASDU_getElement(asdu, 0);
            CP56Time2a time = ClockSynchronizationCommand_getTime(csc);

            LOG_INFO("Clock Sync: %04d-%02d-%02d %02d:%02d:%02d",
                     CP56Time2a_getYear(time) + 2000,
                     CP56Time2a_getMonth(time),
                     CP56Time2a_getDayOfMonth(time),
                     CP56Time2a_getHour(time),
                     CP56Time2a_getMinute(time),
                     CP56Time2a_getSecond(time));

            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Test Command (C_TS_NA_1 = 104) ===== */
        case C_TS_NA_1: {
            LOG_INFO("Test Command received");
            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        /* ===== Reset Process (C_RP_NA_1 = 105) ===== */
        case C_RP_NA_1: {
            LOG_INFO("Reset Process Command received - reinitializing data");
            initialize_data();
            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            IMasterConnection_sendASDU(connection, asdu);
            return true;
        }

        default:
            LOG_WARN("Unhandled ASDU type %d", typeId);
            return false;
    }
}

/* ==========================================================================
 * Connection Event Handler
 * ========================================================================== */

static void connection_handler(void* parameter, IMasterConnection connection,
                                CS104_PeerConnectionEvent event)
{
    const char* eventStr;

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
        default:
            eventStr = "UNKNOWN";
    }

    LOG_INFO("Connection event: %s", eventStr);
}

/* ==========================================================================
 * Print Data Summary
 * ========================================================================== */

static void print_data_summary(void)
{
    printf("\n");
    printf("========================================\n");
    printf("IEC 60870-5-104 Test Server\n");
    printf("========================================\n");
    printf("\n");
    printf("Available Data Points:\n");
    printf("  Type ID   Name                    IOA Range\n");
    printf("  -------   ----------------------  -----------\n");
    printf("  1         M_SP_NA_1 (Single Pt)   %d-%d\n",
           IOA_SINGLE_POINT_START, IOA_SINGLE_POINT_START + IOA_SINGLE_POINT_COUNT - 1);
    printf("  3         M_DP_NA_1 (Double Pt)   %d-%d\n",
           IOA_DOUBLE_POINT_START, IOA_DOUBLE_POINT_START + IOA_DOUBLE_POINT_COUNT - 1);
    printf("  5         M_ST_NA_1 (Step Pos)    %d-%d\n",
           IOA_STEP_POSITION_START, IOA_STEP_POSITION_START + IOA_STEP_POSITION_COUNT - 1);
    printf("  7         M_BO_NA_1 (Bitstring)   %d-%d\n",
           IOA_BITSTRING_START, IOA_BITSTRING_START + IOA_BITSTRING_COUNT - 1);
    printf("  9         M_ME_NA_1 (Meas Norm)   %d-%d\n",
           IOA_MEASURED_NORM_START, IOA_MEASURED_NORM_START + IOA_MEASURED_NORM_COUNT - 1);
    printf("  11        M_ME_NB_1 (Meas Scale)  %d-%d\n",
           IOA_MEASURED_SCALED_START, IOA_MEASURED_SCALED_START + IOA_MEASURED_SCALED_COUNT - 1);
    printf("  13        M_ME_NC_1 (Meas Float)  %d-%d\n",
           IOA_MEASURED_FLOAT_START, IOA_MEASURED_FLOAT_START + IOA_MEASURED_FLOAT_COUNT - 1);
    printf("  15        M_IT_NA_1 (Int Totals)  %d-%d\n",
           IOA_INTEGRATED_TOTALS_START, IOA_INTEGRATED_TOTALS_START + IOA_INTEGRATED_TOTALS_COUNT - 1);
    printf("\n");
    printf("Available Commands:\n");
    printf("  Type ID   Name                    Target IOA Range\n");
    printf("  -------   ----------------------  ----------------\n");
    printf("  45        C_SC_NA_1 (Single Cmd)  %d-%d\n",
           IOA_SINGLE_POINT_START, IOA_SINGLE_POINT_START + IOA_SINGLE_POINT_COUNT - 1);
    printf("  46        C_DC_NA_1 (Double Cmd)  %d-%d\n",
           IOA_DOUBLE_POINT_START, IOA_DOUBLE_POINT_START + IOA_DOUBLE_POINT_COUNT - 1);
    printf("  47        C_RC_NA_1 (Step Cmd)    %d-%d\n",
           IOA_STEP_POSITION_START, IOA_STEP_POSITION_START + IOA_STEP_POSITION_COUNT - 1);
    printf("  48        C_SE_NA_1 (SetPt Norm)  %d-%d\n",
           IOA_MEASURED_NORM_START, IOA_MEASURED_NORM_START + IOA_MEASURED_NORM_COUNT - 1);
    printf("  49        C_SE_NB_1 (SetPt Scale) %d-%d\n",
           IOA_MEASURED_SCALED_START, IOA_MEASURED_SCALED_START + IOA_MEASURED_SCALED_COUNT - 1);
    printf("  50        C_SE_NC_1 (SetPt Float) %d-%d\n",
           IOA_MEASURED_FLOAT_START, IOA_MEASURED_FLOAT_START + IOA_MEASURED_FLOAT_COUNT - 1);
    printf("  100       C_IC_NA_1 (Interrogate) -\n");
    printf("  101       C_CI_NA_1 (Counter Int) -\n");
    printf("  102       C_RD_NA_1 (Read)        Any valid IOA\n");
    printf("  103       C_CS_NA_1 (Clock Sync)  -\n");
    printf("  104       C_TS_NA_1 (Test)        -\n");
    printf("  105       C_RP_NA_1 (Reset)       -\n");
    printf("\n");
    printf("File Transfer (IOA %d-%d):\n", IOA_FILE_DIRECTORY, IOA_FILE_DISTURBANCE);
    printf("  %d - File Directory\n", IOA_FILE_DIRECTORY);
    printf("  %d - config.xml\n", IOA_FILE_CONFIG);
    printf("  %d - events.log\n", IOA_FILE_EVENTS);
    printf("  %d - disturbance_001.comtrade\n", IOA_FILE_DISTURBANCE);
    printf("\n");
    printf("========================================\n");
    printf("\n");
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char** argv)
{
    int port = DEFAULT_PORT;
    const char* data_dir = "./data";

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [port] [options]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  -v, --verbose    Enable verbose logging\n");
            printf("  -h, --help       Show this help\n");
            printf("\nDefault port: %d\n", DEFAULT_PORT);
            return 0;
        } else if (argv[i][0] != '-') {
            port = atoi(argv[i]);
            if (port <= 0 || port > 65535) {
                LOG_ERROR("Invalid port: %s", argv[i]);
                return 1;
            }
        }
    }

    /* Setup signal handler */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Print banner and data summary */
    print_data_summary();

    /* Initialize data */
    initialize_data();
    initialize_files(data_dir);

    /* Create slave instance */
    LOG_INFO("Creating IEC 104 slave on port %d...", port);
    slave = CS104_Slave_create(MAX_QUEUE_SIZE, MAX_LOW_PRIO_QUEUE);

    if (!slave) {
        LOG_ERROR("Failed to create CS104 slave");
        return 1;
    }

    /* Configure slave */
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

    /* Set handlers */
    CS104_Slave_setInterrogationHandler(slave, interrogation_handler, NULL);
    CS104_Slave_setCounterInterrogationHandler(slave, counter_interrogation_handler, NULL);
    CS104_Slave_setReadHandler(slave, read_handler, NULL);
    CS104_Slave_setASDUHandler(slave, asdu_handler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, connection_handler, NULL);

    /* Start server */
    CS104_Slave_start(slave);

    if (!CS104_Slave_isRunning(slave)) {
        LOG_ERROR("Failed to start server on port %d", port);
        CS104_Slave_destroy(slave);
        return 1;
    }

    LOG_INFO("Server running on port %d - Press Ctrl+C to stop", port);

    /* Main loop - periodically update values to simulate real RTU */
    int tick = 0;
    while (running) {
        Thread_sleep(1000);  /* 1 second */

        tick++;

        /* Update some values periodically */
        if (tick % 5 == 0) {
            /* Update a few measured values */
            for (int i = 0; i < 5; i++) {
                measured_float[i] += ((float)rand() / RAND_MAX - 0.5f) * 10.0f;
                measured_scaled[i] += (rand() % 100) - 50;
                integrated_totals[i] += rand() % 10;
            }

            /* Toggle a single point occasionally */
            if (tick % 10 == 0) {
                int idx = rand() % IOA_SINGLE_POINT_COUNT;
                single_points[idx] = !single_points[idx];
                LOG_DEBUG("Auto-toggled single point %d to %s",
                          IOA_SINGLE_POINT_START + idx,
                          single_points[idx] ? "ON" : "OFF");
            }
        }
    }

    /* Shutdown */
    LOG_INFO("Shutting down...");
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);

    LOG_INFO("Server stopped");
    return 0;
}
