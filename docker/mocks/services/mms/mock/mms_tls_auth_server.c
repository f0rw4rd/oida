/*
 *  mms_tls_auth_server.c
 *
 *  MMS/IEC 61850 server combining TLS transport encryption with
 *  ACSE password authentication.  Built for OIDA mock testing.
 *
 *  Credentials:
 *      admin:admin@mms       (full access - read/write/control)
 *      operator:operator@mms (read-only, no control)
 *
 *  Certificate files expected in /etc/iec61850/certs/:
 *      server_CA1_1.key   - server private key
 *      server_CA1_1.pem   - server certificate
 *      root_CA1.pem       - CA root certificate
 *      client_CA1_1.pem   - allowed client certificate 1
 *      client_CA1_2.pem   - allowed client certificate 2
 *
 *  Based on libiec61850 v1.6.0 server_example_password_auth and
 *  tls_server_example patterns.
 */

#include "iec61850_server.h"
#include "hal_thread.h"
#include "tls_config.h"
#include "static_model.h"

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* ---------- globals ---------- */

static int running = 0;
static IedServer iedServer = NULL;

/* credentials */
static char *password_admin    = "admin@mms";
static char *password_operator = "operator@mms";

/* certificate paths */
static const char *CERT_DIR        = "/etc/iec61850/certs/";
static const char *SERVER_KEY      = "/etc/iec61850/certs/server_CA1_1.key";
static const char *SERVER_CERT     = "/etc/iec61850/certs/server_CA1_1.pem";
static const char *CA_CERT         = "/etc/iec61850/certs/root_CA1.pem";
static const char *CLIENT_CERT_1   = "/etc/iec61850/certs/client_CA1_1.pem";
static const char *CLIENT_CERT_2   = "/etc/iec61850/certs/client_CA1_2.pem";

/* ---------- signal handler ---------- */

void
sigint_handler(int signalId)
{
    running = 0;
}

/* ---------- authenticator callback ---------- */

static void
printAppTitle(ItuObjectIdentifier *oid)
{
    int i;
    for (i = 0; i < oid->arcCount; i++) {
        printf("%i", oid->arc[i]);
        if (i != (oid->arcCount - 1))
            printf(".");
    }
}

static bool
clientAuthenticator(void *parameter, AcseAuthenticationParameter authParameter,
                    void **securityToken, IsoApplicationReference *appRef)
{
    printf("[AUTH] ACSE authenticator invoked\n");
    printf("[AUTH]   client ap-title: ");
    printAppTitle(&(appRef->apTitle));
    printf("\n");
    printf("[AUTH]   client ae-qualifier: %i\n", appRef->aeQualifier);
    printf("[AUTH]   auth-mechanism: %i\n", authParameter->mechanism);

    /* Accept TLS-only connections (cert already validated by mbedTLS) */
    if (authParameter->mechanism == ACSE_AUTH_TLS) {
        printf("[AUTH]   TLS certificate present (size: %i) - accepted\n",
               authParameter->value.certificate.length);
        *securityToken = (void *) password_admin;
        return true;
    }

    /* Password authentication */
    if (authParameter->mechanism == ACSE_AUTH_PASSWORD) {
        int pwLen = authParameter->value.password.passwordLength;
        char *pw  = (char *) authParameter->value.password.octetString;

        if (pwLen == (int) strlen(password_admin) &&
            memcmp(pw, password_admin, pwLen) == 0) {
            printf("[AUTH]   password match: admin - accepted\n");
            *securityToken = (void *) password_admin;
            return true;
        }

        if (pwLen == (int) strlen(password_operator) &&
            memcmp(pw, password_operator, pwLen) == 0) {
            printf("[AUTH]   password match: operator - accepted\n");
            *securityToken = (void *) password_operator;
            return true;
        }

        printf("[AUTH]   password mismatch - rejected\n");
        return false;
    }

    printf("[AUTH]   unknown mechanism %i - rejected\n", authParameter->mechanism);
    return false;
}

/* ---------- connection handler ---------- */

static void
connectionHandler(IedServer self, ClientConnection connection,
                  bool connected, void *parameter)
{
    if (connected)
        printf("[CONN] Connection opened\n");
    else
        printf("[CONN] Connection closed\n");
}

/* ---------- TLS security event handler ---------- */

static void
securityEventHandler(void *parameter, TLSEventLevel eventLevel,
                     int eventCode, const char *msg, TLSConnection con)
{
    (void)parameter;
    char *peerAddr = TLSConnection_getPeerAddress(con, NULL);
    const char *tlsVersionStr = TLSConfigVersion_toString(TLSConnection_getTLSVersion(con));

    printf("[TLS-EVENT %s] %s (peer=%s)(level=%i, code=%i)\n",
           tlsVersionStr, msg, peerAddr, eventLevel, eventCode);

    free(peerAddr);
}

/* ---------- control check handler ---------- */

static CheckHandlerResult
performCheckHandler(ControlAction action, void *parameter, MmsValue *ctlVal,
                    bool test, bool interlockCheck, ClientConnection connection)
{
    void *securityToken = ClientConnection_getSecurityToken(connection);

    if (securityToken == password_admin) {
        printf("[CTRL] Control accepted (admin)\n");
        return CONTROL_ACCEPTED;
    }

    printf("[CTRL] Control denied (not admin)\n");
    return CONTROL_OBJECT_ACCESS_DENIED;
}

/* ---------- control handler ---------- */

static void
controlHandlerForBinaryOutput(ControlAction action, void *parameter,
                              MmsValue *value, bool test)
{
    MmsValue *timeStamp = MmsValue_newUtcTimeByMsTime(Hal_getTimeInMs());

    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO1) {
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1_stVal, value);
    }
    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO2) {
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2_stVal, value);
    }
    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO3) {
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3_stVal, value);
    }
    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO4) {
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4_stVal, value);
    }

    MmsValue_delete(timeStamp);
}

/* ---------- write access handler ---------- */

static MmsDataAccessError
writeAccessHandler(DataAttribute *dataAttribute, MmsValue *value,
                   ClientConnection connection, void *parameter)
{
    void *securityToken = ClientConnection_getSecurityToken(connection);

    if (securityToken != password_admin) {
        printf("[WRITE] Access denied (not admin)\n");
        return DATA_ACCESS_ERROR_OBJECT_ACCESS_DENIED;
    }

    return DATA_ACCESS_ERROR_SUCCESS;
}

/* ---------- read access handler ---------- */

static MmsDataAccessError
readAccessHandler(LogicalDevice *ld, LogicalNode *ln, DataObject *dataObject,
                  FunctionalConstraint fc, ClientConnection connection, void *parameter)
{
    /* Both admin and operator can read */
    return DATA_ACCESS_ERROR_SUCCESS;
}

/* ========== main ========== */

int
main(int argc, char **argv)
{
    int tcpPort = 102;

    /* Disable stdout buffering so Docker logs work */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1)
        tcpPort = atoi(argv[1]);

    printf("==============================================\n");
    printf("  MMS TLS + Password Auth Server\n");
    printf("  libiec61850 %s\n", LibIEC61850_getVersionString());
    printf("  Port: %d\n", tcpPort);
    printf("  Credentials:\n");
    printf("    admin:%s     (full access)\n", password_admin);
    printf("    operator:%s  (read-only)\n", password_operator);
    printf("==============================================\n");

    /* ----- TLS configuration ----- */
    printf("[TLS] Configuring TLS...\n");

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_setChainValidation(tlsConfig, false);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);
    TLSConfiguration_setEventHandler(tlsConfig, securityEventHandler, NULL);

    if (!TLSConfiguration_setOwnKeyFromFile(tlsConfig, SERVER_KEY, NULL)) {
        printf("[TLS] ERROR: Failed to load server private key: %s\n", SERVER_KEY);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }
    printf("[TLS] Loaded server key: %s\n", SERVER_KEY);

    if (!TLSConfiguration_setOwnCertificateFromFile(tlsConfig, SERVER_CERT)) {
        printf("[TLS] ERROR: Failed to load server certificate: %s\n", SERVER_CERT);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }
    printf("[TLS] Loaded server cert: %s\n", SERVER_CERT);

    if (!TLSConfiguration_addCACertificateFromFile(tlsConfig, CA_CERT)) {
        printf("[TLS] ERROR: Failed to load CA certificate: %s\n", CA_CERT);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }
    printf("[TLS] Loaded CA cert: %s\n", CA_CERT);

    if (!TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, CLIENT_CERT_1)) {
        printf("[TLS] WARNING: Failed to load allowed client cert: %s\n", CLIENT_CERT_1);
    } else {
        printf("[TLS] Loaded allowed client cert: %s\n", CLIENT_CERT_1);
    }

    if (!TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, CLIENT_CERT_2)) {
        printf("[TLS] WARNING: Failed to load allowed client cert: %s\n", CLIENT_CERT_2);
    } else {
        printf("[TLS] Loaded allowed client cert: %s\n", CLIENT_CERT_2);
    }

    printf("[TLS] TLS configuration complete\n");

    /* ----- create IED server with TLS ----- */
    iedServer = IedServer_createWithTlsSupport(&iedModel, tlsConfig);

    if (iedServer == NULL) {
        printf("ERROR: Failed to create IED server\n");
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    /* ----- set up authentication ----- */
    printf("[AUTH] Setting up password authenticator...\n");
    IedServer_setAuthenticator(iedServer, clientAuthenticator, NULL);

    /* ----- set up connection handler ----- */
    IedServer_setConnectionIndicationHandler(iedServer,
        (IedConnectionIndicationHandler) connectionHandler, NULL);

    /* ----- control handlers ----- */
    IedServer_setPerformCheckHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1,
        (ControlPerformCheckHandler) performCheckHandler, NULL);
    IedServer_setPerformCheckHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2,
        (ControlPerformCheckHandler) performCheckHandler, NULL);
    IedServer_setPerformCheckHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3,
        (ControlPerformCheckHandler) performCheckHandler, NULL);
    IedServer_setPerformCheckHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4,
        (ControlPerformCheckHandler) performCheckHandler, NULL);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1,
        (ControlHandler) controlHandlerForBinaryOutput, IEDMODEL_GenericIO_GGIO1_SPCSO1);
    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2,
        (ControlHandler) controlHandlerForBinaryOutput, IEDMODEL_GenericIO_GGIO1_SPCSO2);
    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3,
        (ControlHandler) controlHandlerForBinaryOutput, IEDMODEL_GenericIO_GGIO1_SPCSO3);
    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4,
        (ControlHandler) controlHandlerForBinaryOutput, IEDMODEL_GenericIO_GGIO1_SPCSO4);

    /* ----- access policies ----- */
    IedServer_setWriteAccessPolicy(iedServer, IEC61850_FC_SP, ACCESS_POLICY_DENY);
    IedServer_handleWriteAccess(iedServer, IEDMODEL_GenericIO_LLN0_ModAuto_setVal,
        writeAccessHandler, NULL);
    IedServer_setReadAccessHandler(iedServer, readAccessHandler, NULL);

    /* ----- start server ----- */
    IedServer_start(iedServer, tcpPort);

    if (!IedServer_isRunning(iedServer)) {
        printf("ERROR: Starting server failed on port %d! Exit.\n", tcpPort);
        IedServer_destroy(iedServer);
        TLSConfiguration_destroy(tlsConfig);
        return 1;
    }

    printf("[SERVER] MMS TLS+Auth server running on port %d\n", tcpPort);
    printf("[SERVER] Waiting for connections...\n");

    running = 1;
    signal(SIGINT, sigint_handler);

    while (running)
        Thread_sleep(100);

    /* ----- cleanup ----- */
    printf("[SERVER] Shutting down...\n");
    IedServer_stop(iedServer);
    IedServer_destroy(iedServer);
    TLSConfiguration_destroy(tlsConfig);

    printf("[SERVER] Server stopped.\n");
    return 0;
}
