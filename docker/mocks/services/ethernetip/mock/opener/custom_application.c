/*******************************************************************************
 * Custom OpENer Application - Extended CIP Objects for Testing
 *
 * This application extends the default OpENer with additional CIP objects
 * for testing the oida EtherNet/IP scanner's advanced features.
 *
 * Added objects:
 *   - Assembly (0x04) - Multiple I/O assemblies
 *   - Parameter (0x0F) - Device parameters
 *   - File (0x37) - Simulated firmware files
 *   - Port (0x47) - Communication ports
 *   - Vendor Specific (0x64) - Custom class example
 ******************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "opener_api.h"
#include "appcontype.h"
#include "trace.h"
#include "cipidentity.h"
#include "ciptcpipinterface.h"
#include "cipqos.h"
#include "nvdata.h"

/* Assembly Object Instances */
#define ASSEMBLY_INPUT_1       100  /* Input assembly 1 */
#define ASSEMBLY_INPUT_2       101  /* Input assembly 2 */
#define ASSEMBLY_OUTPUT_1      150  /* Output assembly 1 */
#define ASSEMBLY_OUTPUT_2      151  /* Output assembly 2 */
#define ASSEMBLY_CONFIG        152  /* Configuration assembly */
#define ASSEMBLY_HEARTBEAT_IN  153  /* Heartbeat for input-only */
#define ASSEMBLY_HEARTBEAT_LO  154  /* Heartbeat for listen-only */
#define ASSEMBLY_EXPLICIT      155  /* Explicit messaging */

/* Parameter Object class code */
#define CIP_PARAMETER_CLASS    0x0F

/* File Object class code */
#define CIP_FILE_CLASS         0x37

/* Port Object class code */
#define CIP_PORT_CLASS         0x47

/* Vendor Specific class (0x64 = first vendor class) */
#define VENDOR_SPECIFIC_CLASS  0x64

/* CIP Security Object Classes */
#define CIP_SECURITY_CLASS            0x5D  /* CIP Security Object */
#define EIP_SECURITY_CLASS            0x5E  /* EtherNet/IP Security Object */
#define CERT_MANAGEMENT_CLASS         0x5F  /* Certificate Management Object */
#define AUTHORITY_CLASS               0x60  /* Authority Object */
#define PASSWORD_AUTH_CLASS           0x61  /* Password Authenticator Object */
#define CERTIFICATE_AUTH_CLASS        0x62  /* Certificate Authenticator Object */

/* Assembly data buffers */
EipUint8 g_input_data_1[32];   /* Input 1: 32 bytes */
EipUint8 g_input_data_2[16];   /* Input 2: 16 bytes */
EipUint8 g_output_data_1[32];  /* Output 1: 32 bytes */
EipUint8 g_output_data_2[16];  /* Output 2: 16 bytes */
EipUint8 g_config_data[10];    /* Config: 10 bytes */
EipUint8 g_explicit_data[64];  /* Explicit: 64 bytes */

/* Parameter Object data */
typedef struct {
    EipUint16 value;
    EipUint16 min_value;
    EipUint16 max_value;
    EipUint16 default_value;
    char name[32];
} ParameterData;

ParameterData g_parameters[10] = {
    {100, 0, 1000, 100, "Speed_Setpoint"},
    {50, 0, 100, 50, "Pressure_Limit"},
    {25, 0, 50, 25, "Temperature_Offset"},
    {1, 0, 1, 1, "Auto_Mode_Enable"},
    {60, 1, 120, 60, "Timeout_Seconds"},
    {0, 0, 255, 0, "Debug_Level"},
    {192, 0, 255, 192, "Network_ID"},
    {44818, 1, 65535, 44818, "Port_Number"},
    {500, 100, 5000, 500, "Scan_Rate_ms"},
    {1, 0, 10, 1, "Retry_Count"},
};

/* File Object data */
typedef struct {
    char filename[64];
    EipUint32 size;
    EipUint16 revision;
    EipUint8 state;  /* 0=nonexistent, 1=empty, 2=loaded, 3=download, 4=upload */
} FileData;

FileData g_files[3] = {
    {"firmware.bin", 524288, 203, 2},
    {"config.xml", 4096, 15, 2},
    {"eventlog.dat", 8192, 1, 2},
};

/* Port Object data */
typedef struct {
    EipUint16 port_type;  /* 2 = EtherNet/IP */
    EipUint16 port_number;
    char port_name[32];
    EipBool8 port_enabled;
} PortData;

PortData g_ports[2] = {
    {2, 1, "Ethernet_Port_1", true},
    {2, 2, "Ethernet_Port_2", false},
};

/* Vendor Specific class data */
typedef struct {
    EipUint32 counter;
    EipUint16 status;
    char description[64];
} VendorData;

VendorData g_vendor_data = {
    12345,
    0x0001,
    "OIDA Test Device v1.0"
};

/* CIP Security Object data */
typedef struct {
    EipUint8 security_state;        /* 0=factory, 1=configuring, 2=configured, 3=incomplete */
    EipUint8 security_profiles;     /* Bitmask of supported profiles */
    EipUint8 active_profile;        /* Currently active security profile */
} CipSecurityData;

CipSecurityData g_cip_security = {
    2,      /* Configured */
    0x03,   /* Profiles: EtherNet/IP Confidentiality + CIP Authorization */
    0x01    /* EtherNet/IP Confidentiality Profile active */
};

/* EtherNet/IP Security Object data */
typedef struct {
    EipUint8 state;                 /* 0=factory, 1=configured, 2=operational */
    EipUint8 capability_flags;      /* Security capabilities */
    EipUint8 psk_pre_shared_keys;   /* Number of PSKs configured */
    EipUint8 active_psk_slot;       /* Active PSK slot */
} EipSecurityData;

EipSecurityData g_eip_security = {
    2,      /* Operational */
    0x1F,   /* TLS 1.2, TLS 1.3, DTLS 1.2, Pre-Shared Keys, Certificates */
    2,      /* 2 PSKs configured */
    1       /* Slot 1 active */
};

/* Certificate Management Object data */
typedef struct {
    EipUint8 state;                 /* 0=no certs, 1=certs present */
    EipUint8 max_certs;             /* Max certificates supported */
    EipUint8 installed_certs;       /* Number installed */
    char device_cert_cn[64];        /* Device certificate CN */
} CertMgmtData;

CertMgmtData g_cert_mgmt = {
    1,      /* Certificates present */
    5,      /* Max 5 certs */
    2,      /* 2 installed */
    "opener-device.local"
};

/* Password Authenticator data */
typedef struct {
    EipUint8 state;                 /* 0=disabled, 1=enabled */
    EipUint8 password_configured;   /* Is password set? */
    EipUint8 max_password_len;      /* Max password length */
    EipUint8 min_password_len;      /* Min password length */
} PasswordAuthData;

PasswordAuthData g_password_auth = {
    1,      /* Enabled */
    1,      /* Password configured */
    32,     /* Max 32 chars */
    8       /* Min 8 chars */
};

/* Forward declarations */
EipStatus ParameterGetAttributeSingle(CipInstance *instance,
                                       CipMessageRouterRequest *request,
                                       CipMessageRouterResponse *response,
                                       const struct sockaddr *originator_address,
                                       const CipSessionHandle encapsulation_session);

EipStatus FileGetAttributeSingle(CipInstance *instance,
                                  CipMessageRouterRequest *request,
                                  CipMessageRouterResponse *response,
                                  const struct sockaddr *originator_address,
                                  const CipSessionHandle encapsulation_session);

EipStatus PortGetAttributeSingle(CipInstance *instance,
                                  CipMessageRouterRequest *request,
                                  CipMessageRouterResponse *response,
                                  const struct sockaddr *originator_address,
                                  const CipSessionHandle encapsulation_session);

EipStatus VendorGetAttributeSingle(CipInstance *instance,
                                    CipMessageRouterRequest *request,
                                    CipMessageRouterResponse *response,
                                    const struct sockaddr *originator_address,
                                    const CipSessionHandle encapsulation_session);

/* CIP Security Object service handlers */
EipStatus CipSecurityGetAttributeSingle(CipInstance *instance,
                                         CipMessageRouterRequest *request,
                                         CipMessageRouterResponse *response,
                                         const struct sockaddr *originator_address,
                                         const CipSessionHandle encapsulation_session);

EipStatus EipSecurityGetAttributeSingle(CipInstance *instance,
                                         CipMessageRouterRequest *request,
                                         CipMessageRouterResponse *response,
                                         const struct sockaddr *originator_address,
                                         const CipSessionHandle encapsulation_session);

EipStatus CertMgmtGetAttributeSingle(CipInstance *instance,
                                      CipMessageRouterRequest *request,
                                      CipMessageRouterResponse *response,
                                      const struct sockaddr *originator_address,
                                      const CipSessionHandle encapsulation_session);

EipStatus PasswordAuthGetAttributeSingle(CipInstance *instance,
                                          CipMessageRouterRequest *request,
                                          CipMessageRouterResponse *response,
                                          const struct sockaddr *originator_address,
                                          const CipSessionHandle encapsulation_session);

/*******************************************************************************
 * Parameter Object (0x0F) - Device configuration parameters
 ******************************************************************************/
void CreateParameterObject(void) {
    CipClass *parameter_class = CreateCipClass(
        CIP_PARAMETER_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services (Get_Attribute_Single, Get_Attributes_All) */
        7,     /* number of instance attributes */
        7,     /* highest instance attribute number */
        1,     /* number of instance services */
        10,    /* number of instances */
        "Parameter",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (parameter_class != NULL) {
        /* Insert Get_Attribute_Single service */
        InsertService(parameter_class, kGetAttributeSingle,
                      ParameterGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("Parameter Object (0x0F) created with 10 instances\n");
    }
}

/*******************************************************************************
 * File Object (0x37) - Simulated firmware/config files
 ******************************************************************************/
void CreateFileObject(void) {
    CipClass *file_class = CreateCipClass(
        CIP_FILE_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        7,     /* number of instance attributes */
        7,     /* highest instance attribute number */
        1,     /* number of instance services */
        3,     /* number of instances (3 files) */
        "File",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (file_class != NULL) {
        InsertService(file_class, kGetAttributeSingle,
                      FileGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("File Object (0x37) created with 3 instances\n");
    }
}

/*******************************************************************************
 * Port Object (0x47) - Communication ports
 ******************************************************************************/
void CreatePortObject(void) {
    CipClass *port_class = CreateCipClass(
        CIP_PORT_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        5,     /* number of instance attributes */
        5,     /* highest instance attribute number */
        1,     /* number of instance services */
        2,     /* number of instances (2 ports) */
        "Port",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (port_class != NULL) {
        InsertService(port_class, kGetAttributeSingle,
                      PortGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("Port Object (0x47) created with 2 instances\n");
    }
}

/*******************************************************************************
 * Vendor Specific Object (0x64) - Custom vendor class
 ******************************************************************************/
void CreateVendorSpecificObject(void) {
    CipClass *vendor_class = CreateCipClass(
        VENDOR_SPECIFIC_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        5,     /* number of instance attributes */
        5,     /* highest instance attribute number */
        1,     /* number of instance services */
        1,     /* number of instances */
        "VendorSpecific",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (vendor_class != NULL) {
        InsertService(vendor_class, kGetAttributeSingle,
                      VendorGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("Vendor Specific Object (0x64) created\n");
    }
}

/*******************************************************************************
 * CIP Security Object (0x5D) - Security configuration and state
 ******************************************************************************/
void CreateCipSecurityObject(void) {
    CipClass *security_class = CreateCipClass(
        CIP_SECURITY_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        5,     /* number of instance attributes */
        5,     /* highest instance attribute number */
        1,     /* number of instance services */
        1,     /* number of instances */
        "CIP Security",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (security_class != NULL) {
        InsertService(security_class, kGetAttributeSingle,
                      CipSecurityGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("CIP Security Object (0x5D) created\n");
    }
}

/*******************************************************************************
 * EtherNet/IP Security Object (0x5E) - TLS/DTLS configuration
 ******************************************************************************/
void CreateEipSecurityObject(void) {
    CipClass *eip_security_class = CreateCipClass(
        EIP_SECURITY_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        8,     /* number of instance attributes */
        8,     /* highest instance attribute number */
        1,     /* number of instance services */
        1,     /* number of instances */
        "EtherNet/IP Security",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (eip_security_class != NULL) {
        InsertService(eip_security_class, kGetAttributeSingle,
                      EipSecurityGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("EtherNet/IP Security Object (0x5E) created\n");
    }
}

/*******************************************************************************
 * Certificate Management Object (0x5F) - Certificate storage and management
 ******************************************************************************/
void CreateCertMgmtObject(void) {
    CipClass *cert_class = CreateCipClass(
        CERT_MANAGEMENT_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        6,     /* number of instance attributes */
        6,     /* highest instance attribute number */
        1,     /* number of instance services */
        1,     /* number of instances */
        "Certificate Management",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (cert_class != NULL) {
        InsertService(cert_class, kGetAttributeSingle,
                      CertMgmtGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("Certificate Management Object (0x5F) created\n");
    }
}

/*******************************************************************************
 * Password Authenticator Object (0x61) - Password-based authentication
 ******************************************************************************/
void CreatePasswordAuthObject(void) {
    CipClass *password_class = CreateCipClass(
        PASSWORD_AUTH_CLASS,
        0,     /* number of class attributes */
        7,     /* highest class attribute number */
        2,     /* number of class services */
        6,     /* number of instance attributes */
        6,     /* highest instance attribute number */
        1,     /* number of instance services */
        1,     /* number of instances */
        "Password Authenticator",
        1,     /* revision */
        NULL   /* initializer function */
    );

    if (password_class != NULL) {
        InsertService(password_class, kGetAttributeSingle,
                      PasswordAuthGetAttributeSingle, "GetAttributeSingle");

        OPENER_TRACE_INFO("Password Authenticator Object (0x61) created\n");
    }
}

/*******************************************************************************
 * Service Implementations
 ******************************************************************************/

/* Parameter Object - Get Attribute Single */
EipStatus ParameterGetAttributeSingle(CipInstance *instance,
                                       CipMessageRouterRequest *request,
                                       CipMessageRouterResponse *response,
                                       const struct sockaddr *originator_address,
                                       const CipSessionHandle encapsulation_session) {
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 instance_id = instance->instance_number;
    EipUint16 attr_id = request->request_path.attribute_number;

    if (instance_id < 1 || instance_id > 10) {
        response->general_status = kCipErrorPathDestinationUnknown;
        return kEipStatusOkSend;
    }

    ParameterData *param = &g_parameters[instance_id - 1];

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* Value */
            AddIntToMessage(param->value, &response->message);
            break;
        case 2:  /* Link Path Size (placeholder) */
            AddIntToMessage(0, &response->message);
            break;
        case 3:  /* Descriptor */
            AddIntToMessage(0x0001, &response->message);  /* Readable */
            break;
        case 4:  /* Data Type */
            AddIntToMessage(0xC7, &response->message);  /* UINT */
            break;
        case 5:  /* Data Size */
            AddIntToMessage(2, &response->message);
            break;
        case 6:  /* Name (SHORT_STRING) */
            {
                EipUint16 name_len = strlen(param->name);
                AddIntToMessage(name_len, &response->message);
                for (int i = 0; i < name_len; i++) {
                    AddSintToMessage(param->name[i], &response->message);
                }
            }
            break;
        case 7:  /* Name (same as 6 for compatibility) */
            {
                EipUint16 name_len = strlen(param->name);
                AddIntToMessage(name_len, &response->message);
                for (int i = 0; i < name_len; i++) {
                    AddSintToMessage(param->name[i], &response->message);
                }
            }
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* File Object - Get Attribute Single */
EipStatus FileGetAttributeSingle(CipInstance *instance,
                                  CipMessageRouterRequest *request,
                                  CipMessageRouterResponse *response,
                                  const struct sockaddr *originator_address,
                                  const CipSessionHandle encapsulation_session) {
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 instance_id = instance->instance_number;
    EipUint16 attr_id = request->request_path.attribute_number;

    if (instance_id < 1 || instance_id > 3) {
        response->general_status = kCipErrorPathDestinationUnknown;
        return kEipStatusOkSend;
    }

    FileData *file = &g_files[instance_id - 1];

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* State */
            AddSintToMessage(file->state, &response->message);
            break;
        case 2:  /* Instance Name (SHORT_STRING) */
            {
                char inst_name[16];
                snprintf(inst_name, sizeof(inst_name), "File%d", instance_id);
                EipUint16 name_len = strlen(inst_name);
                AddIntToMessage(name_len, &response->message);
                for (int i = 0; i < name_len; i++) {
                    AddSintToMessage(inst_name[i], &response->message);
                }
            }
            break;
        case 3:  /* Instance Format Version */
            AddIntToMessage(1, &response->message);
            break;
        case 4:  /* File Name (SHORT_STRING) */
            {
                EipUint16 name_len = strlen(file->filename);
                AddIntToMessage(name_len, &response->message);
                for (int i = 0; i < name_len; i++) {
                    AddSintToMessage(file->filename[i], &response->message);
                }
            }
            break;
        case 5:  /* File Revision */
            AddIntToMessage(file->revision, &response->message);
            break;
        case 6:  /* File Size */
            AddDintToMessage(file->size, &response->message);
            break;
        case 7:  /* File Checksum (placeholder) */
            AddIntToMessage(0x1234, &response->message);
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* Port Object - Get Attribute Single */
EipStatus PortGetAttributeSingle(CipInstance *instance,
                                  CipMessageRouterRequest *request,
                                  CipMessageRouterResponse *response,
                                  const struct sockaddr *originator_address,
                                  const CipSessionHandle encapsulation_session) {
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 instance_id = instance->instance_number;
    EipUint16 attr_id = request->request_path.attribute_number;

    if (instance_id < 1 || instance_id > 2) {
        response->general_status = kCipErrorPathDestinationUnknown;
        return kEipStatusOkSend;
    }

    PortData *port = &g_ports[instance_id - 1];

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* Port Type */
            AddIntToMessage(port->port_type, &response->message);
            break;
        case 2:  /* Port Number */
            AddIntToMessage(port->port_number, &response->message);
            break;
        case 3:  /* Link Object */
            /* Path to Ethernet Link object */
            AddIntToMessage(2, &response->message);  /* Path size */
            AddSintToMessage(0x20, &response->message);  /* Class segment */
            AddSintToMessage(0xF6, &response->message);  /* Ethernet Link */
            break;
        case 4:  /* Port Name (SHORT_STRING) */
            {
                EipUint16 name_len = strlen(port->port_name);
                AddIntToMessage(name_len, &response->message);
                for (int i = 0; i < name_len; i++) {
                    AddSintToMessage(port->port_name[i], &response->message);
                }
            }
            break;
        case 5:  /* Port Enabled */
            AddSintToMessage(port->port_enabled ? 1 : 0, &response->message);
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* Vendor Specific Object - Get Attribute Single */
EipStatus VendorGetAttributeSingle(CipInstance *instance,
                                    CipMessageRouterRequest *request,
                                    CipMessageRouterResponse *response,
                                    const struct sockaddr *originator_address,
                                    const CipSessionHandle encapsulation_session) {
    (void)instance;
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 attr_id = request->request_path.attribute_number;

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* Counter (UDINT) */
            AddDintToMessage(g_vendor_data.counter, &response->message);
            /* Increment counter on each read */
            g_vendor_data.counter++;
            break;
        case 2:  /* Status (UINT) */
            AddIntToMessage(g_vendor_data.status, &response->message);
            break;
        case 3:  /* Description (SHORT_STRING) */
            {
                EipUint16 len = strlen(g_vendor_data.description);
                AddIntToMessage(len, &response->message);
                for (int i = 0; i < len; i++) {
                    AddSintToMessage(g_vendor_data.description[i], &response->message);
                }
            }
            break;
        case 4:  /* Timestamp (UDINT) - simulated */
            AddDintToMessage(1703687400, &response->message);  /* Unix timestamp */
            break;
        case 5:  /* Vendor ID */
            AddIntToMessage(1, &response->message);  /* Rockwell */
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* CIP Security Object (0x5D) - Get Attribute Single */
EipStatus CipSecurityGetAttributeSingle(CipInstance *instance,
                                         CipMessageRouterRequest *request,
                                         CipMessageRouterResponse *response,
                                         const struct sockaddr *originator_address,
                                         const CipSessionHandle encapsulation_session) {
    (void)instance;
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 attr_id = request->request_path.attribute_number;

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* State (USINT) */
            AddSintToMessage(g_cip_security.security_state, &response->message);
            break;
        case 2:  /* Security Profiles Supported (UINT) */
            AddIntToMessage(g_cip_security.security_profiles, &response->message);
            break;
        case 3:  /* Active Security Profile (USINT) */
            AddSintToMessage(g_cip_security.active_profile, &response->message);
            break;
        case 4:  /* Security Targets (array) - placeholder */
            AddIntToMessage(0, &response->message);  /* Empty array */
            break;
        case 5:  /* CIP User Authorization Object Instance (UINT) */
            AddIntToMessage(1, &response->message);  /* Instance 1 */
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* EtherNet/IP Security Object (0x5E) - Get Attribute Single */
EipStatus EipSecurityGetAttributeSingle(CipInstance *instance,
                                         CipMessageRouterRequest *request,
                                         CipMessageRouterResponse *response,
                                         const struct sockaddr *originator_address,
                                         const CipSessionHandle encapsulation_session) {
    (void)instance;
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 attr_id = request->request_path.attribute_number;

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* State (USINT) */
            AddSintToMessage(g_eip_security.state, &response->message);
            break;
        case 2:  /* Capability Flags (USINT) */
            AddSintToMessage(g_eip_security.capability_flags, &response->message);
            break;
        case 3:  /* Allowed Cipher Suites (array) */
            /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (placeholder) */
            AddIntToMessage(2, &response->message);  /* 2 suites */
            AddDintToMessage(0xC02B, &response->message);  /* Suite 1 */
            AddDintToMessage(0xC02F, &response->message);  /* Suite 2 */
            break;
        case 4:  /* Pre-Shared Keys (USINT) */
            AddSintToMessage(g_eip_security.psk_pre_shared_keys, &response->message);
            break;
        case 5:  /* Active PSK Slot (USINT) */
            AddSintToMessage(g_eip_security.active_psk_slot, &response->message);
            break;
        case 6:  /* Trust List Instance (UINT) */
            AddIntToMessage(1, &response->message);  /* Instance 1 */
            break;
        case 7:  /* Certificate Instance (UINT) */
            AddIntToMessage(1, &response->message);  /* Instance 1 */
            break;
        case 8:  /* Pull Model Producer (BOOL) */
            AddSintToMessage(1, &response->message);  /* Enabled */
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* Certificate Management Object (0x5F) - Get Attribute Single */
EipStatus CertMgmtGetAttributeSingle(CipInstance *instance,
                                      CipMessageRouterRequest *request,
                                      CipMessageRouterResponse *response,
                                      const struct sockaddr *originator_address,
                                      const CipSessionHandle encapsulation_session) {
    (void)instance;
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 attr_id = request->request_path.attribute_number;

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* State (USINT) */
            AddSintToMessage(g_cert_mgmt.state, &response->message);
            break;
        case 2:  /* Max Certificates (USINT) */
            AddSintToMessage(g_cert_mgmt.max_certs, &response->message);
            break;
        case 3:  /* Installed Certificates (USINT) */
            AddSintToMessage(g_cert_mgmt.installed_certs, &response->message);
            break;
        case 4:  /* Capability Flags (UINT) */
            AddIntToMessage(0x000F, &response->message);  /* All capabilities */
            break;
        case 5:  /* Certificate Encoding (USINT) - PEM=0, DER=1 */
            AddSintToMessage(1, &response->message);  /* DER */
            break;
        case 6:  /* Device Certificate CN (SHORT_STRING) */
            {
                EipUint16 len = strlen(g_cert_mgmt.device_cert_cn);
                AddIntToMessage(len, &response->message);
                for (int i = 0; i < len; i++) {
                    AddSintToMessage(g_cert_mgmt.device_cert_cn[i], &response->message);
                }
            }
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/* Password Authenticator Object (0x61) - Get Attribute Single */
EipStatus PasswordAuthGetAttributeSingle(CipInstance *instance,
                                          CipMessageRouterRequest *request,
                                          CipMessageRouterResponse *response,
                                          const struct sockaddr *originator_address,
                                          const CipSessionHandle encapsulation_session) {
    (void)instance;
    (void)originator_address;
    (void)encapsulation_session;

    EipUint16 attr_id = request->request_path.attribute_number;

    response->general_status = kCipErrorSuccess;
    response->size_of_additional_status = 0;

    switch (attr_id) {
        case 1:  /* State (USINT) */
            AddSintToMessage(g_password_auth.state, &response->message);
            break;
        case 2:  /* Password Configured (BOOL) */
            AddSintToMessage(g_password_auth.password_configured, &response->message);
            break;
        case 3:  /* Max Password Length (USINT) */
            AddSintToMessage(g_password_auth.max_password_len, &response->message);
            break;
        case 4:  /* Min Password Length (USINT) */
            AddSintToMessage(g_password_auth.min_password_len, &response->message);
            break;
        case 5:  /* Failed Attempts (UDINT) */
            AddDintToMessage(0, &response->message);  /* No failures */
            break;
        case 6:  /* Lockout Time (UDINT) - seconds */
            AddDintToMessage(300, &response->message);  /* 5 minutes */
            break;
        default:
            response->general_status = kCipErrorAttributeNotSupported;
            break;
    }

    return kEipStatusOkSend;
}

/*******************************************************************************
 * Application Initialization
 ******************************************************************************/
EipStatus ApplicationInitialization(void) {
    OPENER_TRACE_INFO("=== OIDA Custom OpENer Application ===\n");

    /* Create Assembly Object instances */
    CreateAssemblyObject(ASSEMBLY_INPUT_1, g_input_data_1, sizeof(g_input_data_1));
    CreateAssemblyObject(ASSEMBLY_INPUT_2, g_input_data_2, sizeof(g_input_data_2));
    CreateAssemblyObject(ASSEMBLY_OUTPUT_1, g_output_data_1, sizeof(g_output_data_1));
    CreateAssemblyObject(ASSEMBLY_OUTPUT_2, g_output_data_2, sizeof(g_output_data_2));
    CreateAssemblyObject(ASSEMBLY_CONFIG, g_config_data, sizeof(g_config_data));
    CreateAssemblyObject(ASSEMBLY_HEARTBEAT_IN, NULL, 0);
    CreateAssemblyObject(ASSEMBLY_HEARTBEAT_LO, NULL, 0);
    CreateAssemblyObject(ASSEMBLY_EXPLICIT, g_explicit_data, sizeof(g_explicit_data));

    OPENER_TRACE_INFO("Created 8 Assembly instances\n");

    /* Configure connection points */
    ConfigureExclusiveOwnerConnectionPoint(0, ASSEMBLY_OUTPUT_1,
                                           ASSEMBLY_INPUT_1, ASSEMBLY_CONFIG);
    ConfigureExclusiveOwnerConnectionPoint(1, ASSEMBLY_OUTPUT_2,
                                           ASSEMBLY_INPUT_2, ASSEMBLY_CONFIG);
    ConfigureInputOnlyConnectionPoint(0, ASSEMBLY_HEARTBEAT_IN,
                                      ASSEMBLY_INPUT_1, ASSEMBLY_CONFIG);
    ConfigureListenOnlyConnectionPoint(0, ASSEMBLY_HEARTBEAT_LO,
                                       ASSEMBLY_INPUT_1, ASSEMBLY_CONFIG);

    /* Create custom CIP objects */
    CreateParameterObject();
    CreateFileObject();
    CreatePortObject();
    CreateVendorSpecificObject();

    /* Create CIP Security objects */
    CreateCipSecurityObject();
    CreateEipSecurityObject();
    CreateCertMgmtObject();
    CreatePasswordAuthObject();

    OPENER_TRACE_INFO("Created CIP Security objects (0x5D, 0x5E, 0x5F, 0x61)\n");

    /* Initialize some test data in assemblies */
    memset(g_input_data_1, 0xAA, sizeof(g_input_data_1));
    memset(g_input_data_2, 0xBB, sizeof(g_input_data_2));

    /* Register NV data callbacks */
    InsertGetSetCallback(GetCipClass(kCipQoSClassCode), NvQosSetCallback,
                         kNvDataFunc);
    InsertGetSetCallback(GetCipClass(kCipTcpIpInterfaceClassCode),
                         NvTcpipSetCallback, kNvDataFunc);

    OPENER_TRACE_INFO("Custom application initialized\n");

    return kEipStatusOk;
}

/*******************************************************************************
 * Runtime Callbacks
 ******************************************************************************/
void HandleApplication(void) {
    /* Periodic application updates could go here */
    /* For example, updating sensor data in assemblies */
}

void CheckIoConnectionEvent(unsigned int output_assembly_id,
                            unsigned int input_assembly_id,
                            IoConnectionEvent io_connection_event) {
    (void)output_assembly_id;
    (void)input_assembly_id;

    OPENER_TRACE_INFO("I/O Connection Event: %d\n", io_connection_event);
}

EipStatus AfterAssemblyDataReceived(CipInstance *instance) {
    /* Mirror output to input for testing */
    switch (instance->instance_number) {
        case ASSEMBLY_OUTPUT_1:
            memcpy(g_input_data_1, g_output_data_1, sizeof(g_input_data_1));
            break;
        case ASSEMBLY_OUTPUT_2:
            memcpy(g_input_data_2, g_output_data_2, sizeof(g_input_data_2));
            break;
    }
    return kEipStatusOk;
}

EipBool8 BeforeAssemblyDataSend(CipInstance *instance) {
    (void)instance;
    return true;
}

EipStatus ResetDevice(void) {
    CloseAllConnections();
    CipQosUpdateUsedSetQosValues();
    return kEipStatusOk;
}

EipStatus ResetDeviceToInitialConfiguration(void) {
    g_tcpip.encapsulation_inactivity_timeout = 120;
    CipQosResetAttributesToDefaultValues();
    ResetDevice();
    return kEipStatusOk;
}

void *CipCalloc(size_t number_of_elements, size_t size_of_element) {
    return calloc(number_of_elements, size_of_element);
}

void CipFree(void *data) {
    free(data);
}

void RunIdleChanged(EipUint32 run_idle_value) {
    OPENER_TRACE_INFO("Run/Idle: %d\n", run_idle_value);
    if ((0x0001 & run_idle_value) == 1) {
        CipIdentitySetExtendedDeviceStatus(kAtLeastOneIoConnectionInRunMode);
    } else {
        CipIdentitySetExtendedDeviceStatus(
            kAtLeastOneIoConnectionEstablishedAllInIdleMode);
    }
}
