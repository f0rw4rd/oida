/**
 * Vulnerable Modbus TCP Server - CVE-2024-10918 Simulation
 *
 * This server intentionally contains a stack-based buffer overflow vulnerability
 * that mimics CVE-2024-10918 in libmodbus v3.1.10 for security testing purposes.
 *
 * CVE-2024-10918: Stack-based Buffer Overflow in modbus_reply()
 * Root Cause: When handling certain function codes (FC 0x05 Write Single Coil,
 *             FC 0x06 Write Single Register), the server performs:
 *                 memcpy(rsp, req, req_length);
 *             where rsp is a stack-allocated buffer (~260 bytes) and req_length
 *             is taken from the MBAP Length field without proper validation.
 *
 * Trigger: Send a valid Modbus request (e.g., FC 0x05 or FC 0x06) but manipulate
 *          the MBAP Length field to be larger than the actual request (e.g., 300+).
 *          The server copies req_length bytes to the stack buffer -> overflow.
 *
 * Expected request lengths:
 *   FC 0x05 (Write Single Coil):     12 bytes total (7 MBAP + 5 PDU)
 *   FC 0x06 (Write Single Register): 12 bytes total (7 MBAP + 5 PDU)
 *
 * POC: Send FC 0x05 with MBAP Length = 0x0200 (512 bytes)
 *      Header: 00 01 00 00 02 00 01 05 00 64 ff 00 [+ padding to 512 bytes]
 *
 * References:
 * - https://nvd.nist.gov/vuln/detail/CVE-2024-10918
 * - https://github.com/stephane/libmodbus/issues/xxx (if public)
 *
 * FOR SECURITY TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#define PORT 5022
#define RECV_BUFFER_SIZE 1024  /* Large receive buffer to accept oversized requests */

/* Modbus Function Codes */
#define MODBUS_FC_READ_COILS                 0x01
#define MODBUS_FC_READ_DISCRETE_INPUTS       0x02
#define MODBUS_FC_READ_HOLDING_REGISTERS     0x03
#define MODBUS_FC_READ_INPUT_REGISTERS       0x04
#define MODBUS_FC_WRITE_SINGLE_COIL          0x05  /* Vulnerable */
#define MODBUS_FC_WRITE_SINGLE_REGISTER      0x06  /* Vulnerable */
#define MODBUS_FC_WRITE_MULTIPLE_COILS       0x0F
#define MODBUS_FC_WRITE_MULTIPLE_REGISTERS   0x10

/* Modbus Exception Codes */
#define MODBUS_EXCEPTION_ILLEGAL_FUNCTION    0x01
#define MODBUS_EXCEPTION_ILLEGAL_ADDRESS     0x02
#define MODBUS_EXCEPTION_ILLEGAL_VALUE       0x03

/* Simulated register/coil storage */
#define NB_COILS      1000
#define NB_REGISTERS  1000

uint8_t coils[NB_COILS];
uint16_t registers[NB_REGISTERS];

/* Stack canary to detect overflow - placed in global for checking */
#define STACK_CANARY_VALUE 0xDEADBEEFCAFEBABE

void send_exception(int client_fd, uint8_t *req, uint8_t exception_code) {
    uint8_t response[9];
    /* Copy transaction ID and protocol ID */
    memcpy(response, req, 4);
    response[4] = 0x00;
    response[5] = 0x03;  /* Length */
    response[6] = req[6]; /* Unit ID */
    response[7] = req[7] | 0x80;  /* Function code with error flag */
    response[8] = exception_code;
    send(client_fd, response, 9, 0);
}

/**
 * VULNERABLE: Handle FC 0x05 - Write Single Coil
 *
 * Request format:
 *   [MBAP Header 7 bytes: TxID(2) + ProtoID(2) + Length(2) + UnitID(1)]
 *   [FC 1 byte = 0x05]
 *   [Coil Address 2 bytes]
 *   [Value 2 bytes: 0xFF00 = ON, 0x0000 = OFF]
 *
 * Normal request length: 12 bytes total (MBAP Length field = 6)
 *
 * VULNERABILITY: The response is built by copying the request to a stack buffer.
 * If MBAP Length is manipulated to be larger than the actual PDU, the memcpy
 * reads beyond the request and/or overwrites the stack.
 *
 * Vulnerable pattern from libmodbus v3.1.10:
 *   uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];  // 260 bytes on stack
 *   memcpy(rsp, req, req_length);  // req_length from MBAP header, not validated!
 */
int handle_write_single_coil(int client_fd, uint8_t *req, int req_length) {
    /*
     * VULNERABLE STACK LAYOUT
     * We use a struct to ensure predictable memory layout for overflow detection.
     * In libmodbus, the buffer is MODBUS_TCP_MAX_ADU_LENGTH (260 bytes).
     */
    struct {
        uint8_t rsp[256];           /* Vulnerable buffer - will overflow */
        volatile uint64_t canary1;  /* First canary - detects 1-8 byte overflow */
        volatile uint64_t canary2;  /* Second canary - detects 9-16 byte overflow */
        volatile uint64_t canary3;  /* Third canary - detects larger overflow */
    } stack_frame;

    /* Initialize canaries */
    stack_frame.canary1 = STACK_CANARY_VALUE;
    stack_frame.canary2 = STACK_CANARY_VALUE;
    stack_frame.canary3 = STACK_CANARY_VALUE;

    uint16_t address = (req[8] << 8) | req[9];
    uint16_t value = (req[10] << 8) | req[11];

    printf("[*] FC 0x05 Write Single Coil\n");
    printf("    Address: %u\n", address);
    printf("    Value: 0x%04x (%s)\n", value, value == 0xFF00 ? "ON" : "OFF");
    printf("    MBAP req_length: %d bytes (expected: 6 for normal request)\n", req_length);
    printf("    Stack buffer size: 256 bytes\n");

    if (req_length > 256) {
        printf("[!] WARNING: req_length (%d) > stack buffer (256) - OVERFLOW IMMINENT!\n", req_length);
    }

    /*
     * VULNERABILITY: CVE-2024-10918
     *
     * The req_length comes from MBAP header Length field + Unit ID.
     * For FC 0x05, normal req_length is 6 bytes (Unit ID + FC + Addr + Value).
     *
     * libmodbus copies this many bytes WITHOUT validating it matches expected PDU size:
     *   memcpy(rsp, req, req_length);
     *
     * If attacker sets MBAP Length to 300, req_length becomes ~300, and we overflow rsp[256].
     *
     * NOTE: We copy from offset 6 (after MBAP header but including Unit ID) to simulate
     * the actual vulnerable code path in modbus_reply().
     */
    printf("[*] Performing vulnerable memcpy(rsp, req+6, %d)\n", req_length);
    printf("[*] Stack layout: rsp=%p, canary1=%p (offset +256)\n",
           (void*)stack_frame.rsp, (void*)&stack_frame.canary1);

    /* INTENTIONALLY VULNERABLE: memcpy without bounds check */
    memcpy(stack_frame.rsp, req + 6, req_length);

    /* Check if stack was corrupted - check all canaries */
    if (stack_frame.canary1 != STACK_CANARY_VALUE ||
        stack_frame.canary2 != STACK_CANARY_VALUE ||
        stack_frame.canary3 != STACK_CANARY_VALUE) {
        printf("\n");
        printf("[CRASH] ========================================\n");
        printf("[CRASH] STACK BUFFER OVERFLOW DETECTED!\n");
        printf("[CRASH] ========================================\n");
        printf("[CRASH] Canary values after overflow:\n");
        printf("[CRASH]   canary1: 0x%016lx %s\n", stack_frame.canary1,
               stack_frame.canary1 != STACK_CANARY_VALUE ? "(CORRUPTED!)" : "(OK)");
        printf("[CRASH]   canary2: 0x%016lx %s\n", stack_frame.canary2,
               stack_frame.canary2 != STACK_CANARY_VALUE ? "(CORRUPTED!)" : "(OK)");
        printf("[CRASH]   canary3: 0x%016lx %s\n", stack_frame.canary3,
               stack_frame.canary3 != STACK_CANARY_VALUE ? "(CORRUPTED!)" : "(OK)");
        printf("[CRASH] Expected: 0x%016lx\n", STACK_CANARY_VALUE);
        printf("[CRASH] Buffer overflow: %d bytes copied to 256-byte buffer\n", req_length);
        printf("[CRASH] Overflow amount: %d bytes\n", req_length - 256);
        printf("[CRASH] CVE-2024-10918 triggered successfully!\n");
        printf("[CRASH] ========================================\n");
        fflush(stdout);
        abort();
    }

    /* Validate coil address */
    if (address >= NB_COILS) {
        printf("[!] Coil address out of bounds: %u >= %d\n", address, NB_COILS);
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    /* Validate coil value */
    if (value != 0xFF00 && value != 0x0000) {
        printf("[!] Invalid coil value: 0x%04x (must be 0xFF00 or 0x0000)\n", value);
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_VALUE);
        return -1;
    }

    /* Set coil value */
    coils[address] = (value == 0xFF00) ? 1 : 0;
    printf("[*] Coil %u set to %s\n", address, coils[address] ? "ON" : "OFF");

    /* Response: echo the request (already in rsp from memcpy above) */
    /* Response is: Unit ID + FC + Address + Value = 6 bytes */
    /* MBAP response header */
    uint8_t mbap[6];
    memcpy(mbap, req, 4);  /* Transaction ID + Protocol ID */
    mbap[4] = 0x00;
    mbap[5] = 0x06;  /* Length: Unit ID(1) + FC(1) + Addr(2) + Value(2) = 6 */

    send(client_fd, mbap, 6, 0);
    send(client_fd, stack_frame.rsp, 6, 0);  /* Unit ID + FC + Address + Value */

    printf("[*] Response sent\n");
    return 0;
}

/**
 * VULNERABLE: Handle FC 0x06 - Write Single Register
 *
 * Same vulnerability as FC 0x05.
 *
 * Request format:
 *   [MBAP Header 7 bytes]
 *   [FC 1 byte = 0x06]
 *   [Register Address 2 bytes]
 *   [Value 2 bytes]
 *
 * Normal request length: 12 bytes total
 */
int handle_write_single_register(int client_fd, uint8_t *req, int req_length) {
    /* VULNERABLE STACK LAYOUT - same as FC 0x05 */
    struct {
        uint8_t rsp[256];
        volatile uint64_t canary1;
        volatile uint64_t canary2;
        volatile uint64_t canary3;
    } stack_frame;

    stack_frame.canary1 = STACK_CANARY_VALUE;
    stack_frame.canary2 = STACK_CANARY_VALUE;
    stack_frame.canary3 = STACK_CANARY_VALUE;

    uint16_t address = (req[8] << 8) | req[9];
    uint16_t value = (req[10] << 8) | req[11];

    printf("[*] FC 0x06 Write Single Register\n");
    printf("    Address: %u\n", address);
    printf("    Value: 0x%04x (%u)\n", value, value);
    printf("    MBAP req_length: %d bytes (expected: 6 for normal request)\n", req_length);
    printf("    Stack buffer size: 256 bytes\n");

    if (req_length > 256) {
        printf("[!] WARNING: req_length (%d) > stack buffer (256) - OVERFLOW IMMINENT!\n", req_length);
    }

    /* INTENTIONALLY VULNERABLE: memcpy without bounds check */
    printf("[*] Performing vulnerable memcpy(rsp, req+6, %d)\n", req_length);
    printf("[*] Stack layout: rsp=%p, canary1=%p (offset +256)\n",
           (void*)stack_frame.rsp, (void*)&stack_frame.canary1);
    memcpy(stack_frame.rsp, req + 6, req_length);

    /* Check for stack corruption */
    if (stack_frame.canary1 != STACK_CANARY_VALUE ||
        stack_frame.canary2 != STACK_CANARY_VALUE ||
        stack_frame.canary3 != STACK_CANARY_VALUE) {
        printf("\n");
        printf("[CRASH] ========================================\n");
        printf("[CRASH] STACK BUFFER OVERFLOW DETECTED!\n");
        printf("[CRASH] ========================================\n");
        printf("[CRASH] Canary values after overflow:\n");
        printf("[CRASH]   canary1: 0x%016lx %s\n", stack_frame.canary1,
               stack_frame.canary1 != STACK_CANARY_VALUE ? "(CORRUPTED!)" : "(OK)");
        printf("[CRASH]   canary2: 0x%016lx %s\n", stack_frame.canary2,
               stack_frame.canary2 != STACK_CANARY_VALUE ? "(CORRUPTED!)" : "(OK)");
        printf("[CRASH]   canary3: 0x%016lx %s\n", stack_frame.canary3,
               stack_frame.canary3 != STACK_CANARY_VALUE ? "(CORRUPTED!)" : "(OK)");
        printf("[CRASH] Expected: 0x%016lx\n", STACK_CANARY_VALUE);
        printf("[CRASH] Buffer overflow: %d bytes copied to 256-byte buffer\n", req_length);
        printf("[CRASH] Overflow amount: %d bytes\n", req_length - 256);
        printf("[CRASH] CVE-2024-10918 triggered successfully!\n");
        printf("[CRASH] ========================================\n");
        fflush(stdout);
        abort();
    }

    /* Validate register address */
    if (address >= NB_REGISTERS) {
        printf("[!] Register address out of bounds: %u >= %d\n", address, NB_REGISTERS);
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    /* Set register value */
    registers[address] = value;
    printf("[*] Register %u set to %u (0x%04x)\n", address, value, value);

    /* Response: echo the request */
    uint8_t mbap[6];
    memcpy(mbap, req, 4);
    mbap[4] = 0x00;
    mbap[5] = 0x06;

    send(client_fd, mbap, 6, 0);
    send(client_fd, stack_frame.rsp, 6, 0);

    printf("[*] Response sent\n");
    return 0;
}

int handle_read_holding_registers(int client_fd, uint8_t *req) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t quantity = (req[10] << 8) | req[11];

    printf("[*] FC 0x03 Read Holding Registers: address=%u, quantity=%u\n",
           address, quantity);

    if (address + quantity > NB_REGISTERS) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    if (quantity == 0 || quantity > 125) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_VALUE);
        return -1;
    }

    uint8_t response[256 + 9];
    memcpy(response, req, 4);
    response[4] = 0x00;
    response[5] = 3 + quantity * 2;
    response[6] = req[6];
    response[7] = MODBUS_FC_READ_HOLDING_REGISTERS;
    response[8] = quantity * 2;

    for (int i = 0; i < quantity; i++) {
        response[9 + i*2] = registers[address + i] >> 8;
        response[9 + i*2 + 1] = registers[address + i] & 0xFF;
    }

    send(client_fd, response, 9 + quantity * 2, 0);
    return 0;
}

int handle_read_coils(int client_fd, uint8_t *req) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t quantity = (req[10] << 8) | req[11];

    printf("[*] FC 0x01 Read Coils: address=%u, quantity=%u\n", address, quantity);

    if (address + quantity > NB_COILS) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    if (quantity == 0 || quantity > 2000) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_VALUE);
        return -1;
    }

    uint8_t byte_count = (quantity + 7) / 8;
    uint8_t response[256 + 9];
    memcpy(response, req, 4);
    response[4] = 0x00;
    response[5] = 3 + byte_count;
    response[6] = req[6];
    response[7] = MODBUS_FC_READ_COILS;
    response[8] = byte_count;

    memset(response + 9, 0, byte_count);
    for (int i = 0; i < quantity; i++) {
        if (coils[address + i]) {
            response[9 + i/8] |= (1 << (i % 8));
        }
    }

    send(client_fd, response, 9 + byte_count, 0);
    return 0;
}

void handle_client(int client_fd) {
    uint8_t buffer[RECV_BUFFER_SIZE];
    ssize_t n;

    printf("[*] Client connected\n");

    while (1) {
        /* Read MBAP header (7 bytes) */
        n = recv(client_fd, buffer, 7, MSG_WAITALL);
        if (n <= 0) {
            printf("[*] Client disconnected\n");
            break;
        }

        if (n < 7) {
            printf("[!] Incomplete MBAP header (%zd bytes)\n", n);
            continue;
        }

        uint16_t transaction_id = (buffer[0] << 8) | buffer[1];
        uint16_t protocol_id = (buffer[2] << 8) | buffer[3];
        uint16_t length = (buffer[4] << 8) | buffer[5];
        uint8_t unit_id = buffer[6];

        printf("\n[*] MBAP Header received:\n");
        printf("    Transaction ID: %u\n", transaction_id);
        printf("    Protocol ID: %u\n", protocol_id);
        printf("    Length: %u (this is the vulnerable field!)\n", length);
        printf("    Unit ID: %u\n", unit_id);

        /* Validate protocol ID (should be 0 for Modbus TCP) */
        if (protocol_id != 0) {
            printf("[!] Invalid protocol ID: %u (expected 0)\n", protocol_id);
            continue;
        }

        /* Read rest of PDU based on MBAP Length field */
        /* Length includes Unit ID (1 byte) + PDU, so PDU length is length - 1 */
        int pdu_length = length - 1;

        if (pdu_length < 1) {
            printf("[!] Invalid PDU length: %d\n", pdu_length);
            continue;
        }

        /* Allow oversized requests for vulnerability testing */
        if (pdu_length > RECV_BUFFER_SIZE - 7) {
            printf("[!] PDU too large for buffer: %d > %d\n", pdu_length, RECV_BUFFER_SIZE - 7);
            pdu_length = RECV_BUFFER_SIZE - 7;
        }

        n = recv(client_fd, buffer + 7, pdu_length, MSG_WAITALL);
        if (n <= 0) {
            printf("[*] Client disconnected during PDU read\n");
            break;
        }

        uint8_t function_code = buffer[7];
        printf("[*] Function code: 0x%02x, PDU length: %d\n", function_code, pdu_length);

        /*
         * The vulnerable req_length passed to handlers is based on MBAP Length.
         * This is the value that will be used in the memcpy.
         */
        int req_length = length;  /* MBAP Length field value */

        switch (function_code) {
            case MODBUS_FC_READ_COILS:
                handle_read_coils(client_fd, buffer);
                break;

            case MODBUS_FC_READ_HOLDING_REGISTERS:
                handle_read_holding_registers(client_fd, buffer);
                break;

            case MODBUS_FC_WRITE_SINGLE_COIL:
                /* VULNERABLE FUNCTION */
                handle_write_single_coil(client_fd, buffer, req_length);
                break;

            case MODBUS_FC_WRITE_SINGLE_REGISTER:
                /* VULNERABLE FUNCTION */
                handle_write_single_register(client_fd, buffer, req_length);
                break;

            default:
                printf("[!] Unsupported function code: 0x%02x\n", function_code);
                send_exception(client_fd, buffer, MODBUS_EXCEPTION_ILLEGAL_FUNCTION);
                break;
        }
    }

    close(client_fd);
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    int port = PORT;

    /* Disable stdout buffering for crash visibility */
    setbuf(stdout, NULL);

    /* Allow port override */
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    char *env_port = getenv("MODBUS_PORT");
    if (env_port) {
        port = atoi(env_port);
    }

    /* Initialize simulated data */
    memset(coils, 0, sizeof(coils));
    for (int i = 0; i < NB_REGISTERS; i++) {
        registers[i] = i * 10;
    }

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    printf("=====================================================\n");
    printf("  VULNERABLE Modbus TCP Server - CVE-2024-10918\n");
    printf("=====================================================\n");
    printf("  Port: %d\n", port);
    printf("  Vulnerability: Stack buffer overflow in memcpy\n");
    printf("                 when handling FC 0x05 / FC 0x06\n");
    printf("  Root Cause: MBAP Length field not validated\n");
    printf("              against expected PDU size\n");
    printf("  Stack buffer: 256 bytes\n");
    printf("  Trigger: Set MBAP Length > 256 with FC 0x05/0x06\n");
    printf("=====================================================\n");
    printf("  Example trigger (FC 0x05 with Length=512):\n");
    printf("  echo -ne '\\x00\\x01\\x00\\x00\\x02\\x00\\x01\\x05");
    printf("\\x00\\x64\\xff\\x00' | nc localhost %d\n", port);
    printf("  (Then send 500+ bytes of padding)\n");
    printf("=====================================================\n");
    printf("  Supported function codes:\n");
    printf("    0x01 - Read Coils\n");
    printf("    0x03 - Read Holding Registers\n");
    printf("    0x05 - Write Single Coil (VULNERABLE)\n");
    printf("    0x06 - Write Single Register (VULNERABLE)\n");
    printf("=====================================================\n");
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("=====================================================\n\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        handle_client(client_fd);
    }

    return 0;
}
