/**
 * Vulnerable Modbus TCP Server - CVE-2022-0367 Simulation
 *
 * This server intentionally contains a heap-based buffer overflow vulnerability
 * that mimics CVE-2022-0367 in libmodbus for security testing purposes.
 *
 * CVE-2022-0367: Heap-based Buffer Overflow in modbus_reply()
 * Root Cause: Copy-paste error in validation for FC 0x17 (Read/Write Multiple Registers)
 *             The write address offset is not properly validated, only the read address.
 *
 * Original vulnerable code pattern:
 *   } else if (mapping_address < 0 ||
 *       (mapping_address + nb) > mb_mapping->nb_registers ||
 *       mapping_address < 0 ||  // BUG: should be mapping_address_write < 0
 *       (mapping_address_write + nb_write) > mb_mapping->nb_registers) {
 *
 * Trigger: Send FC 0x17 with valid read address but out-of-bounds write address
 *
 * POC Payload (base64): A90AAAAN/xcBYgABAIQAAQLXEQ==
 *
 * References:
 * - https://github.com/stephane/libmodbus/issues/614
 * - https://github.com/stephane/libmodbus/commit/b4ef4c17d618eba0adccc4c7d9e9a1ef809fc9b6
 * - https://nvd.nist.gov/vuln/detail/CVE-2022-0367
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
#include <signal.h>
#include <stdint.h>

#define PORT 5021
#define BUFFER_SIZE 512
#define NB_REGISTERS 100  /* Small register space to trigger overflow */

/* Modbus Function Codes */
#define MODBUS_FC_READ_COILS                 0x01
#define MODBUS_FC_READ_HOLDING_REGISTERS     0x03
#define MODBUS_FC_WRITE_SINGLE_COIL          0x05
#define MODBUS_FC_WRITE_SINGLE_REGISTER      0x06
#define MODBUS_FC_WRITE_MULTIPLE_COILS       0x0F
#define MODBUS_FC_WRITE_MULTIPLE_REGISTERS   0x10
#define MODBUS_FC_READ_WRITE_REGISTERS       0x17  /* Vulnerable function */

/* Modbus Exception Codes */
#define MODBUS_EXCEPTION_ILLEGAL_FUNCTION    0x01
#define MODBUS_EXCEPTION_ILLEGAL_ADDRESS     0x02
#define MODBUS_EXCEPTION_ILLEGAL_VALUE       0x03

/* Simulated register mapping (heap allocated) */
typedef struct {
    uint16_t *tab_registers;
    int nb_registers;
    /* Add canary value to detect overflow */
    uint64_t canary;
    /* Pointer that will be corrupted by overflow */
    void *vulnerable_ptr;
} modbus_mapping_t;

modbus_mapping_t *mapping = NULL;

/* Additional heap objects to make overflow more impactful */
typedef struct {
    uint64_t magic;
    char data[64];
    void (*callback)(void);  /* Function pointer - overflow target */
} heap_object_t;

heap_object_t *adjacent_object = NULL;

#define CANARY_VALUE 0xDEADBEEFCAFEBABE

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
 * Handle FC 0x17 - Read/Write Multiple Registers
 *
 * Request format:
 *   [MBAP Header 7 bytes]
 *   [FC 1 byte = 0x17]
 *   [Read Start Address 2 bytes]
 *   [Read Quantity 2 bytes]
 *   [Write Start Address 2 bytes]
 *   [Write Quantity 2 bytes]
 *   [Write Byte Count 1 byte]
 *   [Write Values N bytes]
 *
 * VULNERABILITY: The write address validation is missing (copy-paste error)
 * This allows writing to arbitrary heap locations beyond tab_registers
 */
int handle_read_write_registers(int client_fd, uint8_t *req, int req_len) {
    /* Parse request */
    uint16_t read_address = (req[8] << 8) | req[9];
    uint16_t read_quantity = (req[10] << 8) | req[11];
    uint16_t write_address = (req[12] << 8) | req[13];
    uint16_t write_quantity = (req[14] << 8) | req[15];
    uint8_t write_byte_count = req[16];

    printf("[*] FC 0x17 Read/Write Multiple Registers\n");
    printf("    Read:  address=%u, quantity=%u\n", read_address, read_quantity);
    printf("    Write: address=%u, quantity=%u, bytes=%u\n",
           write_address, write_quantity, write_byte_count);

    /* Validate read parameters (this check is correct) */
    if (read_address < 0 ||
        (read_address + read_quantity) > mapping->nb_registers) {
        printf("[!] Read address out of bounds\n");
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    /*
     * VULNERABILITY: CVE-2022-0367 copy-paste error simulation
     *
     * BUGGY CODE - Notice we check read_address TWICE instead of write_address:
     *
     *   if (read_address < 0 ||    <-- Correct
     *       (read_address + read_quantity) > mapping->nb_registers ||  <-- Correct
     *       read_address < 0 ||    <-- BUG! Should be: write_address < 0
     *       (write_address + write_quantity) > mapping->nb_registers)  <-- Never reached!
     *
     * The third condition (read_address < 0) is always false at this point
     * because we already validated it above. This means the fourth condition
     * (write bounds check) is effectively skipped!
     *
     * Fixed code would be:
     *   if (write_address < 0 ||
     *       (write_address + write_quantity) > mapping->nb_registers)
     */

    /* INTENTIONALLY VULNERABLE: Missing write address validation */
    /* The check below mimics the CVE-2022-0367 bug */
    if (read_address < 0 ||  /* BUG: should be write_address < 0 */
        0) {  /* This condition is never true, so write bounds are never checked! */
        printf("[!] Write address out of bounds (this never triggers due to bug)\n");
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    /* Verify write byte count matches quantity */
    if (write_byte_count != write_quantity * 2) {
        printf("[!] Write byte count mismatch\n");
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_VALUE);
        return -1;
    }

    /*
     * HEAP OVERFLOW HAPPENS HERE!
     *
     * If write_address >= nb_registers, we write beyond the allocated buffer.
     * Since tab_registers is heap-allocated, this corrupts heap metadata.
     *
     * Example: nb_registers=100, write_address=200, write_quantity=10
     * This writes to tab_registers[200] through tab_registers[209]
     * which is way beyond the allocated 100 * sizeof(uint16_t) bytes.
     */
    printf("[*] Writing %u registers starting at address %u (buffer has %d)\n",
           write_quantity, write_address, mapping->nb_registers);

    for (int i = 0; i < write_quantity; i++) {
        uint16_t value = (req[17 + i*2] << 8) | req[17 + i*2 + 1];
        /* OVERFLOW: No bounds check on write_address + i */
        mapping->tab_registers[write_address + i] = value;
        printf("    [%u] = 0x%04x\n", write_address + i, value);
    }

    /* Build response with read data */
    uint8_t response[256];
    memcpy(response, req, 4);  /* Transaction ID, Protocol ID */
    response[4] = 0x00;
    response[5] = 3 + read_quantity * 2;  /* Length */
    response[6] = req[6];  /* Unit ID */
    response[7] = MODBUS_FC_READ_WRITE_REGISTERS;
    response[8] = read_quantity * 2;  /* Byte count */

    for (int i = 0; i < read_quantity; i++) {
        response[9 + i*2] = mapping->tab_registers[read_address + i] >> 8;
        response[9 + i*2 + 1] = mapping->tab_registers[read_address + i] & 0xFF;
    }

    int resp_len = 9 + read_quantity * 2;
    send(client_fd, response, resp_len, 0);

    printf("[*] Response sent (%d bytes)\n", resp_len);

    /*
     * CRASH DETECTION: Check if heap was corrupted
     * In real libmodbus, this would be detected by malloc/free operations.
     * Here we explicitly check to make the demo more reliable.
     */
    if (mapping->canary != CANARY_VALUE) {
        printf("[CRASH] Canary corrupted! Expected 0x%lx, got 0x%lx\n",
               CANARY_VALUE, mapping->canary);
        printf("[CRASH] Heap corruption detected - simulating crash\n");
        fflush(stdout);
        /* Trigger actual crash for fuzzer detection */
        abort();
    }

    if (adjacent_object && adjacent_object->magic != 0x1234567890ABCDEF) {
        printf("[CRASH] Adjacent heap object corrupted! magic=0x%lx\n",
               adjacent_object->magic);
        printf("[CRASH] Heap overflow affected adjacent allocation\n");
        fflush(stdout);
        /* Try to call corrupted function pointer (will crash if corrupted) */
        if (adjacent_object->callback != NULL) {
            printf("[CRASH] Calling corrupted function pointer...\n");
            fflush(stdout);
            adjacent_object->callback();  /* This will crash if pointer is corrupted */
        }
        abort();
    }

    return 0;
}

int handle_read_holding_registers(int client_fd, uint8_t *req) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t quantity = (req[10] << 8) | req[11];

    printf("[*] FC 0x03 Read Holding Registers: address=%u, quantity=%u\n",
           address, quantity);

    if (address + quantity > mapping->nb_registers) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    uint8_t response[256];
    memcpy(response, req, 4);
    response[4] = 0x00;
    response[5] = 3 + quantity * 2;
    response[6] = req[6];
    response[7] = MODBUS_FC_READ_HOLDING_REGISTERS;
    response[8] = quantity * 2;

    for (int i = 0; i < quantity; i++) {
        response[9 + i*2] = mapping->tab_registers[address + i] >> 8;
        response[9 + i*2 + 1] = mapping->tab_registers[address + i] & 0xFF;
    }

    send(client_fd, response, 9 + quantity * 2, 0);
    return 0;
}

int handle_write_single_register(int client_fd, uint8_t *req) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t value = (req[10] << 8) | req[11];

    printf("[*] FC 0x06 Write Single Register: address=%u, value=0x%04x\n",
           address, value);

    if (address >= mapping->nb_registers) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    mapping->tab_registers[address] = value;

    /* Echo request as response */
    send(client_fd, req, 12, 0);
    return 0;
}

int handle_write_multiple_registers(int client_fd, uint8_t *req) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t quantity = (req[10] << 8) | req[11];
    uint8_t byte_count = req[12];

    printf("[*] FC 0x10 Write Multiple Registers: address=%u, quantity=%u\n",
           address, quantity);

    if (address + quantity > mapping->nb_registers) {
        send_exception(client_fd, req, MODBUS_EXCEPTION_ILLEGAL_ADDRESS);
        return -1;
    }

    for (int i = 0; i < quantity; i++) {
        mapping->tab_registers[address + i] = (req[13 + i*2] << 8) | req[13 + i*2 + 1];
    }

    uint8_t response[12];
    memcpy(response, req, 6);
    response[6] = req[6];
    response[7] = MODBUS_FC_WRITE_MULTIPLE_REGISTERS;
    response[8] = address >> 8;
    response[9] = address & 0xFF;
    response[10] = quantity >> 8;
    response[11] = quantity & 0xFF;

    send(client_fd, response, 12, 0);
    return 0;
}

void handle_client(int client_fd) {
    uint8_t buffer[BUFFER_SIZE];
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
            printf("[!] Incomplete MBAP header\n");
            continue;
        }

        uint16_t length = (buffer[4] << 8) | buffer[5];

        /* Read PDU */
        if (length > 1 && length < BUFFER_SIZE - 7) {
            n = recv(client_fd, buffer + 7, length - 1, MSG_WAITALL);
            if (n <= 0) {
                printf("[*] Client disconnected during PDU read\n");
                break;
            }
        }

        uint8_t function_code = buffer[7];
        printf("[*] Received FC 0x%02x, length=%u\n", function_code, length);

        switch (function_code) {
            case MODBUS_FC_READ_COILS:
            case MODBUS_FC_READ_HOLDING_REGISTERS:
                handle_read_holding_registers(client_fd, buffer);
                break;

            case MODBUS_FC_WRITE_SINGLE_COIL:
            case MODBUS_FC_WRITE_SINGLE_REGISTER:
                handle_write_single_register(client_fd, buffer);
                break;

            case MODBUS_FC_WRITE_MULTIPLE_COILS:
            case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
                handle_write_multiple_registers(client_fd, buffer);
                break;

            case MODBUS_FC_READ_WRITE_REGISTERS:
                /* VULNERABLE FUNCTION */
                handle_read_write_registers(client_fd, buffer, 7 + length - 1);
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

    /* Allocate register mapping on heap */
    mapping = (modbus_mapping_t *)malloc(sizeof(modbus_mapping_t));
    mapping->nb_registers = NB_REGISTERS;
    mapping->tab_registers = (uint16_t *)calloc(NB_REGISTERS, sizeof(uint16_t));
    mapping->canary = CANARY_VALUE;
    mapping->vulnerable_ptr = mapping;

    /* Allocate adjacent object immediately after - will be corrupted by overflow */
    adjacent_object = (heap_object_t *)malloc(sizeof(heap_object_t));
    adjacent_object->magic = 0x1234567890ABCDEF;
    adjacent_object->callback = NULL;
    memset(adjacent_object->data, 'X', sizeof(adjacent_object->data));

    /* Initialize with some test data */
    for (int i = 0; i < NB_REGISTERS; i++) {
        mapping->tab_registers[i] = i * 10;
    }

    printf("  Heap layout for crash testing:\n");
    printf("    tab_registers: %p\n", (void*)mapping->tab_registers);
    printf("    adjacent_obj:  %p\n", (void*)adjacent_object);
    printf("    Distance: %ld bytes\n",
           (char*)adjacent_object - (char*)mapping->tab_registers);

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
    printf("  VULNERABLE Modbus TCP Server - CVE-2022-0367\n");
    printf("=====================================================\n");
    printf("  Port: %d\n", port);
    printf("  Register count: %d (heap allocated)\n", NB_REGISTERS);
    printf("  Vulnerability: Missing write address validation\n");
    printf("                 in FC 0x17 (Read/Write Registers)\n");
    printf("  Trigger: Send FC 0x17 with write_address > %d\n", NB_REGISTERS - 1);
    printf("=====================================================\n");
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("=====================================================\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        handle_client(client_fd);
    }

    free(mapping->tab_registers);
    free(mapping);
    return 0;
}
