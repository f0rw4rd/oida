/**
 * Vulnerable Modbus TCP Server - CVE-2023-26793 Simulation
 *
 * Vulnerability: Heap buffer overflow in read_io_status()
 * Root Cause: When parsing FC 0x01/0x02 responses, the byte count field
 *             is not validated against the allocated buffer size.
 *
 * Trigger: Send FC 0x01 Read Coils with quantity that causes response
 *          byte count to exceed internal buffer allocation.
 *
 * FOR SECURITY TESTING ONLY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>

#define PORT 5023
#define COIL_BUFFER_SIZE 32  /* Small buffer for overflow */

uint8_t coils[2000];  /* Actual coil storage */

#define CANARY_VALUE 0xDEADBEEFCAFEBABE

struct {
    uint8_t response_buffer[COIL_BUFFER_SIZE];
    volatile uint64_t canary;
} heap_data;

void send_exception(int fd, uint8_t *req, uint8_t code) {
    uint8_t resp[9];
    memcpy(resp, req, 4);
    resp[4] = 0; resp[5] = 3;
    resp[6] = req[6];
    resp[7] = req[7] | 0x80;
    resp[8] = code;
    send(fd, resp, 9, 0);
}

int handle_read_coils(int fd, uint8_t *req) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t quantity = (req[10] << 8) | req[11];
    uint8_t byte_count = (quantity + 7) / 8;

    printf("[*] FC 0x01 Read Coils: addr=%u, qty=%u, bytes=%u\n",
           address, quantity, byte_count);
    printf("[*] Response buffer size: %d bytes\n", COIL_BUFFER_SIZE);

    if (address + quantity > 2000) {
        send_exception(fd, req, 0x02);
        return -1;
    }

    /*
     * VULNERABILITY: CVE-2023-26793
     * byte_count is derived from quantity without checking against buffer size.
     * If quantity > COIL_BUFFER_SIZE * 8, we overflow response_buffer.
     */
    if (byte_count > COIL_BUFFER_SIZE) {
        printf("[!] WARNING: byte_count (%u) > buffer (%d) - OVERFLOW!\n",
               byte_count, COIL_BUFFER_SIZE);
    }

    /* Pack coils into response buffer - OVERFLOW HAPPENS HERE */
    memset(heap_data.response_buffer, 0, byte_count);  /* Overflow! */
    for (int i = 0; i < quantity; i++) {
        if (coils[address + i]) {
            heap_data.response_buffer[i / 8] |= (1 << (i % 8));
        }
    }

    /* Check canary */
    if (heap_data.canary != CANARY_VALUE) {
        printf("[CRASH] Heap buffer overflow detected!\n");
        printf("[CRASH] Canary: 0x%lx (expected 0x%lx)\n",
               heap_data.canary, CANARY_VALUE);
        printf("[CRASH] CVE-2023-26793 triggered!\n");
        fflush(stdout);
        abort();
    }

    /* Build response */
    uint8_t resp[256];
    memcpy(resp, req, 4);
    resp[4] = 0;
    resp[5] = 3 + byte_count;
    resp[6] = req[6];
    resp[7] = 0x01;
    resp[8] = byte_count;
    memcpy(resp + 9, heap_data.response_buffer, byte_count);

    send(fd, resp, 9 + byte_count, 0);
    return 0;
}

void handle_client(int fd) {
    uint8_t buf[512];
    printf("[*] Client connected\n");

    while (1) {
        ssize_t n = recv(fd, buf, 7, MSG_WAITALL);
        if (n <= 0) break;

        uint16_t length = (buf[4] << 8) | buf[5];
        if (length > 1 && length < 500) {
            recv(fd, buf + 7, length - 1, MSG_WAITALL);
        }

        uint8_t fc = buf[7];
        if (fc == 0x01 || fc == 0x02) {
            handle_read_coils(fd, buf);
        } else {
            send_exception(fd, buf, 0x01);
        }
    }
    close(fd);
    printf("[*] Client disconnected\n");
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr = {0};
    int opt = 1;

    setbuf(stdout, NULL);
    heap_data.canary = CANARY_VALUE;
    memset(coils, 0, sizeof(coils));

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    printf("===========================================\n");
    printf("  VULNERABLE Modbus Server - CVE-2023-26793\n");
    printf("  Port: %d\n", PORT);
    printf("  Vulnerability: Heap overflow in read_io_status\n");
    printf("  Trigger: FC 0x01 with quantity > %d coils\n", COIL_BUFFER_SIZE * 8);
    printf("===========================================\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) handle_client(client_fd);
    }
    return 0;
}
