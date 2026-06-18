/**
 * Vulnerable Modbus TCP Server - CVE-2019-14462 Simulation
 *
 * Vulnerability: Out-of-bounds read in FC 0x0F (Write Multiple Coils)
 * Root Cause: The byte count in the request is not validated against
 *             the quantity field, allowing read beyond request buffer.
 *
 * Trigger: Send FC 0x0F with mismatched byte_count and quantity fields.
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

#define PORT 5024
#define MAX_COILS 1000

uint8_t coils[MAX_COILS];

#define CANARY_VALUE 0xDEADBEEFCAFEBABE

void send_exception(int fd, uint8_t *req, uint8_t code) {
    uint8_t resp[9];
    memcpy(resp, req, 4);
    resp[4] = 0; resp[5] = 3;
    resp[6] = req[6];
    resp[7] = req[7] | 0x80;
    resp[8] = code;
    send(fd, resp, 9, 0);
}

int handle_write_multiple_coils(int fd, uint8_t *req, int req_len) {
    uint16_t address = (req[8] << 8) | req[9];
    uint16_t quantity = (req[10] << 8) | req[11];
    uint8_t byte_count = req[12];
    uint8_t expected_bytes = (quantity + 7) / 8;

    printf("[*] FC 0x0F Write Multiple Coils\n");
    printf("    Address: %u, Quantity: %u\n", address, quantity);
    printf("    Byte count (from request): %u\n", byte_count);
    printf("    Expected byte count: %u\n", expected_bytes);
    printf("    Request length: %d\n", req_len);

    /*
     * VULNERABILITY: CVE-2019-14462
     * The byte_count field is trusted without validation against quantity.
     * If byte_count > expected_bytes, we read beyond the request buffer.
     * If byte_count is very large, we cause out-of-bounds read.
     */
    if (byte_count != expected_bytes) {
        printf("[!] WARNING: byte_count mismatch! %u != %u\n",
               byte_count, expected_bytes);
    }

    if (address + quantity > MAX_COILS) {
        send_exception(fd, req, 0x02);
        return -1;
    }

    /* Check if byte_count would read past request buffer */
    int data_offset = 13;  /* Start of coil data in request */
    int available_bytes = req_len - data_offset;

    if (byte_count > available_bytes) {
        printf("[!] OVERFLOW: byte_count (%u) > available (%d)\n",
               byte_count, available_bytes);
        printf("[CRASH] Out-of-bounds read detected!\n");
        printf("[CRASH] CVE-2019-14462 triggered!\n");
        fflush(stdout);
        abort();
    }

    /* Unpack coils from request data */
    for (int i = 0; i < quantity && i < byte_count * 8; i++) {
        coils[address + i] = (req[data_offset + i/8] >> (i % 8)) & 1;
    }

    /* Send response */
    uint8_t resp[12];
    memcpy(resp, req, 4);
    resp[4] = 0; resp[5] = 6;
    resp[6] = req[6];
    resp[7] = 0x0F;
    resp[8] = address >> 8; resp[9] = address & 0xFF;
    resp[10] = quantity >> 8; resp[11] = quantity & 0xFF;
    send(fd, resp, 12, 0);

    printf("[*] Wrote %u coils at address %u\n", quantity, address);
    return 0;
}

void handle_client(int fd) {
    uint8_t buf[512];
    printf("[*] Client connected\n");

    while (1) {
        ssize_t n = recv(fd, buf, 7, MSG_WAITALL);
        if (n <= 0) break;

        uint16_t length = (buf[4] << 8) | buf[5];
        int pdu_len = 0;
        if (length > 1 && length < 500) {
            pdu_len = recv(fd, buf + 7, length - 1, MSG_WAITALL);
        }

        uint8_t fc = buf[7];
        if (fc == 0x0F) {
            handle_write_multiple_coils(fd, buf, 7 + pdu_len);
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
    memset(coils, 0, sizeof(coils));

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    printf("===========================================\n");
    printf("  VULNERABLE Modbus Server - CVE-2019-14462\n");
    printf("  Port: %d\n", PORT);
    printf("  Vulnerability: OOB read in FC 0x0F\n");
    printf("  Trigger: byte_count > actual data length\n");
    printf("===========================================\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) handle_client(client_fd);
    }
    return 0;
}
