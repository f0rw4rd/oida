/**
 * Vulnerable Modbus TCP Server for Fuzzing Demo
 *
 * This server intentionally contains a buffer overflow vulnerability
 * for demonstrating crash detection and test case replay in OIDA.
 *
 * VULNERABILITY: Stack buffer overflow when MBAP length field exceeds buffer size.
 * The server uses a 64-byte buffer but trusts the length field from the client,
 * allowing heap/stack corruption when length > 57 bytes (64 - 7 byte MBAP header).
 *
 * Trigger: Send Modbus request with MBAP length field > 57 (e.g., 0x1000)
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

#define PORT 5020
#define BUFFER_SIZE 64  /* Intentionally small to trigger overflow */

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t n;

    printf("[*] Client connected\n");

    while (1) {
        /* Read MBAP header (7 bytes):
         * - Transaction ID: 2 bytes
         * - Protocol ID: 2 bytes
         * - Length: 2 bytes (remaining bytes including unit ID)
         * - Unit ID: 1 byte
         */
        n = recv(client_fd, buffer, 7, 0);
        if (n <= 0) {
            printf("[*] Client disconnected\n");
            break;
        }

        if (n < 7) {
            printf("[!] Incomplete MBAP header (%zd bytes)\n", n);
            continue;
        }

        /* Extract length from MBAP header (bytes 4-5, big-endian) */
        uint16_t length = ((uint8_t)buffer[4] << 8) | (uint8_t)buffer[5];
        uint8_t unit_id = buffer[6];

        printf("[*] MBAP: length=%u, unit_id=%u\n", length, unit_id);

        /* VULNERABILITY: No bounds check on length field!
         * Buffer is only 64 bytes, MBAP header is 7 bytes, leaving 57 bytes.
         * If length > 57, we overflow the stack buffer.
         *
         * Using MSG_WAITALL to block until all requested bytes are received,
         * ensuring the overflow happens reliably when fuzzer sends large payloads.
         */
        if (length > 1) {
            /* Read PDU data (length - 1 for unit_id already read) */
            size_t to_read = length - 1;
            size_t total_read = 0;
            while (total_read < to_read) {
                n = recv(client_fd, buffer + 7 + total_read, to_read - total_read, 0);
                if (n <= 0) {
                    printf("[*] Client disconnected during PDU read\n");
                    goto disconnect;
                }
                total_read += n;
            }
        }

        /* Parse function code */
        uint8_t function_code = buffer[7];
        printf("[*] Function code: 0x%02x\n", function_code);

        /* Build simple response */
        /* Keep transaction ID and protocol ID from request */
        buffer[4] = 0;
        buffer[5] = 3;  /* Response length: unit_id + fc + byte_count */
        /* buffer[6] = unit_id (already set) */
        buffer[7] = function_code;
        buffer[8] = 2;  /* Byte count */
        buffer[9] = 0;  /* Data byte 1 */
        buffer[10] = 0; /* Data byte 2 */

        /* Send response (11 bytes total) */
        send(client_fd, buffer, 11, 0);
    }

disconnect:
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    int port = PORT;

    /* Disable stdout buffering for crash visibility */
    setbuf(stdout, NULL);

    /* Allow port override via environment or argument */
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    char *env_port = getenv("MODBUS_PORT");
    if (env_port) {
        port = atoi(env_port);
    }

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }

    /* Allow address reuse */
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind to address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    /* Listen for connections */
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    printf("===========================================\n");
    printf("  VULNERABLE Modbus TCP Server\n");
    printf("  Port: %d\n", port);
    printf("  Buffer size: %d bytes (overflow at length > 57)\n", BUFFER_SIZE);
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");
    fflush(stdout);

    /* Accept connections - SINGLE THREADED for fuzzing demo
     * When overflow corrupts return address, entire server crashes
     * This allows OIDA to detect the crash via connection failure
     */
    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        /* Handle client directly (no fork) - crash kills server */
        handle_client(client_fd);
    }

    return 0;
}
