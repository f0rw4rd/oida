/**
 * Real CVE-2024-10918 - Uses actual vulnerable libmodbus v3.1.10
 *
 * Vulnerability: Stack buffer overflow in modbus_reply() when handling
 * FC 0x05/0x06 with oversized MBAP length field.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <modbus/modbus.h>

#define PORT 5022

int main(void) {
    modbus_t *ctx;
    modbus_mapping_t *mb_mapping;
    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
    int server_socket, client_socket;

    setbuf(stdout, NULL);

    printf("===========================================\n");
    printf("  REAL libmodbus CVE-2024-10918 Server\n");
    printf("  Using: libmodbus v3.1.10 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Trigger: FC 0x05/0x06 with MBAP length > 260\n");
    printf("===========================================\n");

    ctx = modbus_new_tcp("0.0.0.0", PORT);
    if (ctx == NULL) {
        fprintf(stderr, "modbus_new_tcp failed\n");
        return 1;
    }

    mb_mapping = modbus_mapping_new(1000, 0, 1000, 0);
    if (mb_mapping == NULL) {
        fprintf(stderr, "modbus_mapping_new failed\n");
        modbus_free(ctx);
        return 1;
    }

    server_socket = modbus_tcp_listen(ctx, 1);
    if (server_socket == -1) {
        fprintf(stderr, "modbus_tcp_listen failed\n");
        modbus_mapping_free(mb_mapping);
        modbus_free(ctx);
        return 1;
    }

    printf("[*] Listening on port %d...\n", PORT);

    while (1) {
        client_socket = modbus_tcp_accept(ctx, &server_socket);
        if (client_socket == -1) continue;

        printf("[*] Client connected\n");

        while (1) {
            int rc = modbus_receive(ctx, query);
            if (rc == -1) break;

            printf("[*] Received %d bytes, FC=0x%02x\n", rc, query[7]);

            /*
             * CVE-2024-10918: The vulnerability is in modbus_reply()
             * which copies request data to a stack buffer without
             * validating the length against MODBUS_TCP_MAX_ADU_LENGTH.
             */
            rc = modbus_reply(ctx, query, rc, mb_mapping);
            if (rc == -1) {
                printf("[!] modbus_reply failed: %s\n", modbus_strerror(errno));
            }
        }

        printf("[*] Client disconnected\n");
        close(client_socket);
    }

    modbus_mapping_free(mb_mapping);
    modbus_close(ctx);
    modbus_free(ctx);
    return 0;
}
