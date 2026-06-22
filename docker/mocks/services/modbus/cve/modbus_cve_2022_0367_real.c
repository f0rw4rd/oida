/**
 * Real CVE-2022-0367 - Uses actual vulnerable libmodbus v3.1.6
 *
 * The vulnerability is in libmodbus's modbus_reply() function,
 * not in this code. This just exercises the vulnerable code path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <modbus/modbus.h>

#define PORT 5021

int main(void) {
    modbus_t *ctx;
    modbus_mapping_t *mb_mapping;
    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
    int server_socket, client_socket;

    setbuf(stdout, NULL);

    printf("===========================================\n");
    printf("  REAL libmodbus CVE-2022-0367 Server\n");
    printf("  Using: libmodbus v3.1.6 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("===========================================\n");

    /* Create modbus context */
    ctx = modbus_new_tcp("0.0.0.0", PORT);
    if (ctx == NULL) {
        fprintf(stderr, "modbus_new_tcp failed\n");
        return 1;
    }

    /*
     * CVE-2022-0367 trigger: start_registers > 0
     * Bug: mapping_address_write < 0 is not checked
     * If write_address < start_registers, mapping_address_write becomes negative
     * causing write to memory before the buffer (underflow)
     */
    mb_mapping = modbus_mapping_new_start_address(
        0, 0,       /* bits: start=0, nb=0 */
        0, 0,       /* input_bits: start=0, nb=0 */
        100, 100,   /* registers: start=100, nb=100 (addresses 100-199 valid) */
        0, 0        /* input_registers: start=0, nb=0 */
    );
    if (mb_mapping == NULL) {
        fprintf(stderr, "modbus_mapping_new failed\n");
        modbus_free(ctx);
        return 1;
    }

    printf("[*] Mapping: registers start=%d, nb=%d\n",
           mb_mapping->start_registers, mb_mapping->nb_registers);
    printf("[*] Valid write addresses: %d-%d\n",
           mb_mapping->start_registers,
           mb_mapping->start_registers + mb_mapping->nb_registers - 1);
    printf("[*] Trigger: FC 0x17 with write_address < %d\n",
           mb_mapping->start_registers);

    /* Initialize with test data */
    for (int i = 0; i < 100; i++) {
        mb_mapping->tab_registers[i] = i * 10;
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
        if (client_socket == -1) {
            continue;
        }

        printf("[*] Client connected\n");

        while (1) {
            int rc = modbus_receive(ctx, query);
            if (rc == -1) {
                break;
            }

            printf("[*] Received request, FC=0x%02x\n", query[7]);

            /*
             * CVE-2022-0367 is triggered HERE inside modbus_reply()
             * when handling FC 0x17 (Read/Write Multiple Registers)
             * with an out-of-bounds write address.
             *
             * The bug is a copy-paste error in libmodbus src/modbus.c
             * that fails to validate the write address.
             */
            rc = modbus_reply(ctx, query, rc, mb_mapping);
            if (rc == -1) {
                printf("[!] modbus_reply failed: %s\n", modbus_strerror(errno));
            } else {
                printf("[*] modbus_reply returned %d\n", rc);
            }

            /* Force heap operation to detect corruption */
            modbus_mapping_free(mb_mapping);
            printf("[*] Freed mapping - recreating\n");
            mb_mapping = modbus_mapping_new_start_address(0, 0, 0, 0, 100, 100, 0, 0);
            if (!mb_mapping) {
                printf("[CRASH] Heap corruption detected!\n");
                abort();
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
