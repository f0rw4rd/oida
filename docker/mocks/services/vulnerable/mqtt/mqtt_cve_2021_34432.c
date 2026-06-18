/**
 * Vulnerable MQTT Broker - CVE-2021-34432
 *
 * Heap memory corruption in Mosquitto <= 2.0.10 during QoS 2 message flow.
 * When a client sends a PUBREL with an invalid packet ID, the broker may
 * access freed memory or corrupt heap structures.
 *
 * VULNERABILITY: Use-after-free / heap corruption when handling QoS 2
 * PUBREL packets with mismatched or replayed packet IDs.
 *
 * Trigger: Send PUBLISH QoS 2, receive PUBREC, then send PUBREL with
 * different packet ID or send duplicate PUBREL.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2021-34432
 * Affected: Mosquitto <= 2.0.10
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

#define PORT 1883
#define MAX_INFLIGHT 16

/* MQTT Control Packet Types */
#define MQTT_CONNECT     1
#define MQTT_CONNACK     2
#define MQTT_PUBLISH     3
#define MQTT_PUBACK      4
#define MQTT_PUBREC      5
#define MQTT_PUBREL      6
#define MQTT_PUBCOMP     7
#define MQTT_SUBSCRIBE   8
#define MQTT_SUBACK      9
#define MQTT_PINGREQ     12
#define MQTT_PINGRESP    13
#define MQTT_DISCONNECT  14

/* QoS 2 message state */
typedef struct {
    uint16_t packet_id;
    uint8_t *payload;      /* VULNERABLE: Freed but pointer kept */
    uint32_t payload_len;
    uint8_t state;         /* 0=free, 1=PUBREC sent, 2=PUBCOMP sent */
} qos2_msg_t;

typedef struct {
    int fd;
    char client_id[256];
    uint8_t connected;
    qos2_msg_t inflight[MAX_INFLIGHT];  /* VULNERABLE: Poor state management */
} mqtt_client_t;

int read_remaining_length(int fd, uint32_t *length) {
    uint8_t byte;
    uint32_t multiplier = 1;
    *length = 0;

    do {
        if (recv(fd, &byte, 1, 0) != 1) return -1;
        *length += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128) return -1;
    } while (byte & 0x80);

    return 0;
}

void send_connack(int fd, uint8_t return_code) {
    uint8_t packet[] = { (MQTT_CONNACK << 4), 2, 0, return_code };
    send(fd, packet, sizeof(packet), 0);
}

void send_pingresp(int fd) {
    uint8_t packet[] = { (MQTT_PINGRESP << 4), 0 };
    send(fd, packet, sizeof(packet), 0);
}

void send_pubrec(int fd, uint16_t packet_id) {
    uint8_t packet[] = {
        (MQTT_PUBREC << 4), 2,
        (packet_id >> 8) & 0xFF,
        packet_id & 0xFF
    };
    send(fd, packet, sizeof(packet), 0);
    printf("[*] Sent PUBREC for packet_id=%u\n", packet_id);
}

void send_pubcomp(int fd, uint16_t packet_id) {
    uint8_t packet[] = {
        (MQTT_PUBCOMP << 4), 2,
        (packet_id >> 8) & 0xFF,
        packet_id & 0xFF
    };
    send(fd, packet, sizeof(packet), 0);
    printf("[*] Sent PUBCOMP for packet_id=%u\n", packet_id);
}

void send_suback(int fd, uint16_t packet_id, uint8_t qos) {
    uint8_t packet[] = {
        (MQTT_SUBACK << 4), 3,
        (packet_id >> 8) & 0xFF,
        packet_id & 0xFF,
        qos
    };
    send(fd, packet, sizeof(packet), 0);
}

int handle_connect(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    if (length < 10) return -1;

    uint16_t offset = 0;
    uint16_t proto_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + proto_len + 1 + 1 + 2;

    if (offset + 2 > length) return -1;
    uint16_t client_id_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    if (client_id_len > 0 && offset + client_id_len <= length) {
        size_t copy_len = client_id_len < 255 ? client_id_len : 255;
        memcpy(client->client_id, payload + offset, copy_len);
        client->client_id[copy_len] = '\0';
    }

    printf("[*] CONNECT from client: %s\n", client->client_id);
    client->connected = 1;
    send_connack(client->fd, 0);
    return 0;
}

/* Handle QoS 2 PUBLISH - store message state */
int handle_publish_qos2(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    if (length < 4) return -1;

    uint16_t topic_len = (payload[0] << 8) | payload[1];
    if (2 + topic_len + 2 > length) return -1;

    uint16_t packet_id = (payload[2 + topic_len] << 8) | payload[2 + topic_len + 1];
    uint32_t msg_offset = 2 + topic_len + 2;
    uint32_t msg_len = length - msg_offset;

    printf("[*] PUBLISH QoS 2: packet_id=%u, topic_len=%u, msg_len=%u\n",
           packet_id, topic_len, msg_len);

    /* Find or allocate inflight slot */
    int slot = -1;
    for (int i = 0; i < MAX_INFLIGHT; i++) {
        if (client->inflight[i].state == 0) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        printf("[!] No free inflight slots\n");
        return -1;
    }

    /* Store message for QoS 2 flow */
    client->inflight[slot].packet_id = packet_id;
    client->inflight[slot].payload = malloc(msg_len);
    if (client->inflight[slot].payload && msg_len > 0) {
        memcpy(client->inflight[slot].payload, payload + msg_offset, msg_len);
    }
    client->inflight[slot].payload_len = msg_len;
    client->inflight[slot].state = 1;

    send_pubrec(client->fd, packet_id);
    return 0;
}

/*
 * Handle PUBREL - VULNERABLE
 *
 * CVE-2021-34432: The broker doesn't properly validate packet_id state.
 * If attacker sends PUBREL with:
 *   1. A packet_id that was never sent (no matching PUBLISH)
 *   2. A packet_id that was already completed (replay)
 *   3. A packet_id for a slot that was freed
 *
 * This can cause use-after-free or double-free.
 */
int handle_pubrel(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    if (length < 2) return -1;

    uint16_t packet_id = (payload[0] << 8) | payload[1];
    printf("[*] PUBREL: packet_id=%u\n", packet_id);

    /*
     * VULNERABILITY: Poor state machine handling
     *
     * We search for the packet_id but don't properly handle:
     * - Missing packet_id (never existed)
     * - Already completed packet_id
     * - Race conditions
     *
     * Real CVE-2021-34432 had similar issue where PUBREL handling
     * could access freed memory or corrupt internal state.
     */
    for (int i = 0; i < MAX_INFLIGHT; i++) {
        if (client->inflight[i].packet_id == packet_id) {
            printf("[*] Found inflight message at slot %d, state=%u\n",
                   i, client->inflight[i].state);

            /*
             * VULNERABLE: Access payload that might already be freed
             * In a real exploit, sending duplicate PUBREL could trigger
             * use-after-free here.
             */
            if (client->inflight[i].payload) {
                printf("[*] Payload ptr: %p, len: %u\n",
                       client->inflight[i].payload,
                       client->inflight[i].payload_len);

                /* Access potentially freed memory */
                if (client->inflight[i].payload_len > 0) {
                    uint8_t first_byte = client->inflight[i].payload[0];
                    printf("[*] First payload byte: 0x%02x\n", first_byte);
                }

                /* Free the payload */
                free(client->inflight[i].payload);
                client->inflight[i].payload = NULL;  /* But pointer was already used! */
            }

            /* VULNERABLE: Don't clear state properly - allows replay */
            /* Real fix would set state = 0 or remove entry entirely */
            client->inflight[i].state = 2;

            send_pubcomp(client->fd, packet_id);
            return 0;
        }
    }

    /*
     * VULNERABLE: Send PUBCOMP even for unknown packet_id
     * This violates MQTT spec and can cause state confusion
     */
    printf("[!] PUBREL for unknown packet_id=%u - sending PUBCOMP anyway (VULN)\n", packet_id);
    send_pubcomp(client->fd, packet_id);

    return 0;
}

int handle_subscribe(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    if (length < 2) return -1;
    uint16_t packet_id = (payload[0] << 8) | payload[1];
    printf("[*] SUBSCRIBE: packet_id=%u\n", packet_id);
    send_suback(client->fd, packet_id, 2);  /* Grant QoS 2 */
    return 0;
}

void handle_client(int client_fd) {
    mqtt_client_t client = {0};
    client.fd = client_fd;

    uint8_t header;
    uint32_t remaining_length;
    uint8_t *payload = NULL;

    printf("[*] Client connected (fd=%d)\n", client_fd);

    while (1) {
        if (recv(client_fd, &header, 1, 0) != 1) {
            printf("[*] Client disconnected\n");
            break;
        }

        uint8_t packet_type = (header >> 4) & 0x0F;
        uint8_t flags = header & 0x0F;
        uint8_t qos = (flags >> 1) & 0x03;

        if (read_remaining_length(client_fd, &remaining_length) < 0) {
            printf("[!] Failed to read remaining length\n");
            break;
        }

        if (remaining_length > 0) {
            payload = malloc(remaining_length);
            if (!payload) break;

            uint32_t total = 0;
            while (total < remaining_length) {
                ssize_t n = recv(client_fd, payload + total, remaining_length - total, 0);
                if (n <= 0) {
                    free(payload);
                    goto disconnect;
                }
                total += n;
            }
        }

        switch (packet_type) {
            case MQTT_CONNECT:
                handle_connect(&client, payload, remaining_length);
                break;

            case MQTT_PUBLISH:
                if (client.connected && qos == 2) {
                    handle_publish_qos2(&client, payload, remaining_length);
                }
                break;

            case MQTT_PUBREL:
                if (client.connected) {
                    handle_pubrel(&client, payload, remaining_length);
                }
                break;

            case MQTT_SUBSCRIBE:
                if (client.connected) {
                    handle_subscribe(&client, payload, remaining_length);
                }
                break;

            case MQTT_PINGREQ:
                send_pingresp(client_fd);
                break;

            case MQTT_DISCONNECT:
                if (payload) free(payload);
                goto disconnect;
        }

        if (payload) {
            free(payload);
            payload = NULL;
        }
    }

disconnect:
    /* Clean up inflight messages */
    for (int i = 0; i < MAX_INFLIGHT; i++) {
        if (client.inflight[i].payload) {
            free(client.inflight[i].payload);
        }
    }
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    int port = PORT;

    setbuf(stdout, NULL);

    char *env_port = getenv("MQTT_PORT");
    if (env_port) port = atoi(env_port);
    if (argc > 1) port = atoi(argv[1]);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }

    if (listen(server_fd, 5) < 0) { perror("listen"); exit(1); }

    printf("===========================================\n");
    printf("  VULNERABLE MQTT Broker - CVE-2021-34432\n");
    printf("  Port: %d\n", port);
    printf("  Vuln: QoS 2 use-after-free / heap corruption\n");
    printf("  Trigger: PUBREL with invalid/replay packet_id\n");
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }
        handle_client(client_fd);
    }

    return 0;
}
