/**
 * Vulnerable MQTT Broker - CVE-2017-7651
 *
 * Heap buffer overflow in Mosquitto < 1.4.12 when handling oversized CONNECT packets.
 * The broker allocates a fixed-size buffer for client ID but doesn't properly validate
 * the length field, allowing heap overflow.
 *
 * VULNERABILITY: Heap buffer overflow when CONNECT packet contains client_id length
 * that exceeds allocated buffer size.
 *
 * Trigger: Send CONNECT with client_id_length > 256 (buffer size)
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2017-7651
 * Affected: Mosquitto < 1.4.12
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
#include <errno.h>

#define PORT 1883
#define CLIENT_ID_BUFFER 256  /* Intentionally small - CVE trigger */
#define MAX_PACKET_SIZE 65536

/* MQTT Control Packet Types */
#define MQTT_CONNECT     1
#define MQTT_CONNACK     2
#define MQTT_PUBLISH     3
#define MQTT_PUBACK      4
#define MQTT_SUBSCRIBE   8
#define MQTT_SUBACK      9
#define MQTT_PINGREQ     12
#define MQTT_PINGRESP    13
#define MQTT_DISCONNECT  14

/* CONNACK Return Codes */
#define CONNACK_ACCEPTED 0

typedef struct {
    int fd;
    char client_id[CLIENT_ID_BUFFER];  /* VULNERABLE: Fixed size buffer */
    uint8_t connected;
} mqtt_client_t;

/* Read remaining length (variable length encoding) */
int read_remaining_length(int fd, uint32_t *length) {
    uint8_t byte;
    uint32_t multiplier = 1;
    *length = 0;

    do {
        if (recv(fd, &byte, 1, 0) != 1) {
            return -1;
        }
        *length += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128) {
            return -1;  /* Malformed */
        }
    } while (byte & 0x80);

    return 0;
}

/* Send CONNACK */
void send_connack(int fd, uint8_t return_code) {
    uint8_t packet[] = {
        (MQTT_CONNACK << 4),  /* Fixed header */
        2,                     /* Remaining length */
        0,                     /* Session present flag */
        return_code           /* Return code */
    };
    send(fd, packet, sizeof(packet), 0);
}

/* Send PINGRESP */
void send_pingresp(int fd) {
    uint8_t packet[] = {
        (MQTT_PINGRESP << 4),
        0
    };
    send(fd, packet, sizeof(packet), 0);
}

/* Send SUBACK */
void send_suback(int fd, uint16_t packet_id, uint8_t qos) {
    uint8_t packet[] = {
        (MQTT_SUBACK << 4),
        3,                          /* Remaining length */
        (packet_id >> 8) & 0xFF,    /* Packet ID MSB */
        packet_id & 0xFF,           /* Packet ID LSB */
        qos                         /* Granted QoS */
    };
    send(fd, packet, sizeof(packet), 0);
}

/* Handle CONNECT packet - VULNERABLE */
int handle_connect(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    uint16_t offset = 0;

    /* Protocol name length */
    if (offset + 2 > length) return -1;
    uint16_t proto_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    /* Skip protocol name */
    offset += proto_len;

    /* Protocol level */
    if (offset + 1 > length) return -1;
    uint8_t proto_level = payload[offset++];

    /* Connect flags */
    if (offset + 1 > length) return -1;
    uint8_t connect_flags = payload[offset++];

    /* Keep alive */
    if (offset + 2 > length) return -1;
    offset += 2;

    /* Client ID length */
    if (offset + 2 > length) return -1;
    uint16_t client_id_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    printf("[*] CONNECT: proto_level=%u, flags=0x%02x, client_id_len=%u\n",
           proto_level, connect_flags, client_id_len);

    /*
     * VULNERABILITY: CVE-2017-7651
     *
     * No bounds check on client_id_len before copying!
     * If client_id_len > CLIENT_ID_BUFFER (256), we overflow the heap buffer.
     *
     * Real Mosquitto < 1.4.12 had similar issue where client_id was copied
     * without proper length validation, allowing heap corruption.
     */
    if (offset + client_id_len > length) {
        printf("[!] Truncated client_id in packet\n");
        return -1;
    }

    /* VULNERABLE COPY - no bounds check on destination buffer! */
    memcpy(client->client_id, payload + offset, client_id_len);
    client->client_id[client_id_len] = '\0';  /* May write out of bounds! */

    printf("[*] Client ID: %s (len=%u)\n", client->client_id, client_id_len);

    client->connected = 1;
    send_connack(client->fd, CONNACK_ACCEPTED);

    return 0;
}

/* Handle SUBSCRIBE packet */
int handle_subscribe(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    if (length < 2) return -1;

    uint16_t packet_id = (payload[0] << 8) | payload[1];
    printf("[*] SUBSCRIBE: packet_id=%u\n", packet_id);

    send_suback(client->fd, packet_id, 0);
    return 0;
}

/* Handle client connection */
void handle_client(int client_fd) {
    mqtt_client_t client = {0};
    client.fd = client_fd;

    uint8_t header;
    uint32_t remaining_length;
    uint8_t *payload = NULL;

    printf("[*] Client connected (fd=%d)\n", client_fd);

    while (1) {
        /* Read fixed header */
        if (recv(client_fd, &header, 1, 0) != 1) {
            printf("[*] Client disconnected\n");
            break;
        }

        uint8_t packet_type = (header >> 4) & 0x0F;

        /* Read remaining length */
        if (read_remaining_length(client_fd, &remaining_length) < 0) {
            printf("[!] Failed to read remaining length\n");
            break;
        }

        printf("[*] Packet: type=%u, remaining_length=%u\n", packet_type, remaining_length);

        /* Read payload */
        if (remaining_length > 0) {
            payload = malloc(remaining_length);
            if (!payload) {
                printf("[!] malloc failed\n");
                break;
            }

            uint32_t total_read = 0;
            while (total_read < remaining_length) {
                ssize_t n = recv(client_fd, payload + total_read,
                                remaining_length - total_read, 0);
                if (n <= 0) {
                    printf("[*] Client disconnected during payload read\n");
                    free(payload);
                    goto disconnect;
                }
                total_read += n;
            }
        }

        /* Handle packet */
        switch (packet_type) {
            case MQTT_CONNECT:
                if (handle_connect(&client, payload, remaining_length) < 0) {
                    printf("[!] CONNECT failed\n");
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
                printf("[*] Client sent DISCONNECT\n");
                if (payload) free(payload);
                goto disconnect;

            default:
                printf("[*] Unhandled packet type: %u\n", packet_type);
        }

        if (payload) {
            free(payload);
            payload = NULL;
        }
    }

disconnect:
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    int port = PORT;

    setbuf(stdout, NULL);

    char *env_port = getenv("MQTT_PORT");
    if (env_port) {
        port = atoi(env_port);
    }
    if (argc > 1) {
        port = atoi(argv[1]);
    }

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

    printf("===========================================\n");
    printf("  VULNERABLE MQTT Broker - CVE-2017-7651\n");
    printf("  Port: %d\n", port);
    printf("  Vuln: Heap overflow on client_id > %d bytes\n", CLIENT_ID_BUFFER);
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");

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
