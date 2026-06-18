/**
 * Vulnerable MQTT Broker - CVE-2017-7650
 *
 * Pattern-based ACL bypass and out-of-bounds read in Mosquitto < 1.4.12.
 * When processing topic patterns with wildcards (+/#), the broker doesn't
 * properly bounds-check the pattern matching, allowing OOB read.
 *
 * VULNERABILITY: Stack buffer overflow in topic pattern matching when
 * subscription filter or publish topic exceeds expected length.
 *
 * Trigger: Subscribe to topic with very long filter containing wildcards,
 * then publish to matching topic.
 *
 * Real CVE: https://nvd.nist.gov/vuln/detail/CVE-2017-7650
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

#define PORT 1883
#define TOPIC_BUFFER 128      /* Intentionally small for overflow */
#define MAX_SUBSCRIPTIONS 32

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

typedef struct {
    char topic[TOPIC_BUFFER];  /* VULNERABLE: Fixed size */
    uint8_t qos;
    uint8_t active;
} subscription_t;

typedef struct {
    int fd;
    char client_id[256];
    uint8_t connected;
    subscription_t subs[MAX_SUBSCRIPTIONS];
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

void send_connack(int fd, uint8_t rc) {
    uint8_t pkt[] = { (MQTT_CONNACK << 4), 2, 0, rc };
    send(fd, pkt, sizeof(pkt), 0);
}

void send_pingresp(int fd) {
    uint8_t pkt[] = { (MQTT_PINGRESP << 4), 0 };
    send(fd, pkt, sizeof(pkt), 0);
}

void send_suback(int fd, uint16_t packet_id, uint8_t *qos_list, int count) {
    uint8_t pkt[5 + MAX_SUBSCRIPTIONS];
    pkt[0] = (MQTT_SUBACK << 4);
    pkt[1] = 2 + count;
    pkt[2] = (packet_id >> 8) & 0xFF;
    pkt[3] = packet_id & 0xFF;
    for (int i = 0; i < count; i++) {
        pkt[4 + i] = qos_list[i];
    }
    send(fd, pkt, 4 + count, 0);
}

void send_puback(int fd, uint16_t packet_id) {
    uint8_t pkt[] = { (MQTT_PUBACK << 4), 2, (packet_id >> 8) & 0xFF, packet_id & 0xFF };
    send(fd, pkt, sizeof(pkt), 0);
}

/*
 * VULNERABLE topic matching function
 *
 * CVE-2017-7650: Pattern matching doesn't properly validate buffer bounds.
 * When topic or pattern is longer than expected, we read/write out of bounds.
 */
int topic_matches(const char *pattern, const char *topic) {
    char pat_buf[TOPIC_BUFFER];
    char top_buf[TOPIC_BUFFER];

    /*
     * VULNERABILITY: No length check before strcpy!
     * If pattern or topic > TOPIC_BUFFER, we overflow the stack.
     */
    strcpy(pat_buf, pattern);
    strcpy(top_buf, topic);

    char *pat = pat_buf;
    char *top = top_buf;

    while (*pat && *top) {
        if (*pat == '+') {
            /* Single-level wildcard - skip to next / */
            while (*top && *top != '/') top++;
            pat++;
            if (*pat == '/') pat++;
            if (*top == '/') top++;
        } else if (*pat == '#') {
            /* Multi-level wildcard - match everything */
            return 1;
        } else if (*pat == *top) {
            pat++;
            top++;
        } else {
            return 0;
        }
    }

    /* Check for trailing # */
    if (*pat == '#') return 1;

    return (*pat == '\0' && *top == '\0');
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

    printf("[*] CONNECT from: %s\n", client->client_id);
    client->connected = 1;
    send_connack(client->fd, 0);
    return 0;
}

/*
 * Handle SUBSCRIBE - VULNERABLE
 *
 * Stores subscription patterns without proper length validation.
 */
int handle_subscribe(mqtt_client_t *client, uint8_t *payload, uint32_t length) {
    if (length < 5) return -1;

    uint16_t packet_id = (payload[0] << 8) | payload[1];
    uint32_t offset = 2;

    uint8_t granted_qos[MAX_SUBSCRIPTIONS];
    int sub_count = 0;

    while (offset < length && sub_count < MAX_SUBSCRIPTIONS) {
        if (offset + 2 > length) break;

        uint16_t topic_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;

        if (offset + topic_len + 1 > length) break;

        printf("[*] SUBSCRIBE: topic_len=%u\n", topic_len);

        /* Find free subscription slot */
        int slot = -1;
        for (int i = 0; i < MAX_SUBSCRIPTIONS; i++) {
            if (!client->subs[i].active) {
                slot = i;
                break;
            }
        }

        if (slot >= 0) {
            /*
             * VULNERABILITY: CVE-2017-7650
             * No bounds check on topic_len before memcpy!
             * If topic_len > TOPIC_BUFFER, we overflow the stack buffer.
             */
            memcpy(client->subs[slot].topic, payload + offset, topic_len);
            client->subs[slot].topic[topic_len] = '\0';  /* May write OOB! */
            client->subs[slot].qos = payload[offset + topic_len];
            client->subs[slot].active = 1;

            printf("[*] Stored subscription: '%s' (len=%u, slot=%d)\n",
                   client->subs[slot].topic, topic_len, slot);

            granted_qos[sub_count] = client->subs[slot].qos;
        } else {
            granted_qos[sub_count] = 0x80;  /* Failure */
        }

        offset += topic_len + 1;
        sub_count++;
    }

    send_suback(client->fd, packet_id, granted_qos, sub_count);
    return 0;
}

/*
 * Handle PUBLISH - triggers vulnerable pattern matching
 */
int handle_publish(mqtt_client_t *client, uint8_t flags, uint8_t *payload, uint32_t length) {
    if (length < 2) return -1;

    uint8_t qos = (flags >> 1) & 0x03;
    uint16_t topic_len = (payload[0] << 8) | payload[1];

    if (2 + topic_len > length) return -1;

    char topic[512];  /* Larger buffer for receiving */
    if (topic_len < sizeof(topic)) {
        memcpy(topic, payload + 2, topic_len);
        topic[topic_len] = '\0';
    } else {
        return -1;
    }

    uint32_t msg_offset = 2 + topic_len;
    uint16_t packet_id = 0;

    if (qos > 0) {
        if (msg_offset + 2 > length) return -1;
        packet_id = (payload[msg_offset] << 8) | payload[msg_offset + 1];
        msg_offset += 2;
    }

    printf("[*] PUBLISH: topic='%s' (len=%u), qos=%u\n", topic, topic_len, qos);

    /*
     * Check subscriptions - VULNERABLE pattern matching
     * This calls topic_matches() which has the stack overflow vulnerability
     */
    for (int i = 0; i < MAX_SUBSCRIPTIONS; i++) {
        if (client->subs[i].active) {
            printf("[*] Checking pattern '%s' against topic '%s'\n",
                   client->subs[i].topic, topic);

            /* VULNERABLE: topic_matches uses strcpy without bounds check */
            if (topic_matches(client->subs[i].topic, topic)) {
                printf("[*] MATCH! Would forward to subscriber\n");
            }
        }
    }

    if (qos == 1) {
        send_puback(client->fd, packet_id);
    }

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

        if (read_remaining_length(client_fd, &remaining_length) < 0) break;

        if (remaining_length > 0) {
            payload = malloc(remaining_length);
            if (!payload) break;

            uint32_t total = 0;
            while (total < remaining_length) {
                ssize_t n = recv(client_fd, payload + total, remaining_length - total, 0);
                if (n <= 0) { free(payload); goto disconnect; }
                total += n;
            }
        }

        switch (packet_type) {
            case MQTT_CONNECT:
                handle_connect(&client, payload, remaining_length);
                break;
            case MQTT_PUBLISH:
                if (client.connected)
                    handle_publish(&client, flags, payload, remaining_length);
                break;
            case MQTT_SUBSCRIBE:
                if (client.connected)
                    handle_subscribe(&client, payload, remaining_length);
                break;
            case MQTT_PINGREQ:
                send_pingresp(client_fd);
                break;
            case MQTT_DISCONNECT:
                if (payload) free(payload);
                goto disconnect;
        }

        if (payload) { free(payload); payload = NULL; }
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
    printf("  VULNERABLE MQTT Broker - CVE-2017-7650\n");
    printf("  Port: %d\n", port);
    printf("  Vuln: Stack overflow in topic matching\n");
    printf("  Trigger: Subscribe/publish with topic > %d bytes\n", TOPIC_BUFFER);
    printf("  FOR SECURITY TESTING ONLY\n");
    printf("===========================================\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }
        handle_client(client_fd);
    }

    return 0;
}
