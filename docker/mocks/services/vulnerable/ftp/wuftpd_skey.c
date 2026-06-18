#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Simulated wu-ftpd 2.6.2 - CVE-2004-0185 S/Key buffer overflow */
volatile char canary[16] = "CANARYPROTECT!";

void check_canary() {
    if (memcmp((void*)canary, "CANARYPROTECT!", 14) != 0) {
        fprintf(stderr, "[VULN] Stack buffer overflow detected! Simulating crash...\n");
        abort();
    }
}

/* CVE-2004-0185: skey_challenge has fixed buffer that overflows on long name */
void skey_challenge(char *name) {
    char challenge[64];  /* Fixed size buffer - vulnerable */

    /* Original vulnerable code: sprintf(challenge, "S/KEY %d %s", ..., name) */
    /* No bounds checking on name parameter */
    if (strlen(name) > 60) {
        fprintf(stderr, "[VULN] CVE-2004-0185: S/Key buffer overflow triggered\n");
        /* Simulate stack corruption */
        memset((void*)canary, 'X', 16);
    }

    snprintf(challenge, sizeof(challenge), "S/KEY 99 %s", name);
    check_canary();
}

void handle_client(int sock) {
    char buf[1024], cmd[64], arg[960];
    int awaiting_pass = 0;
    char username[960] = {0};

    send(sock, "220 wu-ftpd 2.6.2 (CVE-2004-0185 S/Key vulnerable)\r\n", 52, 0);

    while (1) {
        memset(buf, 0, sizeof(buf));
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n <= 0) break;

        memset(cmd, 0, sizeof(cmd));
        memset(arg, 0, sizeof(arg));
        sscanf(buf, "%63s %959[^\r\n]", cmd, arg);

        if (strcasecmp(cmd, "USER") == 0) {
            strncpy(username, arg, sizeof(username)-1);
            /* Trigger S/Key challenge with username */
            skey_challenge(username);
            char resp[128];
            snprintf(resp, sizeof(resp), "331 Password required for %.64s\r\n", username);
            send(sock, resp, strlen(resp), 0);
            awaiting_pass = 1;
        } else if (strcasecmp(cmd, "PASS") == 0) {
            if (awaiting_pass) {
                send(sock, "230 User logged in\r\n", 20, 0);
                awaiting_pass = 0;
            }
        } else if (strcasecmp(cmd, "QUIT") == 0) {
            send(sock, "221 Goodbye\r\n", 13, 0);
            break;
        } else {
            send(sock, "500 Command not understood\r\n", 28, 0);
        }
    }
    close(sock);
}

int main() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(2125), .sin_addr.s_addr = INADDR_ANY};
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 5);

    printf("wu-ftpd 2.6.2 simulator (CVE-2004-0185 S/Key) listening on port 2125\n");

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (fork() == 0) { handle_client(cli); exit(0); }
        close(cli);
    }
}
