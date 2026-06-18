#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Simulated wu-ftpd 2.6.1 - CVE-2001-0550 glob heap corruption */
volatile char canary[16] = "CANARYPROTECT!";

void check_canary() {
    if (memcmp((void*)canary, "CANARYPROTECT!", 14) != 0) {
        fprintf(stderr, "[VULN] Heap corruption detected! Simulating crash...\n");
        abort();
    }
}

void vulnerable_glob(char *pattern) {
    char heap_buf[64];

    /* CVE-2001-0550: glob function doesn't handle ~{ properly */
    if (strstr(pattern, "~{") != NULL) {
        fprintf(stderr, "[VULN] CVE-2001-0550: Malicious glob pattern detected\n");
        /* Simulate heap corruption */
        memset((void*)canary, 'A', 16);
    }

    strncpy(heap_buf, pattern, sizeof(heap_buf)-1);
    check_canary();
}

void handle_client(int sock) {
    char buf[512], cmd[64], arg[448];

    send(sock, "220 wu-ftpd 2.6.1 (CVE-2001-0550 vulnerable)\r\n", 46, 0);

    while (1) {
        memset(buf, 0, sizeof(buf));
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n <= 0) break;

        memset(cmd, 0, sizeof(cmd));
        memset(arg, 0, sizeof(arg));
        sscanf(buf, "%63s %447s", cmd, arg);

        if (strcasecmp(cmd, "USER") == 0) {
            send(sock, "331 Password required\r\n", 23, 0);
        } else if (strcasecmp(cmd, "PASS") == 0) {
            send(sock, "230 User logged in\r\n", 20, 0);
        } else if (strcasecmp(cmd, "LIST") == 0 || strcasecmp(cmd, "NLST") == 0) {
            vulnerable_glob(arg);
            send(sock, "226 Transfer complete\r\n", 23, 0);
        } else if (strcasecmp(cmd, "CWD") == 0) {
            vulnerable_glob(arg);
            send(sock, "250 CWD successful\r\n", 20, 0);
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

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(2124), .sin_addr.s_addr = INADDR_ANY};
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 5);

    printf("wu-ftpd 2.6.1 simulator (CVE-2001-0550) listening on port 2124\n");

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (fork() == 0) { handle_client(cli); exit(0); }
        close(cli);
    }
}
