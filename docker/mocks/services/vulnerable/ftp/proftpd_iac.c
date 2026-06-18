#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Simulated ProFTPD 1.3.3a - CVE-2010-4221 Telnet IAC stack buffer overflow */
volatile char canary[16] = "CANARYPROTECT!";

void check_canary() {
    if (memcmp((void*)canary, "CANARYPROTECT!", 14) != 0) {
        fprintf(stderr, "[VULN] Stack buffer overflow detected! Simulating crash...\n");
        abort();
    }
}

/* CVE-2010-4221: pr_netio_telnet_gets has 1024-byte buffer that overflows on IAC bytes */
void pr_netio_telnet_gets(char *data, int len) {
    char buf[1024];
    int iac_count = 0;

    /* Count IAC (0xFF) bytes in data */
    for (int i = 0; i < len; i++) {
        if ((unsigned char)data[i] == 0xFF) {
            iac_count++;
        }
    }

    /* CVE-2010-4221: Many IAC bytes cause buffer overflow due to improper length tracking */
    if (iac_count > 512) {
        fprintf(stderr, "[VULN] CVE-2010-4221: Telnet IAC buffer overflow triggered (%d IAC bytes)\n", iac_count);
        /* Simulate stack corruption */
        memset((void*)canary, 'X', 16);
    }

    memset(buf, 0, sizeof(buf));
    check_canary();
}

void handle_client(int sock) {
    char buf[8192];

    send(sock, "220 ProFTPD 1.3.3a Server (CVE-2010-4221 vulnerable)\r\n", 54, 0);

    while (1) {
        memset(buf, 0, sizeof(buf));
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n <= 0) break;

        /* Process through vulnerable telnet gets function */
        pr_netio_telnet_gets(buf, n);

        /* Basic FTP command handling */
        if (strncasecmp(buf, "USER", 4) == 0) {
            send(sock, "331 Password required\r\n", 23, 0);
        } else if (strncasecmp(buf, "PASS", 4) == 0) {
            send(sock, "230 User logged in\r\n", 20, 0);
        } else if (strncasecmp(buf, "QUIT", 4) == 0) {
            send(sock, "221 Goodbye\r\n", 13, 0);
            break;
        } else if (strncasecmp(buf, "SITE", 4) == 0) {
            send(sock, "200 SITE command ok\r\n", 21, 0);
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

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(2127), .sin_addr.s_addr = INADDR_ANY};
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 5);

    printf("ProFTPD 1.3.3a simulator (CVE-2010-4221 IAC) listening on port 2127\n");

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (fork() == 0) { handle_client(cli); exit(0); }
        close(cli);
    }
}
