#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Simulated ProFTPD 1.3.0 - CVE-2006-5815 sreplace stack buffer overflow */
volatile char canary[16] = "CANARYPROTECT!";

void check_canary() {
    if (memcmp((void*)canary, "CANARYPROTECT!", 14) != 0) {
        fprintf(stderr, "[VULN] Stack buffer overflow detected! Simulating crash...\n");
        abort();
    }
}

/* CVE-2006-5815: sreplace function has stack buffer overflow on %C expansion */
void vulnerable_sreplace(char *text) {
    char buf[256];

    /* Check for long format string patterns that trigger overflow */
    int pct_c_count = 0;
    for (int i = 0; text[i]; i++) {
        if (text[i] == '%' && text[i+1] == 'C') {
            pct_c_count++;
        }
    }

    if (pct_c_count > 10 || strlen(text) > 200) {
        fprintf(stderr, "[VULN] CVE-2006-5815: sreplace buffer overflow triggered\n");
        memset((void*)canary, 'X', 16);
    }

    strncpy(buf, text, sizeof(buf)-1);
    check_canary();
}

void handle_client(int sock) {
    char buf[4096], cmd[64], arg[4000];
    int logged_in = 0;

    send(sock, "220 ProFTPD 1.3.0 Server (CVE-2006-5815 vulnerable)\r\n", 53, 0);

    while (1) {
        memset(buf, 0, sizeof(buf));
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n <= 0) break;

        memset(cmd, 0, sizeof(cmd));
        memset(arg, 0, sizeof(arg));
        sscanf(buf, "%63s %3999[^\r\n]", cmd, arg);

        if (strcasecmp(cmd, "USER") == 0) {
            send(sock, "331 Password required\r\n", 23, 0);
        } else if (strcasecmp(cmd, "PASS") == 0) {
            send(sock, "230 User logged in\r\n", 20, 0);
            logged_in = 1;
        } else if (strcasecmp(cmd, "CWD") == 0 && logged_in) {
            /* CWD triggers .message file display which calls sreplace */
            vulnerable_sreplace(arg);
            send(sock, "250 CWD successful\r\n", 20, 0);
        } else if (strcasecmp(cmd, "STOR") == 0 && logged_in) {
            /* STOR creates files - including .message */
            vulnerable_sreplace(arg);
            send(sock, "150 Opening connection\r\n", 24, 0);
            send(sock, "226 Transfer complete\r\n", 23, 0);
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

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(2128), .sin_addr.s_addr = INADDR_ANY};
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 5);

    printf("ProFTPD 1.3.0 simulator (CVE-2006-5815 sreplace) listening on port 2128\n");

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (fork() == 0) { handle_client(cli); exit(0); }
        close(cli);
    }
}
