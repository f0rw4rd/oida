/**
 * Real CVE-2018-20748 - LibVNCServer 0.9.11 (vulnerable)
 *
 * Vulnerability: Stack buffer overflow WRITE (CWE-787) in
 *   HandleFileCreateDirRequest() in
 *   libvncserver/tightvnc-filetransfer/handlefiletransferrequest.c
 *
 * char dirName[PATH_MAX] (4096 bytes) on the stack; rfbReadExact() writes
 * up to msg.fcdr.dNameLen (uint16, max 65535) bytes into it with NO bounds
 * check (the TODO comment in the source confirms it).
 *
 * Trigger: send rfbFileCreateDirRequest (type=136) with dNameLen=0xFFFF
 * after completing the full TightVNC handshake.
 *
 * Fixed by commit 111837d1 which added the missing bound check.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rfb/rfb.h>

#define PORT     5900
#define WIDTH    640
#define HEIGHT   480

int main(void)
{
    rfbScreenInfoPtr server;
    char *frameBuffer;

    /* Disable output buffering so Docker logs show up immediately. */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("==============================================\n");
    printf("  REAL LibVNCServer CVE-2018-20748 Server\n");
    printf("  Using: LibVNCServer 0.9.11 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Trigger: rfbFileCreateDirRequest type=136\n");
    printf("           dNameLen=0xFFFF => stack overflow\n");
    printf("==============================================\n");

    /* Allocate a minimal framebuffer (required by rfbGetScreen). */
    frameBuffer = (char *)calloc(WIDTH * HEIGHT * 4, 1);
    if (frameBuffer == NULL) {
        fprintf(stderr, "calloc frameBuffer failed\n");
        return 1;
    }

    /* rfbGetScreen with argc=0/argv=NULL — we set everything manually. */
    server = rfbGetScreen(0, NULL, WIDTH, HEIGHT, 8, 3, 4);
    if (server == NULL) {
        fprintf(stderr, "rfbGetScreen failed\n");
        free(frameBuffer);
        return 1;
    }

    server->frameBuffer    = frameBuffer;
    server->port           = PORT;
    server->listenInterface = htonl(INADDR_ANY);
    server->desktopName    = "CVE-2018-20748";

    /*
     * Register the TightVNC file-transfer extension BEFORE rfbInitServer.
     * This installs rfbSecTypeTight (16) as a security handler and registers
     * the protocol extension that handles message type 136.
     * InitFileTransfer() is called internally; file transfer is enabled by
     * default (viewOnly=FALSE, no -disablefiletransfer).
     */
    rfbRegisterTightVNCFileTransferExtension();

    rfbInitServer(server);

    printf("[*] Listening on 0.0.0.0:%d (ASan instrumented)\n", PORT);
    printf("[*] Waiting for PoC connection...\n");

    /*
     * rfbRunEventLoop: blocking, handles accept()/read()/write() internally.
     * timeout=-1 means block forever in select(); usec parameter ignored.
     * The third argument FALSE means run in the caller's thread (not a new
     * pthread), which keeps the ASan signal handler reachable.
     */
    rfbRunEventLoop(server, -1, FALSE);

    /* Unreachable after ASan abort, but keep clean for static analysis. */
    free(frameBuffer);
    rfbScreenCleanup(server);
    return 0;
}
