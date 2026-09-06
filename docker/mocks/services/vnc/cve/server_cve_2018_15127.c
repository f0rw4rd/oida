/**
 * Real CVE-2018-15127 - Minimal server using vulnerable LibVNCServer 0.9.11
 *
 * Vulnerability: Heap out-of-bounds write (CWE-787) in rfbProcessFileTransferReadBuffer().
 * When length == 0xFFFFFFFF, malloc(length+1) wraps to malloc(0), then rfbReadExact()
 * writes up to 0xFFFFFFFF attacker bytes into the tiny allocation.
 *
 * Fixed by commit 502821828ed00b4a2c4bef90683d0fd88ce495de (cast to uint64_t before +1).
 *
 * Reachability: msg type 7 (rfbFileTransfer), contentType=1 (rfbDirContentRequest),
 * contentParam=1 (rfbRDirContent) dispatches to rfbProcessFileTransferReadBuffer().
 * Requires screen->permitFileTransfer = TRUE (set below).
 */

#include <rfb/rfb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT       5900
#define FB_WIDTH   640
#define FB_HEIGHT  480
#define FB_BPP     4

int main(void) {
    rfbScreenInfoPtr server;
    char *framebuffer;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("===========================================\n");
    printf("  REAL LibVNCServer CVE-2018-15127 Server\n");
    printf("  Using: LibVNCServer 0.9.11 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Trigger: rfbFileTransfer msg type 7, length=0xFFFFFFFF\n");
    printf("  Vuln: heap-buffer-overflow WRITE in rfbProcessFileTransferReadBuffer\n");
    printf("===========================================\n");

    framebuffer = (char *)calloc(FB_WIDTH * FB_HEIGHT * FB_BPP, 1);
    if (!framebuffer) {
        fprintf(stderr, "[-] calloc for framebuffer failed\n");
        return 1;
    }

    /* argc/argv shim - rfbGetScreen wants them */
    int fake_argc = 0;
    server = rfbGetScreen(&fake_argc, NULL, FB_WIDTH, FB_HEIGHT, 8, 3, FB_BPP);
    if (!server) {
        fprintf(stderr, "[-] rfbGetScreen failed\n");
        free(framebuffer);
        return 1;
    }

    server->frameBuffer    = framebuffer;
    server->port           = PORT;
    server->ipv6port       = -1;   /* disable IPv6 listener */
    server->alwaysShared   = TRUE;

    /*
     * Enable the legacy file-transfer path so msg type 7 reaches
     * rfbProcessClientNormalMessage -> case rfbFileTransfer ->
     * rfbProcessFileTransfer -> rfbProcessFileTransferReadBuffer.
     * Without this flag the server returns rfbErrNoSuchObject.
     */
    server->permitFileTransfer = TRUE;

    /* No password - security type None (1) */
    server->authPasswdData    = NULL;
    server->passwordCheck     = NULL;

    rfbInitServer(server);

    printf("[*] Listening on 0.0.0.0:%d (security=None, permitFileTransfer=TRUE)\n", PORT);
    printf("[*] Waiting for connections...\n");

    /* Block forever; ASan abort will terminate the process */
    rfbRunEventLoop(server, -1, FALSE);

    /* Never reached under normal operation */
    rfbShutdownServer(server, TRUE);
    free(framebuffer);
    return 0;
}
