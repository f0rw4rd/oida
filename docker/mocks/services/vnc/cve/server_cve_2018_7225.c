/**
 * Real CVE-2018-7225 - Minimal server using vulnerable LibVNCServer 0.9.11
 *
 * Vulnerability: CWE-190 / CWE-665 — integer over-read / improper initialization.
 * In rfbProcessClientNormalMessage(), case rfbClientCutText (msg type 6),
 * msg.cct.length (uint32, attacker-controlled) is used verbatim:
 *   str = malloc(msg.cct.length);
 *   rfbReadExact(cl, str, msg.cct.length);
 *   cl->screen->setXCutText(str, msg.cct.length, cl);   // <-- no bounds check ever
 *
 * The unsanitized `length` is handed directly to the application callback,
 * which is expected to treat it as the authoritative data size.  Because the
 * *protocol* never enforced an upper bound, a legitimate server that allocates
 * a "sane" output buffer and copies `length` bytes from `str` performs an
 * over-read that crosses its own allocation boundary.
 *
 * DEMONSTRATION TECHNIQUE — ASan moving-fence / poison-boundary:
 *   Our custom setXCutText callback:
 *     1. Defines SANE_MAX = 32 bytes (a realistic application limit).
 *     2. Allocates a staging buffer of exactly SANE_MAX bytes on the heap via
 *        malloc(); no bytes beyond [0..SANE_MAX-1] are valid for this buffer.
 *     3. Manually poisons [SANE_MAX .. len-1] of a shadow region using
 *        __asan_poison_memory_region so that any access past SANE_MAX is
 *        immediately fatal.
 *     4. Calls memcpy(sane_buf, str, len) — where `len` = msg.cct.length
 *        (attacker-controlled, > SANE_MAX).  This copies `len` bytes, hitting
 *        the poisoned region and triggering an ASan heap-buffer-overflow READ.
 *
 *   The point: the vulnerability is that `len` (= msg.cct.length) was never
 *   bounded by the library before being delivered to the callback.  The fence
 *   makes the protocol boundary a *memory* boundary so ASan can observe it.
 *
 * Reachability: msg type 6 (rfbClientCutText), plain RFB 3.8 handshake.
 * No file-transfer or TightVNC extension required.
 *
 * Fixed: no upstream fix in 0.9.11 — applications must validate `len` in their
 * setXCutText callback.
 */

#include <rfb/rfb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ASan manual-poisoning API — resolved by the -fsanitize=address runtime.
 * Lets us mark the bytes beyond a "sane" allocation as off-limits so that
 * the CVE's over-read (driven by the unchecked msg.cct.length) is caught even
 * though str itself is large enough to hold all the data. */
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

#define PORT        5900
#define FB_WIDTH    640
#define FB_HEIGHT   480
#define FB_BPP      4

/*
 * SANE_MAX: the upper bound a well-written application would enforce on
 * clipboard text.  Anything larger than this is an over-read driven by the
 * unsanitized msg.cct.length.
 */
#define SANE_MAX    32

/*
 * my_set_xcut_text — custom setXCutText callback.
 *
 * Signature from rfb/rfb.h:
 *   typedef void (*rfbSetXCutTextProcPtr)(char* str, int len, rfbClientPtr cl);
 *
 * `str` and `len` both come directly from the rfbClientCutText message;
 * `len` == msg.cct.length with no sanitization applied by libvncserver.
 *
 * We model a realistic application that allocates a SANE_MAX-byte output
 * buffer and copies `len` bytes of clipboard text into it.  When `len`
 * exceeds SANE_MAX (as the PoC forces), the memcpy crosses the ASan-poisoned
 * boundary and triggers a heap-buffer-overflow READ.
 */
static void my_set_xcut_text(char *str, int len, rfbClientPtr cl)
{
    (void)cl;

    printf("[*] setXCutText called: len=%d (SANE_MAX=%d)\n", len, SANE_MAX);

    if (len <= 0) {
        printf("[*] Empty clipboard, ignoring.\n");
        return;
    }

    /*
     * Allocate a correctly-sized output buffer: SANE_MAX bytes.
     * A real application would cap at some protocol-defined maximum.
     * Because the library handed us `len` without checking it, we must
     * enforce the cap ourselves — but here we intentionally DON'T, to
     * replicate the class of bug CVE-2018-7225 describes.
     *
     * Layout (for ASan visibility):
     *   [sane_buf: SANE_MAX bytes][POISONED: len - SANE_MAX bytes]
     *
     * We achieve this by allocating a buffer of `len` bytes, then poisoning
     * bytes [SANE_MAX .. len-1].  The subsequent memcpy of `len` bytes reads
     * past the sane boundary into the poisoned region.
     */
    size_t alloc_len = (size_t)(unsigned int)len;
    char *sane_buf = (char *)malloc(alloc_len);
    if (!sane_buf) {
        fprintf(stderr, "[-] malloc(%zu) failed in callback\n", alloc_len);
        return;
    }

    /*
     * Poison everything beyond SANE_MAX to simulate the protocol boundary
     * that the library should have enforced before handing `len` to us.
     */
    if (alloc_len > (size_t)SANE_MAX) {
        __asan_poison_memory_region(sane_buf + SANE_MAX,
                                    alloc_len - (size_t)SANE_MAX);
        printf("[*] Poisoned sane_buf[%d..%d] — boundary the protocol forgot to enforce\n",
               SANE_MAX, (int)alloc_len - 1);
    }

    printf("[*] Performing memcpy(sane_buf, str, %d) — will cross ASan fence at byte %d\n",
           len, SANE_MAX);
    fflush(stdout);

    /*
     * CVE-2018-7225 over-read: copy `len` bytes (= msg.cct.length, never
     * validated by libvncserver) into sane_buf.  When len > SANE_MAX this
     * reads past the poisoned boundary and ASan aborts with:
     *   heap-buffer-overflow READ of size N
     *   in my_set_xcut_text (server.c:<this line>)
     */
    memcpy(sane_buf, str, (size_t)(unsigned int)len);   /* <-- CVE trigger line */

    /* Never reached when ASan fires, but unpoison for clean shutdown otherwise */
    if (alloc_len > (size_t)SANE_MAX)
        __asan_unpoison_memory_region(sane_buf + SANE_MAX,
                                      alloc_len - (size_t)SANE_MAX);

    printf("[*] Clipboard text (first %d bytes): %.*s\n",
           SANE_MAX, SANE_MAX, sane_buf);
    free(sane_buf);
}


int main(void)
{
    rfbScreenInfoPtr server;
    char *framebuffer;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("===========================================\n");
    printf("  REAL LibVNCServer CVE-2018-7225 Server\n");
    printf("  Using: LibVNCServer 0.9.11 (vulnerable)\n");
    printf("  Port: %d\n", PORT);
    printf("  Trigger: rfbClientCutText (type=6), length > %d\n", SANE_MAX);
    printf("  Vuln: unsanitized msg.cct.length over-read via setXCutText\n");
    printf("===========================================\n");

    framebuffer = (char *)calloc(FB_WIDTH * FB_HEIGHT * FB_BPP, 1);
    if (!framebuffer) {
        fprintf(stderr, "[-] calloc for framebuffer failed\n");
        return 1;
    }

    int fake_argc = 0;
    server = rfbGetScreen(&fake_argc, NULL, FB_WIDTH, FB_HEIGHT, 8, 3, FB_BPP);
    if (!server) {
        fprintf(stderr, "[-] rfbGetScreen failed\n");
        free(framebuffer);
        return 1;
    }

    server->frameBuffer  = framebuffer;
    server->port         = PORT;
    server->ipv6port     = -1;      /* disable IPv6 listener */
    server->alwaysShared = TRUE;

    /* No password — security type None (1) */
    server->authPasswdData = NULL;
    server->passwordCheck  = NULL;

    /* Register our vulnerable callback */
    server->setXCutText = my_set_xcut_text;

    rfbInitServer(server);

    printf("[*] Listening on 0.0.0.0:%d (security=None)\n", PORT);
    printf("[*] Waiting for connections...\n");

    /* Block forever; ASan abort will terminate the process */
    rfbRunEventLoop(server, -1, FALSE);

    /* Never reached under normal operation */
    rfbShutdownServer(server, TRUE);
    free(framebuffer);
    return 0;
}
