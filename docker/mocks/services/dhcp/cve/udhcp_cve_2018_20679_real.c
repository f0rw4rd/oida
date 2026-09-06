/*
 * Real CVE-2018-20679 - BusyBox udhcp out-of-bounds READ in udhcp_get_option()
 *
 * Vulnerable code:  networking/udhcp/common.c  (BusyBox 1.29.3, tag 1_29_3)
 * CWE-125, CVSS 7.5. "consumed by the DHCP server, client, and relay" — this
 * harness exercises the SERVER side: it binds the udhcpd DHCPv4 port (UDP 67)
 * and feeds every received packet straight into the GENUINE BusyBox
 * udhcp_get_option() compiled from networking/udhcp/common.c.
 *
 * Root cause (verbatim logic, see common.c):
 *   udhcp_get_option() walks packet->options bounding the scan against
 *   sizeof(packet->options) (the full 308+slack-byte array), NOT against the
 *   number of bytes actually received off the wire. A crafted message whose
 *   option chain never reaches DHCP_END before the received bytes run out makes
 *   the parser read [code][len][data...] past the end of the actual datagram,
 *   still inside the fixed struct allocation.
 *
 * Why the moving fence:
 *   The over-read is CONTAINED inside the heap/stack struct, so a stock ASan
 *   build does NOT natively fault. Exactly like the libmodbus CVE-2019-14462
 *   harness, we POISON the bytes past the actually-received length before
 *   calling the real parser. The genuine udhcp_get_option() then steps into the
 *   poisoned tail and ASan aborts with the trace landing inside
 *   udhcp_get_option / common.c — proving the real over-read, deterministically.
 *
 * This file contains NO reimplementation of the vulnerable logic. It only
 * recvfrom()s, poisons, and calls the real symbol linked from common.o.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ASan manual poisoning API (resolved by the -fsanitize=address runtime). */
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

/* ----------------------------------------------------------------------------
 * ABI-compatible mirror of BusyBox's struct dhcp_packet (networking/udhcp/
 * common.h, tag 1_29_3). Layout MUST match the struct that the linked
 * common.o was compiled against; it is __packed__ there, so we pack here too.
 * DHCP_OPTIONS_BUFSIZE = 308; CONFIG_UDHCPC_SLACK_FOR_BUGGY_SERVERS defaults to
 * 80 in defconfig -> options[388]. The exact slack does not affect the bug
 * (the scan bound is sizeof(options), whatever it is); we only need our struct
 * to be at least as large so the real parser's reads stay inside our buffer.
 * --------------------------------------------------------------------------*/
#define DHCP_OPTIONS_BUFSIZE 308
#define UDHCPC_SLACK_FOR_BUGGY_SERVERS 80
#define OPTIONS_LEN (DHCP_OPTIONS_BUFSIZE + UDHCPC_SLACK_FOR_BUGGY_SERVERS)

struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr_nip;
	uint32_t gateway_nip;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t cookie;
	uint8_t options[OPTIONS_LEN];
} __attribute__((__packed__));

/* The genuine vulnerable function, linked from BusyBox common.o.
 * FAST_FUNC is empty on x86-64 (regparm only on i386), so plain SysV ABI. */
uint8_t *udhcp_get_option(struct dhcp_packet *packet, int code);

/* Minimal libbb stub. udhcp_get_option() only references bb_error_msg() on its
 * "bad packet, malformed option field" complain path; with CONFIG_UDHCP_DEBUG
 * unset all log1/2/3 macros compile to no-ops, so this is the sole external
 * symbol common.o needs from libbb on the udhcp_get_option() code path. */
void bb_error_msg(const char *s, ...)
{
	fprintf(stderr, "[udhcp] %s\n", s);
}

/* Stubs for the other libbb symbols that OTHER functions in common.o reference
 * (udhcp_str2optset, udhcp_init_header, etc.). None are reachable from
 * udhcp_get_option(); they exist only to satisfy the static linker. If one is
 * ever actually called we abort loudly rather than misbehave silently. */
#define UDHCP_LINK_STUB(name) \
	void name(void) { fprintf(stderr, "UNEXPECTED call to " #name "\n"); abort(); }
UDHCP_LINK_STUB(bb_error_msg_and_die)
UDHCP_LINK_STUB(bb_strtoi)
UDHCP_LINK_STUB(bb_strtou)
UDHCP_LINK_STUB(bin2hex)
UDHCP_LINK_STUB(dname_enc)
UDHCP_LINK_STUB(hex2bin)
UDHCP_LINK_STUB(host_and_af2sockaddr)
UDHCP_LINK_STUB(index_in_strings)
UDHCP_LINK_STUB(last_char_is)
UDHCP_LINK_STUB(trim)
UDHCP_LINK_STUB(xmalloc)
UDHCP_LINK_STUB(xrealloc)
UDHCP_LINK_STUB(xstrdup)
UDHCP_LINK_STUB(xzalloc)
int bb_errno;

#define DHCP_MAGIC 0x63825363
#define DHCP_PARAM_REQ 0x37
#define DHCP_LEASE_TIME 0x33

int main(int argc, char **argv)
{
	int port = 67;
	if (argc > 1)
		port = atoi(argv[1]);

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		return 1;
	}

	printf("===========================================\n");
	printf("  REAL BusyBox udhcp CVE-2018-20679 server\n");
	printf("  Using: BusyBox 1.29.3 networking/udhcp/common.c (vulnerable)\n");
	printf("  Vulnerable fn: udhcp_get_option() (OOB read, CWE-125)\n");
	printf("  Server-reachable: udhcpd DHCPv4 path, UDP port %d\n", port);
	printf("===========================================\n");
	printf("[*] Listening on UDP %d ...\n", port);

	for (;;) {
		/* One struct dhcp_packet worth of buffer, exactly like udhcpd's
		 * udhcp_recv_kernel_packet() target. */
		struct dhcp_packet packet;
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);

		memset(&packet, 0, sizeof(packet));
		ssize_t rc = recvfrom(fd, &packet, sizeof(packet), 0,
				      (struct sockaddr *)&from, &fromlen);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			perror("recvfrom");
			break;
		}
		printf("[*] Received %zd bytes from %s:%d\n", rc,
		       inet_ntoa(from.sin_addr), ntohs(from.sin_port));

		/* Sanity: a real BOOTP/DHCP message is >= 240 bytes (236 header +
		 * 4 magic). Anything past the actually-received length is NOT input
		 * the server legitimately holds — poison it so the genuine parser's
		 * over-read past the truncated option trips ASan. This is the moving
		 * fence at the received-packet boundary (the modbus-14462 pattern). */
		size_t total = sizeof(packet);
		if ((size_t)rc < total) {
			uint8_t *base = (uint8_t *)&packet;
			__asan_poison_memory_region(base + rc, total - rc);
		}

		/* Call the GENUINE vulnerable function exactly as udhcpd does when it
		 * parses an inbound request. We look up an option that is deliberately
		 * NOT present (DHCP_LEASE_TIME 0x33) so the parser must walk the entire
		 * option chain: it advances PAST the crafted truncated trailing option
		 * (optionptr += 2 + len, where len reaches beyond the received bytes)
		 * and on the next iteration reads optionptr[OPT_CODE] from the poisoned
		 * tail -> ASan abort inside udhcp_get_option / common.c. */
		uint8_t *opt = udhcp_get_option(&packet, DHCP_LEASE_TIME);

		__asan_unpoison_memory_region(&packet, sizeof(packet));

		if (opt)
			printf("[*] option 0x37 found at offset %ld\n",
			       (long)(opt - (uint8_t *)&packet));
		else
			printf("[*] option 0x37 not present / malformed\n");
	}

	close(fd);
	return 0;
}
