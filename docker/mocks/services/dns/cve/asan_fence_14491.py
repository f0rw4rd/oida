#!/usr/bin/env python3
"""
Build-time patcher: install an ASan "moving fence" around dnsmasq 2.77's UDP
answer_request() call so CVE-2017-14491's overflow becomes observable.

Why this is needed (crash-class analysis):
  dnsmasq allocates the answer buffer as
      packet_buff_sz = edns_pktsz + MAXDNAME(1025) + RRFIXEDSZ(10)
  and answers with  limit = header + udp_size  (udp_size <= edns_pktsz).
  The pre-fix add_resource_record()/do_rfc1035_name() write a whole record
  (up to one MAXDNAME) and only check `limit` AFTERWARDS. So the genuine
  CVE-2017-14491 overshoot past `limit` lands inside the MAXDNAME+RRFIXEDSZ
  slack -- still inside the same safe_malloc() allocation. ASan sees only the
  *allocation* boundary, so it stays silent: this is a contained (class-c) bug
  w.r.t. the allocation, exactly like libmodbus CVE-2019-14462.

  Fix: poison the slack region [header+udp_size, header+packet_buff_sz) right
  before answer_request() and unpoison it right after. Now any write past
  `limit` (the real bug) hits poisoned bytes -> ASan aborts in the genuine
  vulnerable function (do_rfc1035_name / add_resource_record, rfc1035.c). The
  poison models the protocol/limit boundary as a memory boundary; it never
  changes the actual bytes, so legitimate (in-limit) replies are unaffected.
"""

import re
import sys

path = "/build/dnsmasq/src/forward.c"
with open(path) as f:
    src = f.read()

# Declare the ASan poison intrinsics once, near the top include block.
decl = (
    "\n/* CVE-2017-14491 ASan moving fence (build-time injected) */\n"
    "void __asan_poison_memory_region(void const volatile *addr, unsigned long size);\n"
    "void __asan_unpoison_memory_region(void const volatile *addr, unsigned long size);\n"
)
src = src.replace('#include "dnsmasq.h"', '#include "dnsmasq.h"' + decl, 1)

# Target the UDP answer_request call (limit = header + udp_size). There are two
# answer_request() calls; only the UDP one uses udp_size as the limit.
needle = "      m = answer_request(header, ((char *) header) + udp_size, (size_t)n, \n"
assert needle in src, "UDP answer_request call site not found"

wrapped = (
    "      /* CVE-2017-14491 fence: poison the MAXDNAME+RRFIXEDSZ slack above the\n"
    "         reply limit so the pre-fix overshoot past `limit` is caught. */\n"
    "      __asan_poison_memory_region(((char *)header) + udp_size,\n"
    "                                  daemon->packet_buff_sz - udp_size);\n"
    + needle
)

src = src.replace(needle, wrapped, 1)

# Unpoison after the call returns (m is assigned across the next few lines; we
# insert the unpoison immediately after the statement's closing line).
# The statement ends with "have_pseudoheader);" on the line after `needle`.
end_marker = "\t\t\t dst_addr_4, netmask, now, ad_reqd, do_bit, have_pseudoheader);\n"
assert end_marker in src, "answer_request end marker not found"
src = src.replace(
    end_marker,
    end_marker
    + "      __asan_unpoison_memory_region(((char *)header) + udp_size,\n"
    + "                                    daemon->packet_buff_sz - udp_size);\n",
    1,
)

with open(path, "w") as f:
    f.write(src)

print("[patch] ASan moving fence installed around UDP answer_request()")
