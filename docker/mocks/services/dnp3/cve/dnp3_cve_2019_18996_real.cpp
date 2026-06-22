/*
 * REAL opendnp3 1.1.0 APDU-parser over-read - 1-BYTE COUNT qualifier family.
 *
 * Bug family: ICSA-13-291-01 "aegis" DNP3 application-layer parser cluster.
 * Vulnerable code: opendnp3::APDU::ReadObjectHeader (src/opendnp3/APDU.cpp),
 *   OT_PLACEHOLDER arm leaves data_size == 0; APDU::GetNumObjects() returns the
 *   attacker count (ICountHeader::GetCount) for a count-qualified header, so a
 *   count over a var-0 placeholder object passes the length guard yet produces
 *   `count` iterable objects. opendnp3::ObjectReadIterator (operator* /
 *   CalcCountIndex, src/opendnp3/ObjectReadIterator.cpp) hands back data
 *   pointers past the fragment -> out-of-bounds read (CWE-125). Distinct parse
 *   path from the range family (CountHeader vs RangedHeader / CalcCountIndex).
 *
 * Trigger qualifier: QC_1B_CNT (0x07) - 1-byte count header.
 *
 * Loosely tracked here under CVE-2019-18996 (the historical opendnp3 over-read
 * label used by this mock fleet); the authentic defect is the aegis APDU
 * object-header over-read against the genuine 1.1.0 parser.
 *
 * CRASH CLASS: contained over-read made observable with a fragment-tight buffer
 *   fence (ASan reports the read 0 bytes past the genuine CopyableBuffer alloc).
 *
 * FOR AUTHORIZED SECURITY TESTING ONLY - DO NOT USE IN PRODUCTION.
 */
#define DNP3_PORT 20000
#include "dnp3_outstation_common.h"

int main(void) {
    return run_outstation(
        DNP3_PORT,
        "  REAL opendnp3 CVE-2019-18996 outstation\n"
        "  APDU 1-byte-count object over-read\n");
}
