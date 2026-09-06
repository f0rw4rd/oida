/*
 * REAL opendnp3 1.1.0 APDU-parser over-read - 2-BYTE COUNT qualifier family.
 *
 * Bug family: ICSA-13-291-01 "aegis" DNP3 application-layer parser cluster.
 * Vulnerable code: opendnp3::APDU::ReadObjectHeader (src/opendnp3/APDU.cpp),
 *   OT_PLACEHOLDER arm leaves data_size == 0; a QC_2B_CNT header is parsed by
 *   the 2-octet Count2OctetHeader path (APDU::GetObjectHeader ->
 *   Count2OctetHeader, GetNumObjects -> ICountHeader::GetCount reading a 16-bit
 *   count), exercising the 16-bit count-width branch rather than the 8-bit one.
 *   The count over a var-0 placeholder passes the length guard and yields
 *   iterable objects whose ObjectReadIterator data pointers run past the
 *   fragment -> out-of-bounds read (CWE-125).
 *
 * Trigger qualifier: QC_2B_CNT (0x08) - 2-byte count header.
 *
 * Loosely tracked here under CVE-2017-7938 (the historical opendnp3 over-read
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
        "  REAL opendnp3 CVE-2017-7938 outstation\n"
        "  APDU 2-byte-count object over-read\n");
}
